import * as tl from 'azure-pipelines-task-lib/task';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as https from 'https';
import * as path from 'path';
import sanitizeHtml from 'sanitize-html';

const SHELL = process.platform === 'win32' ? (process.env['ComSpec'] ?? 'cmd.exe') : '/bin/sh';

// ---------------------------------------------------------------------------
// Types matching the Cycode CLI JSON output schema
// ---------------------------------------------------------------------------

interface ScaAlert {
    cve_identifier?: string;
    ghsa_identifier?: string;
    description?: string;
    dependency_paths?: string;
    affected_package_name?: string;
    first_patched_version?: string;
    vulnerable_requirements?: string;
}

interface DetectionDetails {
    file_path?: string;
    file_name?: string;
    manifest_file_path?: string;
    line?: number | string;
    line_in_file?: number | string;
    infra_provider?: string;
    cwe?: string[];
    owasp?: string[];
    category?: string;
    languages?: string[];
    remediation_guidelines?: string;
    custom_remediation_guidelines?: string;
    policy_display_name?: string;
    description?: string;
    detection_rule_id?: string;
    policy_id?: string;
    alert?: ScaAlert;
    build_tool?: string;
    ecosystem?: string;
    package_name?: string;
    package_version?: string;
    dependency_paths?: string;
    license?: string;
    cvss_score?: number;
    epss?: number;
    is_direct_dependency?: boolean;
    is_dev_dependency?: boolean;
}

interface Detection {
    severity?: string;
    type?: string;
    message?: string;
    detection_rule_id?: string;
    detection_details?: DetectionDetails;
    id?: string;
    _scanType?: string;  // synthetic field — CLI scan type that produced this detection
}

interface ScanBlock {
    detections?: Detection[];
}

interface ScanOutput {
    scan_results?: ScanBlock[];
    detections?: Detection[];
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

// Ordered from most to least severe so slice(0, n) gives "n and above"
const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

const SEVERITY_COLORS: Record<string, string> = {
    Critical: '#b71c1c',
    High:     '#e65100',
    Medium:   '#f9a825',
    Low:      '#1565c0',
    Info:     '#546e7a',
};

const ALL_SCAN_TYPES = ['sast', 'sca', 'secret', 'iac'] as const;
type ScanType = typeof ALL_SCAN_TYPES[number];

function parseScanTypes(input: string): ScanType[] {
    const normalized = input.trim().toLowerCase();
    if (!normalized || normalized === 'all') return [...ALL_SCAN_TYPES];
    const requested = normalized.split(',').map(t => t.trim()).filter(Boolean);
    const valid = requested.filter((t): t is ScanType => (ALL_SCAN_TYPES as readonly string[]).includes(t));
    const invalid = requested.filter(t => !(ALL_SCAN_TYPES as readonly string[]).includes(t));
    if (invalid.length) console.log(`Warning: ignoring unrecognised scan type(s): ${invalid.join(', ')}`);
    if (!valid.length) throw new Error(`No valid scan types in "${input}". Valid: ${ALL_SCAN_TYPES.join(', ')}`);
    return valid;
}

function normalizeSeverity(raw: string | undefined): string {
    if (!raw) return 'Info';
    const s = raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase();
    return SEVERITY_ORDER.includes(s) ? s : 'Info';
}

// Lower rank index = more severe. Returns SEVERITY_ORDER.length for unknowns.
function severityRank(sev: string): number {
    const idx = SEVERITY_ORDER.indexOf(normalizeSeverity(sev));
    return idx === -1 ? SEVERITY_ORDER.length : idx;
}

// ---------------------------------------------------------------------------
// CLI installation helpers (cross-platform: Linux + Windows)
// ---------------------------------------------------------------------------

function tryExec(cmd: string): boolean {
    try {
        execSync(cmd, { stdio: 'pipe', shell: SHELL });
        return true;
    } catch {
        return false;
    }
}

function findUserBin(python: string): string | null {
    try {
        const userBase = execSync(`${python} -m site --user-base`, {
            stdio: 'pipe', shell: SHELL, encoding: 'utf8',
        }).trim();
        return process.platform === 'win32'
            ? path.join(userBase, 'Scripts')
            : path.join(userBase, 'bin');
    } catch {
        return null;
    }
}

function ensureCycodeInstalled(): string {
    const candidates = ['cycode', 'python3 -m cycode', 'python -m cycode'];
    for (const cmd of candidates) {
        if (tryExec(`${cmd} status`)) {
            console.log(`Cycode CLI found: ${cmd}`);
            return cmd;
        }
    }

    console.log('Cycode CLI not found — attempting installation via pip...');

    // Each entry pairs the pip installer with the Python that owns it so that
    // post-install module invocation uses the same interpreter.
    // Try plain install first (required inside virtualenvs); fall back to --user
    // for non-root installs on bare Python environments.
    const installPairs: Array<{ pip: string; python: string }> = [
        { pip: 'python3 -m pip', python: 'python3' },
        { pip: 'pip3',           python: 'python3' },
        { pip: 'python -m pip',  python: 'python'  },
        { pip: 'pip',            python: 'python'  },
    ];

    for (const { pip, python } of installPairs) {
        let installCmd: string | undefined;
        // Try without --user first (required inside virtualenvs and when running as root).
        // Fall back to --user for non-root installs on bare Python environments.
        for (const flags of ['', ' --user']) {
            try {
                execSync(`${pip} install${flags} cycode`, { stdio: 'inherit', shell: SHELL });
                installCmd = `${pip} install${flags} cycode`;
                break;
            } catch {
                continue;
            }
        }
        if (!installCmd) continue;

        console.log(`Installed Cycode CLI via: ${installCmd}`);

        // Prefer module invocation — works even when the script dir isn't in PATH
        if (tryExec(`${python} -m cycode --version`)) return `${python} -m cycode`;

        // Probe the user scripts/bin directory for the cycode binary
        const userBin = findUserBin(python);
        if (userBin) {
            const ext = process.platform === 'win32' ? '.exe' : '';
            const bin = path.join(userBin, `cycode${ext}`);
            if (fs.existsSync(bin) && tryExec(`"${bin}" --version`)) {
                return `"${bin}"`;
            }
        }

        // Fall back to any candidate now reachable in PATH
        for (const cmd of candidates) {
            if (tryExec(`${cmd} status`)) return cmd;
        }

        // Install succeeded but CLI still not reachable — stop trying other pip variants
        break;
    }

    throw new Error(
        'Failed to install or locate the Cycode CLI. ' +
        'Ensure Python 3 and pip are available on the build agent, ' +
        'or pre-install the CLI with: pip install cycode'
    );
}

// ---------------------------------------------------------------------------
// JSON extraction — Cycode exits non-zero when findings exist; stdout = JSON
// ---------------------------------------------------------------------------

class AuthenticationError extends Error {
    constructor(detail: string) {
        super(
            'Cycode authentication failed — verify that CycodeClientID and CycodeClientSecret ' +
            'are correct and have not expired.' +
            (detail ? `\nDetail: ${detail}` : '')
        );
        this.name = 'AuthenticationError';
    }
}

// Patterns that indicate a credential / auth rejection from the Cycode CLI
const AUTH_ERROR_RE = /unauthori[sz]ed|authentication[\s_-]?failed|invalid[\s_-]?(client|credentials?|token)|access[\s_-]?denied|forbidden|401|403/i;

function assertNotAuthError(stdout: string, stderr: string): void {
    const detail = stderr.trim() || stdout.trim();
    if (AUTH_ERROR_RE.test(detail)) throw new AuthenticationError(detail);
}

function runScan(cmd: string, env: Record<string, string>): string {
    const mergedEnv = { ...process.env, ...env } as NodeJS.ProcessEnv;
    try {
        const output = execSync(cmd, {
            env: mergedEnv,
            encoding: 'utf8',
            shell: SHELL,
            maxBuffer: 100 * 1024 * 1024, // 100 MB
        });
        // Cycode can exit 0 on auth errors in some versions — check stdout too
        assertNotAuthError(output, '');
        return output;
    } catch (ex: any) {
        if (ex instanceof AuthenticationError) throw ex;
        // Non-zero exit is expected when findings are present
        const stdout: string = ex.stdout
            ? (Buffer.isBuffer(ex.stdout) ? ex.stdout.toString('utf8') : String(ex.stdout))
            : '';
        const stderr: string = ex.stderr
            ? (Buffer.isBuffer(ex.stderr) ? ex.stderr.toString('utf8') : String(ex.stderr))
            : '';
        assertNotAuthError(stdout, stderr);
        if (stdout.trim()) return stdout;
        throw new Error(`Cycode scan failed with no JSON output.\n${stderr || ex.message}`);
    }
}

export function extractDetections(data: ScanOutput | Detection[]): Detection[] {
    if (Array.isArray(data)) return data;
    const out: Detection[] = [];
    for (const block of data.scan_results ?? []) {
        out.push(...(block.detections ?? []));
    }
    out.push(...(data.detections ?? []));
    return out;
}

// ---------------------------------------------------------------------------
// HTML report generation — tabbed layout per scan type
// ---------------------------------------------------------------------------

function sanitizeHtmlInput(val: string | number | undefined): string {
        return sanitizeHtml(String(val ?? ''));
}

function escapeHtmlAttr(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}


function normalizeFilePath(p: string, basePath?: string): string {
    if (!p) return '';
    // Strip ADO hosted-agent workspace prefix: /_work/<n>/s/... or /work/<n>/s/...
    const adoMatch = p.match(/\/_?work\/\d+\/s\/(.+)$/);
    if (adoMatch) return adoMatch[1];
    // Strip Windows-style agent path: \agent\_work\<n>\s\... or \work\<n>\s\...
    const winMatch = p.match(/[\\\/]_?work[\\\/]\d+[\\\/]s[\\\/](.+)$/);
    if (winMatch) return winMatch[1].replace(/\\/g, '/');
    // Strip the configured scan path so only the repo-relative portion is shown
    let normalized = p.replace(/\\/g, '/');
    if (basePath) {
        const base = basePath.replace(/\\/g, '/').replace(/\/+$/, '') + '/';
        if (normalized.toLowerCase().startsWith(base.toLowerCase())) {
            return normalized.slice(base.length);
        }
    }
    return normalized.replace(/^\/+/, '');
}

interface BuildInfo {
    repo:    string;
    branch:  string;
    commit:  string;
    org:     string;
    project: string;
}

function buildDescBlock(desc: string, rem: string): string {
    const short = desc.length > 180 ? desc.slice(0, 180) + '…' : desc;
    const parts: string[] = [`<div>${sanitizeHtmlInput(short)}</div>`];
    if (desc.length > 180)
        parts.push(`<details><summary>Full description</summary><div class="content">${sanitizeHtmlInput(desc)}</div></details>`);
    if (rem)
        parts.push(`<details><summary>Mitigation guidance</summary><div class="content">${sanitizeHtmlInput(rem)}</div></details>`);
    return parts.join('');
}

function getTypeHeaders(type: string): string {
    const si = '<span class="sort-icon"></span>';
    switch (type) {
        case 'sast':
            return `<th data-col-idx="0" class="sortable" style="width:110px">Severity${si}</th>` +
                `<th data-col-idx="1" class="sortable">Rule / Policy${si}</th>` +
                `<th data-col-idx="2" class="sortable">Description &amp; Mitigation${si}</th>` +
                `<th data-col-idx="3" class="sortable" style="width:260px">File &amp; Line${si}</th>` +
                `<th data-col-idx="4" class="sortable" style="width:200px">CWE / Language${si}</th>`;
        case 'sca':
            return `<th data-col-idx="0" class="sortable" style="width:110px">Severity${si}</th>` +
                `<th data-col-idx="1" class="sortable" style="width:250px">Package Info${si}</th>` +
                `<th data-col-idx="2" class="sortable" style="width:650px">Dependency Path${si}</th>` +
                `<th data-col-idx="3" class="sortable" style="width:220px">Manifest File${si}</th>` +
                `<th data-col-idx="4" class="sortable">Remediation${si}</th>`;
        case 'sca_license':
            return `<th data-col-idx="0" class="sortable" style="width:110px">Severity${si}</th>` +
                `<th data-col-idx="1" class="sortable" style="width:300px">Package Info${si}</th>` +
                `<th data-col-idx="2" class="sortable" style="width:200px">License Type${si}</th>` +
                `<th data-col-idx="3" class="sortable" style="width:650px">Dependency Path${si}</th>` +
                `<th data-col-idx="4" class="sortable">Description${si}</th>`;
        case 'secrets':
            return `<th data-col-idx="0" class="sortable" style="width:110px">Severity${si}</th>` +
                `<th data-col-idx="1" class="sortable" style="width:200px">Secret Type${si}</th>` +
                `<th data-col-idx="2" class="sortable" style="width:280px">File &amp; Line${si}</th>` +
                `<th data-col-idx="3" class="sortable">Description${si}</th>`;
        case 'iac':
            return `<th data-col-idx="0" class="sortable" style="width:110px">Severity${si}</th>` +
                `<th data-col-idx="1" class="sortable">Rule / CVE${si}</th>` +
                `<th data-col-idx="2" class="sortable" style="width:240px">File${si}</th>` +
                `<th data-col-idx="3" class="sortable">Description &amp; Mitigation${si}</th>` +
                `<th data-col-idx="4" class="sortable" style="width:180px">References${si}</th>`;
        default:
            return `<th data-col-idx="0" class="sortable" style="width:110px">Severity${si}</th>` +
                `<th data-col-idx="1" class="sortable">Issue${si}</th>` +
                `<th data-col-idx="2" class="sortable">Description${si}</th>` +
                `<th data-col-idx="3" class="sortable">File &amp; Line${si}</th>` +
                `<th data-col-idx="4" class="sortable">Details${si}</th>`;
    }
}

function buildPackageInfoHtml(ecosystem: string, pkgDisplay: string, isDirect: boolean | undefined, isDev: boolean | undefined): string {
    const parts: string[] = [];
    parts.push(`<div><strong>Build Tool:</strong> ${sanitizeHtmlInput(ecosystem)}</div>`);
    parts.push(`<div><strong>Package:</strong> ${sanitizeHtmlInput(pkgDisplay)}</div>`);
    if (isDirect != null) parts.push(`<div><strong>Direct:</strong> ${isDirect ? 'Yes' : 'No'}</div>`);
    if (isDev    != null) parts.push(`<div><strong>Dev:</strong> ${isDev    ? 'Yes' : 'No'}</div>`);
    return parts.join('') || '<span style="color:var(--muted)">—</span>';
}

function buildAdoFileUrl(filePath: string, line: number | string | undefined, buildInfo: BuildInfo): string | null {
    if (!buildInfo.org || !buildInfo.project || !buildInfo.repo || !filePath) return null;
    const cleanPath = '/' + filePath.replace(/^\//, '');
    let url = `https://dev.azure.com/${buildInfo.org}/${buildInfo.project}/_git/${buildInfo.repo}?path=${cleanPath}`;
    if (buildInfo.branch) url += `&version=GB${buildInfo.branch}`;
    if (line != null && line !== '' && String(line) !== '-1') {
        const lineNum = Number(line);
        if (!isNaN(lineNum) && lineNum > 0) {
            url += `&line=${lineNum}&lineEnd=${lineNum + 1}&lineStartColumn=1&lineEndColumn=1&lineStyle=plain&_a=contents`;
        }
    }
    return url;
}

function buildDepPathHtml(depPath: string): string {
    const segments = depPath ? depPath.split(/\s*,\s*/).map(s => s.trim()).filter(Boolean) : [];
    return segments.length > 0
        ? segments.map(s => `<div style="font-size:12px;margin-bottom:2px">&#8226; ${sanitizeHtmlInput(s)}</div>`).join('')
        : '<span style="color:var(--muted)">—</span>';
}

function buildTypeRows(type: string, detections: Detection[], scanPath: string, buildInfo: BuildInfo): string {
    return detections.map(d => {
        const sev      = normalizeSeverity(d.severity);
        const color    = SEVERITY_COLORS[sev] ?? '#546e7a';
        const dd       = d.detection_details ?? {};
        const filePath = normalizeFilePath(dd.file_path ?? '', scanPath);
        const line     = dd.line ?? '';

        const sevCell  = `<td><span class="sev" style="background:${color};">${sanitizeHtmlInput(sev)}</span></td>`;
        const fileUrl  = filePath ? buildAdoFileUrl(filePath, line, buildInfo) : null;
        const fileInner = fileUrl
            ? `<a href="${escapeHtmlAttr(fileUrl)}" target="_blank">${sanitizeHtmlInput(filePath)}</a>`
            : sanitizeHtmlInput(filePath);
        const fileCell = `<td><div class="file">${fileInner}</div>` +
                         `${line ? `<div class="line">Line ${sanitizeHtmlInput(line)}</div>` : ''}</td>`;

        switch (type) {
            case 'sast': {
                const rule  = sanitizeHtmlInput(dd.policy_display_name ?? d.detection_rule_id ?? 'Unknown');
                const desc  = (dd.description ?? d.message ?? '').trim();
                const rem   = (dd.remediation_guidelines ?? dd.custom_remediation_guidelines ?? '').trim();
                const cwe   = Array.isArray(dd.cwe) ? dd.cwe.join('; ') : '';
                const owasp = Array.isArray(dd.owasp) ? dd.owasp.join('; ') : '';
                const langs = Array.isArray(dd.languages) ? dd.languages.join(', ') : '';

                const metaParts: string[] = [];
                if (cwe)   metaParts.push(`<div><strong>CWE:</strong> ${sanitizeHtmlInput(cwe)}</div>`);
                if (owasp) metaParts.push(`<div><strong>OWASP:</strong> ${sanitizeHtmlInput(owasp)}</div>`);
                if (langs) metaParts.push(`<div><strong>Lang:</strong> ${sanitizeHtmlInput(langs)}</div>`);
                const metaHtml = metaParts.join('') || '<span style="color:var(--muted)">—</span>';

                const hs = [sev, rule, desc, filePath, String(line), cwe, owasp, langs].join(' ').toLowerCase();
                return `<tr data-severity="${sanitizeHtmlInput(sev)}" data-sev-rank="${SEVERITY_ORDER.indexOf(sev)}" data-type="${sanitizeHtmlInput(d.type ?? '')}" data-search="${sanitizeHtmlInput(hs)}">` +
                    sevCell +
                    `<td><strong>${rule}</strong></td>` +
                    `<td>${buildDescBlock(desc, rem)}</td>` +
                    fileCell +
                    `<td class="meta-col">${metaHtml}</td>` +
                    `</tr>`;
            }
            case 'sca': {
                const alert = dd.alert ?? {};
                const cve = alert.cve_identifier ?? '';
                const ghsa = alert.ghsa_identifier ?? '';
                const desc = (alert.description ?? '').trim();
                const depPath = (alert.dependency_paths ?? '').trim();
                const rem = (dd.remediation_guidelines ?? dd.custom_remediation_guidelines ?? '').trim();
                const manifestPath = normalizeFilePath(dd.manifest_file_path ?? dd.file_name ?? '', scanPath);

                // Extract package name & version from the alert object
                const pkgName = alert.affected_package_name ?? '';
                const pkgVer = alert.vulnerable_requirements ?? '';
                const pkgDisplay = pkgName ? `${pkgName}@${pkgVer}` : 'Unknown';
                const ecosystem = dd.build_tool ?? 'Unknown'; // 

                const cvss = dd.cvss_score != null ? dd.cvss_score.toFixed(1) : null;
                const epss = dd.epss != null ? (dd.epss * 100).toFixed(2) + '%' : null;
                const isDirect = dd.is_direct_dependency;
                const isDev    = dd.is_dev_dependency;

                // Build the Package Info column content — shared helper + SCA-specific CVE/GHSA/CVSS/EPSS
                const basePkgHtml = buildPackageInfoHtml(ecosystem, pkgDisplay, isDirect, isDev);
                const scaExtras: string[] = [];
                if (cve)  scaExtras.push(`<div><strong>CVE:</strong> ${sanitizeHtmlInput(cve)}</div>`);
                if (ghsa) scaExtras.push(`<div><strong>GHSA:</strong> ${sanitizeHtmlInput(ghsa)}</div>`);
                if (cvss) scaExtras.push(`<div><strong>CVSS:</strong> ${sanitizeHtmlInput(cvss)}</div>`);
                if (epss) scaExtras.push(`<div><strong>EPSS:</strong> ${sanitizeHtmlInput(epss)}</div>`);
                const idHtml = basePkgHtml + scaExtras.join('');

                const depHtml = buildDepPathHtml(depPath);

                // Remediation column: description first, then remediation guidelines
                const remParts: string[] = [];
                if (desc) {
                    const descShort = desc.length > 200 ? desc.slice(0, 200) + '…' : desc;
                    remParts.push(`<div style="margin-bottom:6px;color:var(--muted);font-size:12px">${sanitizeHtmlInput(descShort)}</div>`);
                    if (desc.length > 200) remParts.push(`<details><summary>Full description</summary><div class="content">${sanitizeHtmlInput(desc)}</div></details>`);
                }
                const remShort = rem.length > 180 ? rem.slice(0, 180) + '…' : rem;
                remParts.push(`<div>${remShort ? sanitizeHtmlInput(remShort) : (desc ? '' : '<span style="color:var(--muted)">—</span>')}</div>`);
                if (rem.length > 180) remParts.push(`<details><summary>Full guidance</summary><div class="content">${sanitizeHtmlInput(rem)}</div></details>`);

                const hs = [sev, ecosystem, pkgName, pkgVer, cve, ghsa, desc, depPath, manifestPath, rem, cvss, epss].join(' ').toLowerCase();


                const directAttr = isDirect == null ? '' : (isDirect ? 'direct' : 'indirect');
                const devAttr    = isDev    == null ? '' : (isDev    ? 'yes'    : 'no');

                const manifestUrl = manifestPath ? buildAdoFileUrl(manifestPath, undefined, buildInfo) : null;
                const manifestCell = manifestPath
                    ? `<td><div class="file">${manifestUrl ? `<a href="${escapeHtmlAttr(manifestUrl)}" target="_blank">${sanitizeHtmlInput(manifestPath)}</a>` : sanitizeHtmlInput(manifestPath)}</div></td>`
                    : `<td><span style="color:var(--muted)">—</span></td>`;

                return `<tr data-severity="${sanitizeHtmlInput(sev)}" data-sev-rank="${SEVERITY_ORDER.indexOf(sev)}" data-type="${sanitizeHtmlInput(d.type ?? '')}" data-direct="${directAttr}" data-dev="${devAttr}" data-search="${sanitizeHtmlInput(hs)}">` +
                    sevCell +
                    `<td>${idHtml}</td>` +
                    `<td>${depHtml}</td>` +
                    manifestCell +
                    `<td>${remParts.join('')}</td>` +
                    `</tr>`;
            }
            case 'sca_license': {
                const licenseVal  = (dd.license ?? '').trim();
                const licenseDisplay = licenseVal
                    ? licenseVal.split(',').map(l => `<span style="background:#e8f5e9;color:#2e7d32;border-radius:4px;padding:1px 6px;margin-right:4px;font-size:12px">${sanitizeHtmlInput(l.trim())}</span>`).join('')
                    : sanitizeHtmlInput(dd.policy_display_name ?? d.detection_rule_id ?? 'Unknown');

                const pkgName    = dd.package_name ?? '';
                const pkgVer     = dd.package_version ?? '';
                const pkgDisplay = pkgName ? `${pkgName}@${pkgVer}` : 'Unknown';
                const ecosystem  = dd.build_tool ?? dd.ecosystem ?? 'Unknown';
                const isDirect   = dd.is_direct_dependency;
                const isDev      = dd.is_dev_dependency;
                const depPath    = (dd.dependency_paths ?? '').trim();
                const manifestPath = normalizeFilePath(dd.manifest_file_path ?? dd.file_name ?? '', scanPath);

                const idHtml  = buildPackageInfoHtml(ecosystem, pkgDisplay, isDirect, isDev);
                const depHtml = buildDepPathHtml(depPath);

                // Description column: message, then remediation guidelines
                const msg  = (d.message ?? '').trim();
                const rem  = (dd.remediation_guidelines ?? dd.custom_remediation_guidelines ?? '').trim();
                const descParts: string[] = [];
                if (msg) {
                    const msgShort = msg.length > 180 ? msg.slice(0, 180) + '…' : msg;
                    descParts.push(`<div style="margin-bottom:4px">${sanitizeHtmlInput(msgShort)}</div>`);
                    if (msg.length > 180) descParts.push(`<details><summary>Full message</summary><div class="content">${sanitizeHtmlInput(msg)}</div></details>`);
                }
                if (rem) {
                    const remShort = rem.length > 180 ? rem.slice(0, 180) + '…' : rem;
                    descParts.push(`<div style="color:var(--muted);font-size:12px">${sanitizeHtmlInput(remShort)}</div>`);
                    if (rem.length > 180) descParts.push(`<details><summary>Full guidance</summary><div class="content">${sanitizeHtmlInput(rem)}</div></details>`);
                }
                if (!descParts.length) descParts.push('<span style="color:var(--muted)">—</span>');

                const directAttr = isDirect == null ? '' : (isDirect ? 'direct' : 'indirect');
                const devAttr    = isDev    == null ? '' : (isDev    ? 'yes'    : 'no');

                const hs = [sev, licenseVal, pkgName, pkgVer, ecosystem, msg, rem, depPath, manifestPath].join(' ').toLowerCase();
                return `<tr data-severity="${sanitizeHtmlInput(sev)}" data-sev-rank="${SEVERITY_ORDER.indexOf(sev)}" data-type="${sanitizeHtmlInput(d.type ?? '')}" data-direct="${directAttr}" data-dev="${devAttr}" data-search="${sanitizeHtmlInput(hs)}">` +
                    sevCell +
                    `<td>${idHtml}</td>` +
                    `<td>${licenseDisplay}</td>` +
                    `<td>${depHtml}</td>` +
                    `<td>${descParts.join('')}</td>` +
                    `</tr>`;
            }
            case 'secrets': {
                const secretType = sanitizeHtmlInput(dd.policy_display_name ?? d.detection_rule_id ?? 'Unknown');
                const msg  = (d.message ?? '').trim();
                const desc = (dd.description ?? '').trim();
                const rem  = (dd.remediation_guidelines ?? dd.custom_remediation_guidelines ?? '').trim();

                // Combine directory path + filename so the cell shows the full relative path
                const rawSecretPath = (dd.file_path ?? '').replace(/\/?$/, '/') + (dd.file_name ?? '');
                const secretFilePath = normalizeFilePath(rawSecretPath || (dd.file_path ?? ''), scanPath);
                const secretFileUrl  = secretFilePath ? buildAdoFileUrl(secretFilePath, line, buildInfo) : null;
                const secretFileInner = secretFileUrl
                    ? `<a href="${escapeHtmlAttr(secretFileUrl)}" target="_blank">${sanitizeHtmlInput(secretFilePath)}</a>`
                    : sanitizeHtmlInput(secretFilePath);
                const secretFileCell = `<td><div class="file">${secretFileInner}</div>` +
                    `${line ? `<div class="line">Line ${sanitizeHtmlInput(line)}</div>` : ''}</td>`;

                const descParts: string[] = [];
                if (msg) {
                    const msgShort = msg.length > 200 ? msg.slice(0, 200) + '…' : msg;
                    descParts.push(`<div style="margin-bottom:4px">${sanitizeHtmlInput(msgShort)}</div>`);
                    if (msg.length > 200) descParts.push(`<details><summary>Full message</summary><div class="content">${sanitizeHtmlInput(msg)}</div></details>`);
                }
                if (desc) {
                    const descShort = desc.length > 180 ? desc.slice(0, 180) + '…' : desc;
                    descParts.push(`<div style="margin-bottom:4px;color:var(--muted);font-size:12px">${sanitizeHtmlInput(descShort)}</div>`);
                    if (desc.length > 180) descParts.push(`<details><summary>Full description</summary><div class="content">${sanitizeHtmlInput(desc)}</div></details>`);
                }
                if (rem) {
                    const remShort = rem.length > 180 ? rem.slice(0, 180) + '…' : rem;
                    descParts.push(`<div style="color:var(--muted);font-size:12px">${sanitizeHtmlInput(remShort)}</div>`);
                    if (rem.length > 180) descParts.push(`<details><summary>Full guidance</summary><div class="content">${sanitizeHtmlInput(rem)}</div></details>`);
                }
                if (!descParts.length) descParts.push('<span style="color:var(--muted)">—</span>');

                const hs = [sev, secretType, msg, desc, rem, secretFilePath, String(line)].join(' ').toLowerCase();
                return `<tr data-severity="${sanitizeHtmlInput(sev)}" data-sev-rank="${SEVERITY_ORDER.indexOf(sev)}" data-type="${sanitizeHtmlInput(d.type ?? '')}" data-search="${sanitizeHtmlInput(hs)}">` +
                    sevCell +
                    `<td><strong>${secretType}</strong></td>` +
                    secretFileCell +
                    `<td>${descParts.join('')}</td>` +
                    `</tr>`;
            }
            case 'iac': {
                const vuln     = sanitizeHtmlInput(dd.policy_display_name ?? d.detection_rule_id ?? 'Unknown');
                const desc     = (dd.description ?? d.message ?? '').trim();
                const rem      = (dd.remediation_guidelines ?? dd.custom_remediation_guidelines ?? '').trim();
                const cwe      = Array.isArray(dd.cwe) ? dd.cwe.join('; ') : '';
                const owasp    = Array.isArray(dd.owasp) ? dd.owasp.join('; ') : '';
                const provider = (dd.infra_provider ?? '').trim();

                const refParts: string[] = [];
                if (provider) refParts.push(`<div><strong>Provider:</strong> ${sanitizeHtmlInput(provider)}</div>`);
                if (cwe)      refParts.push(`<div><strong>CVE/CWE:</strong> ${sanitizeHtmlInput(cwe)}</div>`);
                if (owasp)    refParts.push(`<div><strong>OWASP:</strong> ${sanitizeHtmlInput(owasp)}</div>`);
                const refHtml = refParts.join('') || '<span style="color:var(--muted)">—</span>';

                const iacLineNum = dd.line_in_file;
                const iacFileUrl = filePath ? buildAdoFileUrl(filePath, iacLineNum, buildInfo) : null;
                const iacFileInner = iacFileUrl
                    ? `<a href="${escapeHtmlAttr(iacFileUrl)}" target="_blank">${sanitizeHtmlInput(filePath)}</a>`
                    : sanitizeHtmlInput(filePath);
                const iacLineDisplay = iacLineNum != null && iacLineNum !== -1
                    ? `<div class="line">Line ${sanitizeHtmlInput(iacLineNum)}</div>` : '';

                const hs = [sev, vuln, filePath, desc, rem, cwe, owasp, provider].join(' ').toLowerCase();
                return `<tr data-severity="${sanitizeHtmlInput(sev)}" data-sev-rank="${SEVERITY_ORDER.indexOf(sev)}" data-type="${sanitizeHtmlInput(d.type ?? '')}" data-provider="${sanitizeHtmlInput(provider)}" data-search="${sanitizeHtmlInput(hs)}">` +
                    sevCell +
                    `<td><strong>${vuln}</strong></td>` +
                    `<td><div class="file">${iacFileInner}</div>${iacLineDisplay}</td>` +
                    `<td>${buildDescBlock(desc, rem)}</td>` +
                    `<td class="meta-col">${refHtml}</td>` +
                    `</tr>`;
            }
            default: {
                const issueName = sanitizeHtmlInput(dd.policy_display_name ?? d.detection_rule_id ?? 'Unknown');
                const desc      = (dd.description ?? d.message ?? '').trim();
                const short     = desc.length > 180 ? desc.slice(0, 180) + '…' : desc;
                const hs = [sev, issueName, desc, filePath, String(line)].join(' ').toLowerCase();
                return `<tr data-severity="${sanitizeHtmlInput(sev)}" data-sev-rank="${SEVERITY_ORDER.indexOf(sev)}" data-type="${sanitizeHtmlInput(d.type ?? '')}" data-search="${sanitizeHtmlInput(hs)}">` +
                    sevCell +
                    `<td><strong>${issueName}</strong></td>` +
                    `<td>${sanitizeHtmlInput(short)}</td>` +
                    fileCell +
                    `<td>—</td>` +
                    `</tr>`;
            }
        }
    }).join('\n    ');
}

export function generateHtmlReport(
    detections: Detection[],
    scanPath: string,
    scanType: string,
    buildInfo: BuildInfo
): string {
    // Overall severity counts for summary cards
    const counts: Record<string, number> = {};
    for (const d of detections) {
        const s = normalizeSeverity(d.severity);
        counts[s] = (counts[s] ?? 0) + 1;
    }
    const presentSevs = SEVERITY_ORDER.filter(s => counts[s] > 0);
    const summaryCards = [
        `<div class="summary-card"><div class="label">Total</div><div class="value">${detections.length}</div></div>`,
        ...presentSevs.map(sev =>
            `<div class="summary-card"><div class="label">${sev}</div>` +
            `<div class="value" style="color:${SEVERITY_COLORS[sev]};">${counts[sev]}</div></div>`
        ),
    ].join('\n  ');

    // Map Cycode detection type values to display tabs (case-insensitive key lookup)
    // Primary routing: use the CLI scan type stamped at collection time.
    // SCA still needs d.type inspection to split vulnerability vs license findings.
    // TYPE_TO_TAB is kept as a fallback for untagged detections (e.g. future integrations).
    const SCAN_TO_TAB: Record<string, string> = {
        sast:   'sast',
        secret: 'secrets',
        iac:    'iac',
    };
    const TYPE_TO_TAB: Record<string, string> = {
        'vulnerable_code_dependency': 'sca',
        'non permissive license':     'sca_license',
        'non_permissive_license':     'sca_license',
    };

    const byTab: Record<string, Detection[]> = {};
    for (const d of detections) {
        let tab: string;
        if (d._scanType === 'sca') {
            const raw = (d.type ?? '').toLowerCase().trim();
            tab = raw.includes('license') ? 'sca_license' : 'sca';
        } else if (d._scanType && SCAN_TO_TAB[d._scanType]) {
            tab = SCAN_TO_TAB[d._scanType];
        } else {
            const raw = (d.type ?? '').toLowerCase().trim();
            tab = TYPE_TO_TAB[raw] ?? (raw || 'other');
        }
        if (!byTab[tab]) byTab[tab] = [];
        byTab[tab].push(d);
    }

    const TAB_LABELS: Record<string, string> = {
        sast:        'SAST',
        sca:         'SCA',
        sca_license: 'SCA License',
        secrets:     'Secrets',
        iac:         'IaC',
    };
    const TAB_ORDER = ['sast', 'sca', 'sca_license', 'secrets', 'iac'];
    const orderedTypes = [
        ...TAB_ORDER.filter(t => byTab[t]?.length),
        ...Object.keys(byTab).filter(t => !TAB_ORDER.includes(t) && byTab[t]?.length),
    ];

    const tabButtons = orderedTypes.map((t, i) => {
        const label = TAB_LABELS[t] ?? t.toUpperCase();
        const cnt   = byTab[t].length;
        return `<button class="tab-btn${i === 0 ? ' active' : ''}" data-tab="${t}">${sanitizeHtmlInput(label)}<span class="tab-count">${cnt}</span></button>`;
    }).join('\n    ');

    const tabPanels = orderedTypes.map((t, i) => {
        const tabDetections = byTab[t];
        const rows    = buildTypeRows(t, tabDetections, scanPath, buildInfo);
        const headers = getTypeHeaders(t);

        const tabCounts: Record<string, number> = {};
        for (const d of tabDetections) {
            const s = normalizeSeverity(d.severity);
            tabCounts[s] = (tabCounts[s] ?? 0) + 1;
        }

        return `<div class="tab-panel${i === 0 ? ' active' : ''}" id="panel-${t}" data-counts='${JSON.stringify(tabCounts)}'>` +
            `<table class="findings">` +
            `<thead><tr>${headers}</tr></thead>` +
            `<tbody>${rows || '<tr><td colspan="10" class="empty">No findings.</td></tr>'}</tbody>` +
            `</table></div>`;
    }).join('\n');

    const severityOptions = SEVERITY_ORDER
        .filter(s => presentSevs.includes(s))
        .map(s => `<option value="${s}">${s}</option>`).join('\n    ');

    const shortCommit = buildInfo.commit ? buildInfo.commit.slice(0, 7) : '';
    const metaLine1Parts: string[] = [];
    if (buildInfo.repo)   metaLine1Parts.push(`Repo: <strong>${sanitizeHtmlInput(buildInfo.repo)}</strong>`);
    if (buildInfo.branch) metaLine1Parts.push(`Branch: <strong>${sanitizeHtmlInput(buildInfo.branch)}</strong>`);
    if (shortCommit)      metaLine1Parts.push(`Commit: <code>${sanitizeHtmlInput(shortCommit)}</code>`);
    const metaLine1 = metaLine1Parts.join(' &middot; ');
    const metaLine2Parts: string[] = [`Scan path: <code>${sanitizeHtmlInput(scanPath)}</code>`];
    metaLine2Parts.push(`Scan type(s): <strong>${sanitizeHtmlInput(scanType)}</strong>`);
    const metaLine2 = metaLine2Parts.join(' &middot; ');

    return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<title>Cycode Scan Report</title>
<style>
  :root{--bg:#f7f8fa;--fg:#212121;--muted:#546e7a;--card:#fff;--border:#e0e3e7;--accent:#1565c0}
  *{box-sizing:border-box}
  body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:14px;line-height:1.45}
  h1{margin:0 0 8px;font-size:22px}
  .meta{color:var(--muted);margin-bottom:20px}
  .summary-grid{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:0}
  .summary-section{margin-bottom:16px}
  .summary-section>summary{cursor:pointer;font-size:12px;font-weight:600;text-transform:uppercase;
    letter-spacing:.5px;color:var(--muted);list-style:none;user-select:none;padding:4px 0;
    display:inline-flex;align-items:center;gap:4px}
  .summary-section>summary::-webkit-details-marker{display:none}
  .summary-section>summary::before{content:"▸";font-size:10px}
  .summary-section[open]>summary::before{content:"▾"}
  .summary-section>summary~*{margin-top:8px}
  .summary-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;min-width:110px}
  .summary-card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  .summary-card .value{font-size:22px;font-weight:600;margin-top:2px}
  .tab-nav{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:16px}
  .tab-btn{background:none;border:none;border-bottom:3px solid transparent;margin-bottom:-2px;
    padding:10px 18px;font-size:14px;font-weight:500;cursor:pointer;color:var(--muted);
    display:flex;align-items:center;gap:8px;transition:color .15s}
  .tab-btn:hover{color:var(--fg)}
  .tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}
  .tab-count{background:#eceff1;color:#37474f;border-radius:10px;padding:1px 7px;font-size:12px;font-weight:600}
  .tab-btn.active .tab-count{background:#e3f2fd;color:var(--accent)}
  .tab-panel{display:none}
  .tab-panel.active{display:block}
  .controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
  .controls input,.controls select{padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;background:#fff}
  .controls input{flex:1;min-width:200px}
  .findings{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
  .findings thead th{text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);background:#eceff1;border-bottom:1px solid var(--border)}
  .findings tbody td{padding:12px;vertical-align:top;border-bottom:1px solid var(--border)}
  .findings tbody tr:last-child td{border-bottom:none}
  .findings tbody tr.hidden{display:none}
  .sev{display:inline-block;padding:2px 10px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
  .file{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-all}
  .line{color:var(--muted)}
  .meta-col{color:var(--muted);font-size:12.5px}
  details{margin-top:6px}
  details summary{cursor:pointer;color:var(--accent);font-size:12.5px;user-select:none;list-style:none}
  details summary::-webkit-details-marker{display:none}
  details summary::before{content:"▸ ";color:var(--accent)}
  details[open] summary::before{content:"▾ "}
  details .content{margin-top:6px;padding:10px 12px;background:#fafbfc;border-left:3px solid var(--accent);border-radius:4px;font-size:13px;white-space:pre-wrap}
  .empty{text-align:center;padding:40px;color:var(--muted)}
  .sortable{cursor:pointer;user-select:none}
  .sortable:hover{background:#dde0e4!important}
  .sort-icon{display:inline-block;margin-left:4px;font-size:10px}
  .sortable:not(.sort-asc):not(.sort-desc) .sort-icon::after{content:"↕";color:#b0bec5}
  .sortable.sort-asc .sort-icon::after{content:"▲";color:var(--accent)}
  .sortable.sort-desc .sort-icon::after{content:"▼";color:var(--accent)}
</style>
</head>
<body>
<h1>Cycode Security Scan Results</h1>
<div class="meta">
  ${metaLine1}
  <br>${metaLine2}
</div>

<details class="summary-section" open>
  <summary>Overall Summary</summary>
  <div class="summary-grid">
    ${summaryCards}
  </div>
</details>

<div class="tab-nav">
  ${tabButtons || '<span style="padding:10px 18px;color:var(--muted)">No findings</span>'}
</div>

<details class="summary-section" id="tab-summary-section" open>
  <summary>Tab Summary</summary>
  <div id="tab-summary" class="summary-grid"></div>
</details>

<div class="controls">
  <input id="search" type="search" placeholder="Search findings…">
  <select id="severity-filter">
    <option value="">All severities</option>
    ${severityOptions}
  </select>
  <select id="type-filter" style="display:none"></select>
  <select id="provider-filter" style="display:none"></select>
  <select id="direct-filter" style="display:none">
    <option value="">Direct &amp; Indirect</option>
    <option value="direct">Direct only</option>
    <option value="indirect">Indirect only</option>
  </select>
  <select id="dev-filter" style="display:none">
    <option value="">All (incl. dev)</option>
    <option value="no">Non-dev only</option>
    <option value="yes">Dev only</option>
  </select>
  <span id="shown-count" style="color:var(--muted);font-size:12px"></span>
</div>

${tabPanels || '<p style="text-align:center;color:var(--muted);padding:40px">No findings detected.</p>'}

<script>
(function(){
  var tabBtns=document.querySelectorAll('.tab-btn');
  var allPanels=document.querySelectorAll('.tab-panel');
  var search=document.getElementById('search');
  var sevFilter=document.getElementById('severity-filter');
  var typeFilter=document.getElementById('type-filter');
  var providerFilter=document.getElementById('provider-filter');
  var directFilter=document.getElementById('direct-filter');
  var devFilter=document.getElementById('dev-filter');
  var shownCount=document.getElementById('shown-count');

  function initSort(panel){
    var table=panel.querySelector('.findings');
    var tbody=table?table.querySelector('tbody'):null;
    if(!tbody)return;
    var headers=table.querySelectorAll('thead th[data-col-idx]');
    var sortCol=0,sortDir=1;
    function doSort(){
      var rows=Array.prototype.slice.call(tbody.querySelectorAll('tr[data-severity]'));
      rows.sort(function(a,b){
        var av,bv;
        if(sortCol===0){
          av=parseInt(a.getAttribute('data-sev-rank')||'99',10);
          bv=parseInt(b.getAttribute('data-sev-rank')||'99',10);
          return sortDir*(av-bv);
        }
        var ac=a.cells[sortCol],bc=b.cells[sortCol];
        av=(ac?(ac.textContent||''):'').trim().toLowerCase();
        bv=(bc?(bc.textContent||''):'').trim().toLowerCase();
        return sortDir*(av<bv?-1:av>bv?1:0);
      });
      rows.forEach(function(r){tbody.appendChild(r);});
      headers.forEach(function(th){
        th.classList.remove('sort-asc','sort-desc');
        if(parseInt(th.getAttribute('data-col-idx'),10)===sortCol){
          th.classList.add(sortDir===1?'sort-asc':'sort-desc');
        }
      });
    }
    headers.forEach(function(th){
      th.addEventListener('click',function(){
        var col=parseInt(th.getAttribute('data-col-idx'),10);
        sortDir=sortCol===col?-sortDir:1;
        sortCol=col;
        doSort();
      });
    });
    doSort();
  }
  allPanels.forEach(function(p){initSort(p);});

  var SEV_ORDER=['Critical','High','Medium','Low','Info'];
  var SEV_COLORS={Critical:'#b71c1c',High:'#e65100',Medium:'#f9a825',Low:'#1565c0',Info:'#546e7a'};
  var tabSummaryEl=document.getElementById('tab-summary');
  var tabSummarySection=document.getElementById('tab-summary-section');
  function renderTabSummary(panel){
    if(!tabSummaryEl||!panel)return;
    var counts={};
    try{counts=JSON.parse(panel.getAttribute('data-counts')||'{}');}catch(e){}
    var total=Object.values(counts).reduce(function(a,b){return a+b;},0);
    var html='<div class="summary-card"><div class="label">Total</div><div class="value">'+total+'</div></div>';
    SEV_ORDER.forEach(function(s){
      if(counts[s]){
        html+='<div class="summary-card"><div class="label">'+s+'</div>'+
          '<div class="value" style="color:'+SEV_COLORS[s]+';">'+counts[s]+'</div></div>';
      }
    });
    tabSummaryEl.innerHTML=html;
    if(tabSummarySection)tabSummarySection.style.display=total>0?'':'none';
  }
  renderTabSummary(document.querySelector('.tab-panel.active'));

  function getActiveRows(){
    var active=document.querySelector('.tab-panel.active');
    return active?active.querySelectorAll('tbody tr[data-severity]'):[];
  }
  function updateTypeFilter(panel){
    if(!typeFilter||!panel)return;
    var rows=panel.querySelectorAll('tbody tr[data-type]');
    var seen={};
    rows.forEach(function(tr){var t=tr.getAttribute('data-type')||'';if(t)seen[t]=true;});
    var types=Object.keys(seen);
    if(types.length>1){
      var html='<option value="">All types</option>';
      types.forEach(function(t){html+='<option value="'+t+'">'+t+'</option>';});
      typeFilter.innerHTML=html;
      typeFilter.style.display='';
    }else{
      typeFilter.innerHTML='';
      typeFilter.style.display='none';
    }
    typeFilter.value='';
  }
  function updateIacFilters(panel){
    if(!providerFilter||!panel)return;
    var isIac=panel.id==='panel-iac';
    if(!isIac){providerFilter.style.display='none';providerFilter.value='';return;}
    var rows=panel.querySelectorAll('tbody tr[data-provider]');
    var seen={};
    rows.forEach(function(tr){var p=tr.getAttribute('data-provider')||'';if(p)seen[p]=true;});
    var providers=Object.keys(seen);
    if(providers.length>1){
      var html='<option value="">All providers</option>';
      providers.forEach(function(p){html+='<option value="'+p+'">'+p+'</option>';});
      providerFilter.innerHTML=html;
      providerFilter.style.display='';
    }else{
      providerFilter.innerHTML='';
      providerFilter.style.display='none';
    }
    providerFilter.value='';
  }
  function updateScaFilters(panel){
    var isSca=panel&&(panel.id==='panel-sca'||panel.id==='panel-sca_license');
    if(directFilter)directFilter.style.display=isSca?'':'none';
    if(devFilter)devFilter.style.display=isSca?'':'none';
    if(directFilter)directFilter.value='';
    if(devFilter)devFilter.value='';
  }
  function applyFilters(){
    var q=search.value.trim().toLowerCase();
    var sev=sevFilter.value;
    var typ=typeFilter?typeFilter.value:'';
    var provider=providerFilter?providerFilter.value:'';
    var direct=directFilter?directFilter.value:'';
    var dev=devFilter?devFilter.value:'';
    var rows=getActiveRows();
    var shown=0;
    rows.forEach(function(tr){
      var match=
        (!q||(tr.getAttribute('data-search')||'').indexOf(q)!==-1)&&
        (!sev||(tr.getAttribute('data-severity')||'')===sev)&&
        (!typ||(tr.getAttribute('data-type')||'')===typ)&&
        (!provider||(tr.getAttribute('data-provider')||'')===provider)&&
        (!direct||(tr.getAttribute('data-direct')||'')===direct)&&
        (!dev||(tr.getAttribute('data-dev')||'')===dev);
      tr.classList.toggle('hidden',!match);
      if(match)shown++;
    });
    shownCount.textContent=rows.length>0?'Showing '+shown+' of '+rows.length:'';
  }
  tabBtns.forEach(function(btn){
    btn.addEventListener('click',function(){
      tabBtns.forEach(function(b){b.classList.remove('active');});
      allPanels.forEach(function(p){p.classList.remove('active');});
      btn.classList.add('active');
      var panel=document.getElementById('panel-'+btn.getAttribute('data-tab'));
      if(panel)panel.classList.add('active');
      renderTabSummary(panel);
      updateTypeFilter(panel);
      updateIacFilters(panel);
      updateScaFilters(panel);
      search.value='';
      sevFilter.value='';
      applyFilters();
    });
  });
  search.addEventListener('input',applyFilters);
  sevFilter.addEventListener('change',applyFilters);
  if(typeFilter)typeFilter.addEventListener('change',applyFilters);
  if(providerFilter)providerFilter.addEventListener('change',applyFilters);
  if(directFilter)directFilter.addEventListener('change',applyFilters);
  if(devFilter)devFilter.addEventListener('change',applyFilters);
  updateTypeFilter(document.querySelector('.tab-panel.active'));
  updateIacFilters(document.querySelector('.tab-panel.active'));
  updateScaFilters(document.querySelector('.tab-panel.active'));
  applyFilters();
})();
</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Commit-history scan helpers
// ---------------------------------------------------------------------------

function httpsGet(url: string, token: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { headers: { Authorization: `Bearer ${token}` } }, res => {
            let body = '';
            res.on('data', (chunk: string) => body += chunk);
            res.on('end', () => resolve(body));
        });
        req.on('error', reject);
    });
}

interface AdoBuild { sourceVersion?: string; finishTime?: string; }

function getParentBranchCandidates(): string[] {
    // PR builds set the target branch explicitly — most reliable source
    const prTarget = (tl.getVariable('System.PullRequest.TargetBranch') ?? '').replace('refs/heads/', '');
    if (prTarget) return [prTarget];
    // For pushes to feature branches, try common integration branch names
    return ['main', 'master', 'develop', 'dev'];
}

async function queryAdoBuilds(
    base: string, projectId: string, definitionId: string, token: string, branchRef: string
): Promise<AdoBuild[]> {
    const branchParam = branchRef ? `&branchName=${encodeURIComponent(branchRef)}` : '';
    const url = `${base}/${projectId}/_apis/build/builds?definitions=${definitionId}&resultFilter=succeeded${branchParam}&$top=10&api-version=7.1`;
    const body = await httpsGet(url, token);
    return (JSON.parse(body)?.value ?? []) as AdoBuild[];
}

async function getPreviousSha(repoPath: string, currentSha: string, sourceBranch: string): Promise<string | null> {
    // Strategy 1: git rev-parse HEAD~1
    try {
        const sha = execSync('git rev-parse HEAD~1', {
            cwd: repoPath, shell: SHELL, encoding: 'utf8', stdio: 'pipe',
        }).trim();
        if (/^[0-9a-f]{40}$/i.test(sha) && sha !== currentSha) {
            console.log(`Previous SHA from git: ${sha.slice(0, 7)}`);
            return sha;
        }
    } catch {
        console.log('git rev-parse HEAD~1 failed — falling back to ADO REST API');
    }

    const collectionUri = tl.getVariable('System.TeamFoundationCollectionUri') ?? '';
    const projectId     = tl.getVariable('System.TeamProjectId') ?? '';
    const definitionId  = tl.getVariable('System.DefinitionId') ?? '';
    const token         = tl.getVariable('System.AccessToken') ?? '';
    const adoBase       = collectionUri.replace(/\/$/, '');
    const adoAvailable  = !!(collectionUri && projectId && definitionId && token);

    // Strategy 2: ADO REST API — same branch, different SHA
    if (adoAvailable) {
        try {
            console.log(`Fetching recent successful builds from ADO REST API (branch: ${sourceBranch || 'any'})...`);
            const builds = await queryAdoBuilds(adoBase, projectId, definitionId, token, sourceBranch);
            for (const build of builds) {
                const sha = build.sourceVersion ?? '';
                if (/^[0-9a-f]{40}$/i.test(sha) && sha !== currentSha) {
                    console.log(`Previous SHA from ADO REST API (same branch): ${sha.slice(0, 7)}`);
                    return sha;
                }
            }
            console.log('No previous build with a different SHA found on this branch — trying parent branch...');
        } catch (err: any) {
            console.log(`ADO REST API (same branch) failed: ${err.message}`);
        }
    } else {
        console.log('ADO REST API skipped — System.* variables not available');
    }

    // Strategy 3: Parent branch fallback
    const parentCandidates = getParentBranchCandidates();

    // 3a: git merge-base — gives the exact fork point, inherently excludes any post-fork commits
    for (const branch of parentCandidates) {
        try {
            const sha = execSync(`git merge-base HEAD origin/${branch}`, {
                cwd: repoPath, shell: SHELL, encoding: 'utf8', stdio: 'pipe',
            }).trim();
            if (/^[0-9a-f]{40}$/i.test(sha) && sha !== currentSha) {
                console.log(`Fork point with origin/${branch}: ${sha.slice(0, 7)}`);
                return sha;
            }
        } catch { /* branch not present in shallow clone, try next candidate */ }
    }

    // 3b: ADO REST API — last successful build on parent branch, filtered to builds that
    //     finished before the current build started (excludes post-fork builds)
    if (adoAvailable) {
        let cutoff: Date | null = null;
        try {
            const buildId = tl.getVariable('Build.BuildId') ?? '';
            if (buildId) {
                const buildBody = await httpsGet(`${adoBase}/${projectId}/_apis/build/builds/${buildId}?api-version=7.1`, token);
                const buildJson = JSON.parse(buildBody);
                const t = buildJson?.startTime ?? buildJson?.queueTime ?? '';
                if (t) cutoff = new Date(t);
            }
        } catch { /* proceed without time filtering */ }

        for (const branch of parentCandidates) {
            try {
                const fullRef = `refs/heads/${branch}`;
                console.log(`Trying parent branch ${branch} via ADO REST API...`);
                const builds = await queryAdoBuilds(adoBase, projectId, definitionId, token, fullRef);
                for (const build of builds) {
                    const sha = build.sourceVersion ?? '';
                    if (!/^[0-9a-f]{40}$/i.test(sha) || sha === currentSha) continue;
                    if (cutoff && build.finishTime && new Date(build.finishTime) > cutoff) continue;
                    console.log(`Previous SHA from parent branch ${branch}: ${sha.slice(0, 7)}`);
                    return sha;
                }
            } catch (err: any) {
                console.log(`Parent branch ${branch} ADO API failed: ${err.message}`);
            }
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// Main task entry point
// ---------------------------------------------------------------------------

async function run(): Promise<void> {
    try {
        const clientId     = tl.getInput('CycodeClientID', true)!;
        const clientSecret = tl.getInput('CycodeClientSecret', true)!;
        const scanPath     = tl.getInput('scanPath') || tl.getVariable('Build.SourcesDirectory') || '.';
        const sevThreshold = tl.getInput('severityThreshold') || 'Info';
        const breakPipeline = tl.getBoolInput('breakPipeline', false);
        const extraFlags   = tl.getInput('additionalFlags') || '';
        const verbose      = tl.getBoolInput('verbose', false);

        // Ensure Cycode CLI is available, installing if necessary
        const cycodeExe = ensureCycodeInstalled();

        const statusOut = (() => { try { return execSync(`${cycodeExe} status`, { shell: SHELL, encoding: 'utf8' }).trim(); } catch { return 'unknown'; } })();
        console.log(`Cycode CLI status: ${statusOut}`);

        const scanMode     = tl.getInput('scanMode') || 'path';
        const scanTypes    = parseScanTypes(tl.getInput('scanType') || 'all');
        const verboseFlag  = verbose ? ' -v' : '';
        const extraStr     = extraFlags ? ` ${extraFlags}` : '';
        const quotedPath   = `"${scanPath.replace(/"/g, '\\"')}"`;

        const credentials: Record<string, string> = {
            CYCODE_CLIENT_ID:     clientId,
            CYCODE_CLIENT_SECRET: clientSecret,
        };

        const tempDir = tl.getVariable('Agent.TempDirectory') ?? __dirname;

        const repo   = tl.getVariable('Build.Repository.Name') ?? '';
        const branch = tl.getVariable('Build.SourceBranchName') ?? '';
        const commit = tl.getVariable('Build.SourceVersion') ?? '';
        console.log(`Repository: ${repo || '(unknown)'}`);
        console.log(`Branch:     ${branch || '(unknown)'}`);
        console.log(`Commit:     ${commit ? commit.slice(0, 7) : '(unknown)'}`);
        console.log(`Scan path:  ${scanPath}`);
        console.log(`Scan type:  ${scanTypes.join(', ')}`);

        // Resolve commit range once before the scan loop
        let commitRange: string | null = null;
        if (scanMode === 'commitHistory') {
            const currentSha  = tl.getVariable('Build.SourceVersion') ?? '';
            const sourceBranch = tl.getVariable('Build.SourceBranch') ?? '';
            const prevSha    = await getPreviousSha(scanPath, currentSha, sourceBranch);
            if (!prevSha) {
                throw new Error(
                    'Commit history scan requires a previous SHA but none could be resolved. ' +
                    'Ensure the pipeline has access to git history (no shallow clone) or that ' +
                    '"Allow scripts to access OAuth token" is enabled for the REST API fallback.'
                );
            }
            commitRange = `${prevSha}..${currentSha}`;
            console.log(`Commit range: ${commitRange}`);
        }

        const allDetections: Detection[] = [];
        const failedTypes: string[] = [];

        for (const type of scanTypes) {
            console.log(`\nStarting ${type} scan...`);
            const scanCmd = commitRange
                ? `${cycodeExe}${verboseFlag} -o json scan --soft-fail -t ${type}${extraStr} commit-history -r ${commitRange} ${quotedPath}`
                : `${cycodeExe}${verboseFlag} -o json scan --soft-fail -t ${type}${extraStr} path ${quotedPath}`;
            console.log(`Running: ${scanCmd}`);

            let rawData: ScanOutput | Detection[];
            try {
                const scanOutput = runScan(scanCmd, credentials);
                // Slice from the first { or [ to tolerate stray text before the JSON blob
                const jsonStart = scanOutput.search(/[{[]/);
                if (jsonStart === -1) throw new Error('no JSON found in output');
                rawData = JSON.parse(scanOutput.slice(jsonStart));
            } catch (err: any) {
                if (err instanceof AuthenticationError) throw err;
                console.log(`Warning: ${type} scan failed — ${err.message}`);
                failedTypes.push(type);
                continue;
            }

            // Upload per-type raw JSON artifact
            const jsonFile = path.join(tempDir, `cycode_results_${type}.json`);
            fs.writeFileSync(jsonFile, JSON.stringify(rawData, null, 2));
            tl.uploadArtifact('Cycode', jsonFile, 'Cycode Scan Results');

            const typeDetections = extractDetections(rawData).map(d => ({ ...d, _scanType: type }));
            console.log(`${type} scan complete — findings: ${typeDetections.length}`);
            allDetections.push(...typeDetections);
        }

        if (failedTypes.length) {
            console.log(`\nScan type(s) that failed: ${failedTypes.join(', ')}`);
        }

        console.log(`\nAll scans complete. Total findings: ${allDetections.length}`);

        // Severity breakdown for the log
        const counts: Record<string, number> = {};
        for (const d of allDetections) {
            const s = normalizeSeverity(d.severity);
            counts[s] = (counts[s] ?? 0) + 1;
        }
        for (const s of SEVERITY_ORDER) {
            if (counts[s]) console.log(`  ${s}: ${counts[s]}`);
        }

        // Write combined HTML report and attach to build results tab
        const reportFile = path.join(tempDir, 'cycode_results.html');
        const collectionUri = tl.getVariable('System.TeamFoundationCollectionUri') ?? '';
        const orgMatch = collectionUri.match(/dev\.azure\.com\/([^/]+)/);
        const buildInfo: BuildInfo = {
            repo:    tl.getVariable('Build.Repository.Name') ?? '',
            branch:  tl.getVariable('Build.SourceBranchName') ?? '',
            commit:  tl.getVariable('Build.SourceVersion') ?? '',
            org:     orgMatch?.[1] ?? '',
            project: tl.getVariable('System.TeamProject') ?? '',
        };
        fs.writeFileSync(reportFile, generateHtmlReport(allDetections, scanPath, scanTypes.join(', '), buildInfo));
        console.log(`##vso[task.addattachment type=cycode.scan.result;name=content;]${reportFile}`);

        // Gate: count findings at or above threshold
        const thresholdRank  = severityRank(sevThreshold);
        const flaggedCount   = allDetections.filter((d: Detection) => severityRank(d.severity ?? 'Info') <= thresholdRank).length;

        if (breakPipeline) {
            if (flaggedCount > 0) {
                tl.setResult(
                    tl.TaskResult.Failed,
                    `Cycode scan found ${flaggedCount} finding(s) at or above ` +
                    `${sevThreshold} severity. Pipeline will not continue.`
                );
            } else {
                console.log(`Cycode scan passed — no findings at or above ${sevThreshold} severity.`);
            }
        } else {
            console.log(
                `Cycode scan found ${allDetections.length} finding(s). ` +
                `Break pipeline is disabled — pipeline will continue.`
            );
        }
    } catch (err: any) {
        tl.setResult(tl.TaskResult.Failed, err.message);
    }
}

if (require.main === module) run();
