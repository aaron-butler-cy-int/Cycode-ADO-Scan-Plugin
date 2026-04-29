import * as tl from 'azure-pipelines-task-lib/task';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import sanitizeHtml from 'sanitize-html';

const SHELL = process.platform === 'win32' ? (process.env['ComSpec'] ?? 'cmd.exe') : '/bin/sh';

// ---------------------------------------------------------------------------
// Types matching the Cycode CLI JSON output schema
// ---------------------------------------------------------------------------

interface DetectionDetails {
    file_path?: string;
    file_name?: string;
    line?: number | string;
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
}

interface Detection {
    severity?: string;
    type?: string;
    message?: string;
    detection_rule_id?: string;
    detection_details?: DetectionDetails;
    id?: string;
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

function runScan(cmd: string, env: Record<string, string>): string {
    const mergedEnv = { ...process.env, ...env } as NodeJS.ProcessEnv;
    try {
        return execSync(cmd, {
            env: mergedEnv,
            encoding: 'utf8',
            shell: SHELL,
            maxBuffer: 100 * 1024 * 1024, // 100 MB
        });
    } catch (ex: any) {
        // Non-zero exit is expected when findings are present
        const stdout: string = ex.stdout
            ? (Buffer.isBuffer(ex.stdout) ? ex.stdout.toString('utf8') : String(ex.stdout))
            : '';
        if (stdout.trim()) return stdout;
        const stderr: string = ex.stderr
            ? (Buffer.isBuffer(ex.stderr) ? ex.stderr.toString('utf8') : String(ex.stderr))
            : '';
        throw new Error(`Cycode scan failed with no JSON output.\n${stderr || ex.message}`);
    }
}

function extractDetections(data: ScanOutput | Detection[]): Detection[] {
    if (Array.isArray(data)) return data;
    const out: Detection[] = [];
    for (const block of data.scan_results ?? []) {
        out.push(...(block.detections ?? []));
    }
    out.push(...(data.detections ?? []));
    return out;
}

// ---------------------------------------------------------------------------
// HTML report generator (ported from cycode-summary.py)
// ---------------------------------------------------------------------------

function sanitizeHtmlInput(val: string | number | undefined): string {
        return sanitizeHtml(String(val ?? ''));
}


function normalizeFilePath(p: string): string {
    if (!p) return '';
    // Strip ADO hosted-agent workspace prefix: /_work/<n>/s/...
    const adoMatch = p.match(/\/_work\/\d+\/s\/(.+)$/);
    if (adoMatch) return adoMatch[1];
    // Strip Windows-style agent path: \agent\_work\<n>\s\...
    const winMatch = p.match(/[\\\/]_work[\\\/]\d+[\\\/]s[\\\/](.+)$/);
    if (winMatch) return winMatch[1].replace(/\\/g, '/');
    return p.replace(/^\/+/, '');
}

function generateHtmlReport(
    detections: Detection[],
    scanPath: string,
    scanType: string
): string {
    const counts: Record<string, number> = {};
    for (const d of detections) {
        const s = normalizeSeverity(d.severity);
        counts[s] = (counts[s] ?? 0) + 1;
    }

    const presentSevs = SEVERITY_ORDER.filter(s => counts[s] > 0);
    const presentTypes = [...new Set(detections.map(d => d.type ?? '').filter(Boolean))].sort();

    const summaryCards = [
        `<div class="summary-card"><div class="label">Total</div><div class="value">${detections.length}</div></div>`,
        ...presentSevs.map(sev =>
            `<div class="summary-card">` +
            `<div class="label">${sev}</div>` +
            `<div class="value" style="color:${SEVERITY_COLORS[sev]};">${counts[sev]}</div>` +
            `</div>`
        ),
    ].join('\n  ');

    const severityOptions = presentSevs.map(s => `<option value="${s}">${s}</option>`).join('\n    ');
    const typeOptions = presentTypes.map(t => `<option value="${sanitizeHtmlInput(t)}">${sanitizeHtmlInput(t)}</option>`).join('\n    ');

    const rows = detections.map(d => {
        const sev   = normalizeSeverity(d.severity);
        const color = SEVERITY_COLORS[sev] ?? '#546e7a';
        const dd    = d.detection_details ?? {};
        const issueName   = sanitizeHtmlInput(dd.policy_display_name ?? d.detection_rule_id ?? 'Unknown');
        const description = (dd.description ?? d.message ?? '').trim();
        const descShort   = description.length > 180 ? description.slice(0, 180) + '…' : description;
        const filePath    = normalizeFilePath(dd.file_path ?? '');
        const line        = dd.line ?? '';
        const cwe         = Array.isArray(dd.cwe) ? dd.cwe.join('; ') : '';
        const owasp       = Array.isArray(dd.owasp) ? dd.owasp.join('; ') : '';
        const category    = dd.category ?? '';
        const languages   = Array.isArray(dd.languages) ? dd.languages.join(', ') : '';
        const remediation = (dd.remediation_guidelines ?? dd.custom_remediation_guidelines ?? '').trim();
        const type        = d.type ?? '';

        const metaParts: string[] = [];
        if (cwe)       metaParts.push(`<div><strong>CWE:</strong> ${sanitizeHtmlInput(cwe)}</div>`);
        if (owasp)     metaParts.push(`<div><strong>OWASP:</strong> ${sanitizeHtmlInput(owasp)}</div>`);
        if (category)  metaParts.push(`<div><strong>Category:</strong> ${sanitizeHtmlInput(category)}</div>`);
        if (languages) metaParts.push(`<div><strong>Language:</strong> ${sanitizeHtmlInput(languages)}</div>`);
        const metaHtml = metaParts.join('') || '<span style="color:var(--muted)">—</span>';

        const descParts: string[] = [`<div>${sanitizeHtmlInput(descShort)}</div>`];
        if (description.length > 180) {
            descParts.push(
                `<details><summary>Full description</summary>` +
                `<div class="content">${sanitizeHtmlInput(description)}</div></details>`
            );
        }
        if (remediation) {
            descParts.push(
                `<details><summary>Mitigation guidance</summary>` +
                `<div class="content">${sanitizeHtmlInput(remediation)}</div></details>`
            );
        }

        const haystack = [sev, type, issueName, description, filePath, String(line), cwe, owasp, category, languages]
            .join(' ').toLowerCase();

        return (
            `<tr data-severity="${sanitizeHtmlInput(sev)}" data-type="${sanitizeHtmlInput(type)}" data-search="${sanitizeHtmlInput(haystack)}">` +
            `<td><span class="sev" style="background:${color};">${sanitizeHtmlInput(sev)}</span>` +
            `<div style="margin-top:6px"><span class="type-badge">${sanitizeHtmlInput(type)}</span></div></td>` +
            `<td><strong>${issueName}</strong></td>` +
            `<td>${descParts.join('')}</td>` +
            `<td><div class="file">${sanitizeHtmlInput(filePath)}</div>${line ? `<div class="line">Line ${sanitizeHtmlInput(line)}</div>` : ''}</td>` +
            `<td class="meta-col">${metaHtml}</td>` +
            `</tr>`
        );
    }).join('\n    ');

    const emptyRow = '<tr><td colspan="5" class="empty">No findings.</td></tr>';

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cycode Scan Report</title>
<style>
  :root{--bg:#f7f8fa;--fg:#212121;--muted:#546e7a;--card:#fff;--border:#e0e3e7}
  *{box-sizing:border-box}
  body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:14px;line-height:1.45}
  h1{margin:0 0 8px;font-size:22px}
  .meta{color:var(--muted);margin-bottom:20px}
  .summary-grid{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
  .summary-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;min-width:110px}
  .summary-card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  .summary-card .value{font-size:22px;font-weight:600;margin-top:2px}
  .controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
  .controls input,.controls select{padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;background:#fff}
  .controls input{flex:1;min-width:200px}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
  thead th{text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);background:#eceff1;border-bottom:1px solid var(--border)}
  tbody td{padding:12px;vertical-align:top;border-bottom:1px solid var(--border)}
  tbody tr:last-child td{border-bottom:none}
  tbody tr.hidden{display:none}
  .sev{display:inline-block;padding:2px 10px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
  .type-badge{display:inline-block;padding:2px 8px;border-radius:4px;background:#eceff1;color:#37474f;font-size:11px;font-weight:500}
  .file{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-all}
  .line{color:var(--muted)}
  .meta-col{color:var(--muted);font-size:12.5px}
  details{margin-top:6px}
  details summary{cursor:pointer;color:#1565c0;font-size:12.5px;user-select:none;list-style:none}
  details summary::-webkit-details-marker{display:none}
  details summary::before{content:"▸ ";color:#1565c0}
  details[open] summary::before{content:"▾ "}
  details .content{margin-top:6px;padding:10px 12px;background:#fafbfc;border-left:3px solid #1565c0;border-radius:4px;font-size:13px;white-space:pre-wrap}
  .empty{text-align:center;padding:40px;color:var(--muted)}
</style>
</head>
<body>
<h1>Cycode Security Scan Results</h1>
<div class="meta">
  Scan path: <code>${sanitizeHtmlInput(scanPath)}</code> &middot;
  Scan type(s): <strong>${sanitizeHtmlInput(scanType)}</strong>
</div>

<div class="summary-grid">
  ${summaryCards}
</div>

<div class="controls">
  <input id="search" type="search" placeholder="Filter by file, issue name, description, CWE…">
  <select id="severity-filter">
    <option value="">All severities</option>
    ${severityOptions}
  </select>
  <select id="type-filter">
    <option value="">All types</option>
    ${typeOptions}
  </select>
  <span id="shown-count" style="color:var(--muted);font-size:12px"></span>
</div>

<table id="findings">
  <thead>
    <tr>
      <th style="width:110px">Severity</th>
      <th>Issue Name</th>
      <th>Description &amp; Mitigation</th>
      <th style="width:270px">File &amp; Line</th>
      <th style="width:220px">Metadata</th>
    </tr>
  </thead>
  <tbody>
    ${rows || emptyRow}
  </tbody>
</table>

<script>
(function(){
  var rows=document.querySelectorAll('#findings tbody tr');
  var search=document.getElementById('search');
  var sevFilter=document.getElementById('severity-filter');
  var typeFilter=document.getElementById('type-filter');
  var shownCount=document.getElementById('shown-count');
  function apply(){
    var q=search.value.trim().toLowerCase();
    var sev=sevFilter.value;
    var typ=typeFilter.value;
    var shown=0;
    rows.forEach(function(tr){
      var match=
        (!q||( tr.getAttribute('data-search')||'').indexOf(q)!==-1)&&
        (!sev||(tr.getAttribute('data-severity')||'')===sev)&&
        (!typ||(tr.getAttribute('data-type')||'')===typ);
      tr.classList.toggle('hidden',!match);
      if(match)shown++;
    });
    shownCount.textContent='Showing '+shown+' of '+rows.length;
  }
  search.addEventListener('input',apply);
  sevFilter.addEventListener('change',apply);
  typeFilter.addEventListener('change',apply);
  apply();
})();
</script>
</body>
</html>`;
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

        const scanTypes    = parseScanTypes(tl.getInput('scanType') || 'all');
        const verboseFlag  = verbose ? ' -v' : '';
        const extraStr     = extraFlags ? ` ${extraFlags}` : '';
        const quotedPath   = `"${scanPath.replace(/"/g, '\\"')}"`;

        const credentials: Record<string, string> = {
            CYCODE_CLIENT_ID:     clientId,
            CYCODE_CLIENT_SECRET: clientSecret,
        };

        const tempDir = tl.getVariable('Agent.TempDirectory') ?? __dirname;

        const allDetections: Detection[] = [];
        const failedTypes: string[] = [];

        for (const type of scanTypes) {
            console.log(`\nStarting ${type} scan...`);
            const scanCmd = `${cycodeExe}${verboseFlag} --no-progress-meter --no-update-notifier -o json scan --soft-fail -t ${type}${extraStr} path ${quotedPath}`;
            console.log(`Running: ${scanCmd}`);

            let rawData: ScanOutput | Detection[];
            try {
                const scanOutput = runScan(scanCmd, credentials);
                // Slice from the first { or [ to tolerate stray text before the JSON blob
                const jsonStart = scanOutput.search(/[{[]/);
                if (jsonStart === -1) throw new Error('no JSON found in output');
                rawData = JSON.parse(scanOutput.slice(jsonStart));
            } catch (err: any) {
                console.log(`Warning: ${type} scan failed — ${err.message}`);
                failedTypes.push(type);
                continue;
            }

            // Upload per-type raw JSON artifact
            const jsonFile = path.join(tempDir, `cycode_results_${type}.json`);
            fs.writeFileSync(jsonFile, JSON.stringify(rawData, null, 2));
            tl.uploadArtifact('Cycode', jsonFile, 'Cycode Scan Results');

            const typeDetections = extractDetections(rawData);
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
        fs.writeFileSync(reportFile, generateHtmlReport(allDetections, scanPath, scanTypes.join(', ')));
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

run();
