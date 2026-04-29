import * as tl from 'azure-pipelines-task-lib/task';
import * as https from 'https';
import * as http from 'http';

// ---------------------------------------------------------------------------
// HTTP helper — uses Node built-ins; no extra dependencies needed
// ---------------------------------------------------------------------------

function httpPost(url: string, body: object, extraHeaders: Record<string, string> = {}): Promise<unknown> {
    return new Promise((resolve, reject) => {
        const parsedUrl  = new URL(url);
        const payload    = JSON.stringify(body);
        const options: https.RequestOptions = {
            hostname: parsedUrl.hostname,
            port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
            path:     parsedUrl.pathname + parsedUrl.search,
            method:   'POST',
            headers:  {
                'Content-Type':   'application/json',
                'Content-Length': Buffer.byteLength(payload),
                ...extraHeaders,
            },
        };

        const client = parsedUrl.protocol === 'https:' ? https : http;
        const req = client.request(options, res => {
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => chunks.push(chunk));
            res.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                if (res.statusCode && res.statusCode >= 400) {
                    reject(new Error(`HTTP ${res.statusCode}: ${text.slice(0, 300)}`));
                    return;
                }
                try   { resolve(JSON.parse(text)); }
                catch { resolve(text); }
            });
        });

        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

// ---------------------------------------------------------------------------
// Severity helpers — same ordering as the scan task
// ---------------------------------------------------------------------------

// Most severe first; slice(0, n) gives "at n and above"
const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

function normalizeSeverity(raw: string): string {
    const s = raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase();
    return SEVERITY_ORDER.includes(s) ? s : raw;
}

// Return all severities at or above minSev (most-severe first)
function severitiesAtOrAbove(minSev: string): string[] {
    const idx = SEVERITY_ORDER.indexOf(normalizeSeverity(minSev));
    return idx === -1 ? SEVERITY_ORDER : SEVERITY_ORDER.slice(0, idx + 1);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run(): Promise<void> {
    try {
        const clientId     = tl.getInput('CycodeClientID', true)!;
        const clientSecret = tl.getInput('CycodeClientSecret', true)!;
        const repoName     = tl.getInput('repoName', true)!;
        const apiUrl       = (tl.getInput('apiUrl') || 'https://api.cycode.com').replace(/\/$/, '');
        const severityMin  = tl.getInput('severityMin') || '';
        const category     = tl.getInput('category') || '';
        const riskScoreMin = tl.getInput('riskScoreMin') || '';
        const breakPipeline = tl.getBoolInput('breakPipeline', false);

        console.log(`Cycode API Gate — checking Open violations for repository: "${repoName}"`);
        if (severityMin)  console.log(`  Severity filter : ${severityMin} and above`);
        if (category)     console.log(`  Category filter : ${category}`);
        if (riskScoreMin) console.log(`  Risk score min  : ${riskScoreMin}`);

        // -----------------------------------------------------------------------
        // Step 1: Authenticate
        // -----------------------------------------------------------------------
        console.log('\nAuthenticating with Cycode API...');
        let authResp: Record<string, unknown>;
        try {
            authResp = (await httpPost(`${apiUrl}/api/v1/auth/api-token`, {
                clientId: clientId,
                secret:   clientSecret,
            })) as Record<string, unknown>;
        } catch (err: any) {
            tl.setResult(tl.TaskResult.Failed, `Authentication request failed: ${err.message}`);
            return;
        }

        const token = authResp?.token as string | undefined;
        if (!token) {
            tl.setResult(
                tl.TaskResult.Failed,
                `Cycode authentication returned no token. ` +
                `Response: ${JSON.stringify(authResp).slice(0, 300)}`
            );
            return;
        }

        // -----------------------------------------------------------------------
        // Step 2: Build RIG filter array  (mirrors cycode-gate.sh logic)
        // -----------------------------------------------------------------------
        const filters: object[] = [
            { name: 'status',                              operator: 'Eq',  value: 'Open',    type: 'String' },
            { name: 'detection_details.repository_name',  operator: 'Eq',  value: repoName,  type: 'String' },
        ];

        if (severityMin) {
            const sevs = severitiesAtOrAbove(severityMin);
            filters.push({ name: 'severity', operator: 'In', value: sevs.join(','), type: 'String' });
        }
        if (category) {
            filters.push({ name: 'category', operator: 'Eq', value: category, type: 'String' });
        }
        if (riskScoreMin) {
            filters.push({ name: 'risk_score', operator: 'Gte', value: riskScoreMin, type: 'Numeric' });
        }

        const rigBody = {
            resource_type:  'detection',
            filters:        [{ mode: 'And', filters }],
            sort_by:        'risk_score',
            sort_order:     'desc',
            limit:          -1,
            fast_query:     true,
            connections:    [],
            exists:         true,
            is_optional:    false,
            edge_type:      '',
            variables:      [],
            edge_filters:   [],
            edge_columns:   [],
            parent_resource_type:              '',
            optional_connections_minimum_count: 0,
        };

        // -----------------------------------------------------------------------
        // Step 3: Query Risk Intelligence Graph
        // -----------------------------------------------------------------------
        console.log('Querying Cycode Risk Intelligence Graph...');
        let rigResp: Record<string, unknown>;
        try {
            rigResp = (await httpPost(
                `${apiUrl}/graph/api/v1/graph/query?mode=AlertWhen&page_number=0&page_size=200`,
                rigBody,
                { Authorization: `Bearer ${token}` }
            )) as Record<string, unknown>;
        } catch (err: any) {
            tl.setResult(tl.TaskResult.Failed, `RIG query failed: ${err.message}`);
            return;
        }

        if (!Array.isArray(rigResp?.result)) {
            tl.setResult(
                tl.TaskResult.Failed,
                `Unexpected API response — missing 'result' array. ` +
                `Response: ${JSON.stringify(rigResp).slice(0, 500)}`
            );
            return;
        }

        // -----------------------------------------------------------------------
        // Step 4: Evaluate results
        // -----------------------------------------------------------------------
        const results = rigResp.result as Record<string, unknown>[];
        const count   = results.length;
        const hasMore = rigResp.fast_query_has_more === true;
        const countLabel = hasMore ? `at least ${count} (page cap reached — 200 result limit)` : String(count);

        console.log(`\nOpen violations matching filters for "${repoName}": ${countLabel}`);

        if (count > 0) {
            console.log('\nTop findings (up to 20):');
            for (const item of results.slice(0, 20)) {
                const r = (item.resource ?? item) as Record<string, unknown>;
                const dd  = (r.detection_details ?? {}) as Record<string, unknown>;
                const sev  = String(r.severity  ?? '-');
                const risk = String(r.risk_score ?? '-');
                const policy = String(r.source_policy_name ?? '-');
                const loc    = String(dd.file_path ?? dd.package_name ?? r.source_entity_name ?? '-');
                const line   = dd.line ? `:${dd.line}` : '';
                console.log(`  [${sev} / risk ${risk}] ${policy} — ${loc}${line}`);
            }

            if (breakPipeline) {
                tl.setResult(
                    tl.TaskResult.Failed,
                    `Cycode API gate failed: ${countLabel} Open violation(s) found for repository "${repoName}".`
                );
            } else {
                console.log(
                    `\nCycode API gate: ${countLabel} violation(s) found. ` +
                    `Break pipeline is disabled — pipeline will continue.`
                );
            }
        } else {
            console.log(`\nCycode API gate passed — no Open violations matched the filters for "${repoName}".`);
        }
    } catch (err: any) {
        tl.setResult(tl.TaskResult.Failed, err.message);
    }
}

run();
