import * as fs from 'fs';
import * as path from 'path';
import { extractDetections, generateHtmlReport } from './index';

const JSON_DIR  = path.resolve(__dirname, '..', '..', 'json_examples');
const OUT_FILE  = path.resolve(__dirname, '..', '..', 'test-report.html');
const SCAN_PATH = '/home/vsts/work/1/s';

const BUILD_INFO = {
    repo:    'NodeGoat',
    branch:  'master',
    commit:  'cfbb0b9abc1234567890',
    org:     'aaronbutlercy',
    project: 'Goats',
};

const files = fs.readdirSync(JSON_DIR).filter(f =>
    f.endsWith('.json') && fs.statSync(path.join(JSON_DIR, f)).isFile()
);

const allDetections: ReturnType<typeof extractDetections> = [];
const scanTypes: string[] = [];

// Map filename suffix to CLI scan type (e.g. 'secrets' → 'secret', 'iac' → 'iac')
const FILENAME_TO_SCAN_TYPE: Record<string, string> = {
    sast:    'sast',
    sca:     'sca',
    secret:  'secret',
    secrets: 'secret',
    iac:     'iac',
};

for (const file of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(JSON_DIR, file), 'utf8'));
    const m = file.match(/cycode_results_(.+)\.json$/i);
    const suffix = m?.[1].toLowerCase() ?? '';
    const scanType = FILENAME_TO_SCAN_TYPE[suffix] ?? suffix;
    const detections = extractDetections(raw).map(d => ({ ...d, _scanType: scanType }));
    console.log(`${file}: ${detections.length} detection(s) [_scanType=${scanType}]`);
    allDetections.push(...detections);
    if (scanType) scanTypes.push(scanType);
}

console.log(`\nTotal: ${allDetections.length} detections across ${files.length} file(s)`);

const html = generateHtmlReport(allDetections, SCAN_PATH, scanTypes.join(', '), BUILD_INFO);
fs.writeFileSync(OUT_FILE, html);
console.log(`\nReport written to: ${OUT_FILE}`);
