import * as fs from 'fs';
import * as path from 'path';
import { extractDetections, generateHtmlReport } from './index';

const JSON_DIR  = path.resolve(__dirname, '..', '..', 'json_examples');
const OUT_FILE  = path.resolve(__dirname, '..', '..', 'test-report.html');
const SCAN_PATH = '/home/vsts/work/1/s';

const BUILD_INFO = {
    repo:   'NodeGoat',
    branch: 'master',
    commit: 'cfbb0b9abc1234567890',
};

const files = fs.readdirSync(JSON_DIR).filter(f => f.endsWith('.json'));

const allDetections: ReturnType<typeof extractDetections> = [];
const scanTypes: string[] = [];

for (const file of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(JSON_DIR, file), 'utf8'));
    const detections = extractDetections(raw);
    console.log(`${file}: ${detections.length} detection(s)`);
    allDetections.push(...detections);

    // Derive scan type label from filename (e.g. cycode_results_sast.json → sast)
    const m = file.match(/cycode_results_(.+)\.json$/i);
    if (m) scanTypes.push(m[1]);
}

console.log(`\nTotal: ${allDetections.length} detections across ${files.length} file(s)`);

const html = generateHtmlReport(allDetections, SCAN_PATH, scanTypes.join(', '), BUILD_INFO);
fs.writeFileSync(OUT_FILE, html);
console.log(`\nReport written to: ${OUT_FILE}`);
