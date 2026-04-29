'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJson(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 4) + '\n');
}

const ext = readJson(path.join(ROOT, 'vss-extension.json'));
const [major, minor, patch] = ext.version.split('.').map(Number);

const args = process.argv.slice(2);
let newMajor = major, newMinor = minor, newPatch = patch;

if (args.includes('--major')) {
    newMajor += 1; newMinor = 0; newPatch = 0;
} else if (args.includes('--minor')) {
    newMinor += 1; newPatch = 0;
} else {
    newPatch += 1;
}

const newVersion = `${newMajor}.${newMinor}.${newPatch}`;
console.log(`Bumping version: ${major}.${minor}.${patch} → ${newVersion}`);

const semverFiles = [
    'vss-extension.json',
    'package.json',
    'cycodescan/package.json',
    'cycodeapigate/package.json',
];

for (const rel of semverFiles) {
    const file = path.join(ROOT, rel);
    const data = readJson(file);
    data.version = newVersion;
    writeJson(file, data);
    console.log(`  updated ${rel}`);
}

const taskFiles = [
    'cycodescan/task.json',
    'cycodeapigate/task.json',
];

for (const rel of taskFiles) {
    const file = path.join(ROOT, rel);
    const data = readJson(file);
    data.version = { Major: newMajor, Minor: newMinor, Patch: newPatch };
    writeJson(file, data);
    console.log(`  updated ${rel}`);
}

console.log(`\nDone. New version: ${newVersion}`);
