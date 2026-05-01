# ADO Cycode Security Scan Plugin

Azure DevOps extension that integrates [Cycode](https://cycode.com) security scanning into Azure Pipelines.

## Contents

```
ADO-Cycode-Plugin/
├── cycodescan/               # Task: run Cycode CLI scan + attach HTML report
│   ├── index.ts              # Main task logic
│   ├── task.json             # Task manifest
│   ├── package.json
│   └── tsconfig.json
├── cycodeapigate/            # Task: query Cycode RIG API for open violations
│   ├── index.ts
│   ├── task.json
│   ├── package.json
│   └── tsconfig.json
├── src/resultsDisplay/
│   └── resultsTab.ts         # UI tab that renders the HTML report in build results
├── .github/workflows/
│   └── build.yml             # CI: compile + package on push/PR
├── scripts/
│   └── increment-version.js  # Bumps version across all manifests
├── images/
│   └── cycode-logo.png       # Publisher icon
├── index.html                # Entry point for the build results tab
├── overview.md               # Marketplace listing content
├── vss-extension.json        # Extension manifest
├── webpack.config.js         # Bundles the UI tab for the extension
├── package.json              # Root build/package scripts
└── tsconfig.json             # TypeScript config for the UI tab (bundled by webpack)
```

## Prerequisites

- **Node.js 22+** and **npm**
- **Python 3 + pip** on any agent running `cycodescan` (the task auto-installs the Cycode CLI if missing)
- **tfx-cli** (installed as a dev dependency via root `npm install`)
- A Cycode **API Client ID** and **Client Secret** from the Cycode Console

## Setup

1. **Install dependencies:**

   ```bash
   npm install --prefix cycodescan
   npm install --prefix cycodeapigate
   npm install
   ```

2. **Compile and package:**

   ```bash
   npm run build
   ```

   `npm run build` compiles both tasks (`cycodescan/out/` and `cycodeapigate/out/`), runs webpack to bundle the UI tab (`dist/resultsTab.js`), and packages everything into a `.vsix` file in `builds/`.

   Individual steps are also available:

   ```bash
   npm run build:tasks   # compile task TypeScript only
   npm run build:ui      # webpack bundle only
   npm run package       # package to .vsix only
   ```

3. **Publish to the marketplace** (requires a PAT with Marketplace publish scope):

   ```bash
   npx tfx extension publish --manifest-globs vss-extension.json \
     --token <your-PAT>
   ```

   To share a private build with a specific organisation without publishing publicly:

   ```bash
   npx tfx extension publish --manifest-globs vss-extension.json \
     --token <your-PAT> \
     --share-with <your-org>
   ```

## Local testing

### HTML report preview — no ADO required

The fastest way to inspect report changes is to generate an HTML report from the sample JSON files in `json_examples/` and open it in a browser.

```bash
cd cycodescan
npm install
npm run test-report
```

This compiles the task TypeScript, reads all four files in `json_examples/` (`cycode_results_sast.json`, `cycode_results_sca.json`, `cycode_results_secret.json`, `cycode_results_iac.json`), generates a combined report, and writes it to `test-report.html` at the repo root.

Open the result:

```bash
open ../test-report.html        # macOS
start ../test-report.html       # Windows
xdg-open ../test-report.html    # Linux
```

To add or replace sample data, drop a `cycode_results_<type>.json` file into `json_examples/` and re-run `npm run test-report`. The script picks up every `*.json` file in that directory automatically.

### Quick smoke test — no ADO required

`azure-pipelines-task-lib` reads task inputs from `INPUT_<NAME>` environment variables. Compile the task and run it directly:

```bash
cd cycodescan
npm install && npm run build

export INPUT_CYCODECLIENTID=your-client-id
export INPUT_CYCODECLIENTSECRET=your-client-secret
export INPUT_SCANPATH=$(pwd)
export INPUT_SCANTYPE=sast
export INPUT_SEVERITYTHRESHOLD=High
export INPUT_BREAKPIPELINE=false
export AGENT_TEMPDIRECTORY=/tmp
export BUILD_SOURCESDIRECTORY=$(pwd)

node out/index.js
```

The same pattern applies to `cycodeapigate` — set `INPUT_REPONAME`, `INPUT_SEVERITYMIN`, etc.

### Unit tests — `azure-pipelines-task-lib/mock-run`

The official Microsoft approach. Create a test file per task:

```typescript
import * as tmrm from 'azure-pipelines-task-lib/mock-run';
import * as ma from 'azure-pipelines-task-lib/mock-answer';
import * as path from 'path';

const taskPath = path.join(__dirname, '..', 'out', 'index.js');
const tmr = new tmrm.TaskMockRunner(taskPath);

tmr.setInput('CycodeClientID', 'test-id');
tmr.setInput('CycodeClientSecret', 'test-secret');
tmr.setInput('scanPath', '/tmp/repo');
tmr.setInput('scanType', 'sast');
tmr.setInput('severityThreshold', 'High');
tmr.setInput('breakPipeline', 'false');

tmr.setAnswers({
    exec: {
        'cycode --version': { code: 0, stdout: '1.0.0' },
        'cycode scan path --output-format json /tmp/repo': {
            code: 1,
            stdout: JSON.stringify({ detections: [] })
        }
    }
} as ma.TaskLibAnswers);

tmr.run();
```

Run with:

```bash
npx tsc && node _tests/cycodescan.test.js
```

### End-to-end — private Azure DevOps organisation

The only way to test the UI results tab and full pipeline integration. Setup is free:

1. Create an org at `dev.azure.com`
2. Get a PAT with **Marketplace (publish)** scope
3. Build and publish privately:

   ```bash
   npm install --prefix cycodescan
   npm install --prefix cycodeapigate
   npm install
   npm run build
   npx tfx extension publish --manifest-globs vss-extension.json \
     --token <PAT> --share-with <your-org>
   ```

4. Install the extension in your org, create a pipeline, and run it

> Bump the patch version before each re-publish — ADO rejects duplicate versions.

## Pipeline usage

### Cycode Security Scan

```yaml
variables:
  CycodeClientID: $(CycodeClientID)         # secret variable
  CycodeClientSecret: $(CycodeClientSecret) # secret variable

steps:
  - task: cycodescan@0
    displayName: 'Cycode Security Scan'
    inputs:
      CycodeClientID: $(CycodeClientID)
      CycodeClientSecret: $(CycodeClientSecret)
      scanPath: $(Build.SourcesDirectory)
      scanType: all              # all | sast | sca | secret | iac
      severityThreshold: Medium  # Info | Low | Medium | High | Critical
      breakPipeline: true
```

### Cycode API Gate

```yaml
  - task: cycodeapigate@0
    displayName: 'Cycode API Gate'
    inputs:
      CycodeClientID: $(CycodeClientID)
      CycodeClientSecret: $(CycodeClientSecret)
      repoName: my-service       # bare repo name as shown in Cycode Violations UI
      severityMin: High          # optional: Info | Low | Medium | High | Critical
      category: SAST             # optional: SAST | SCA | Secrets | IaC | ContainerScanning
      riskScoreMin: '70'         # optional: 0–100
      breakPipeline: true
```

### Combined pattern (scan then gate)

```yaml
steps:
  - task: cycodescan@0
    displayName: 'Run Cycode Scan'
    inputs:
      CycodeClientID: $(CycodeClientID)
      CycodeClientSecret: $(CycodeClientSecret)
      scanType: all
      breakPipeline: false       # don't break here — let the API gate decide

  - task: cycodeapigate@0
    displayName: 'Cycode API Gate (triaged violations)'
    inputs:
      CycodeClientID: $(CycodeClientID)
      CycodeClientSecret: $(CycodeClientSecret)
      repoName: $(Build.Repository.Name)
      severityMin: High
      breakPipeline: true
```

## Task IDs

| Task | UUID |
|------|------|
| `cycodescan` | `3f7b8c9d-1e2f-4a5b-9c8d-7e6f5a4b3c2d` |
| `cycodeapigate` | `4a8c9d0e-2f3a-5b6c-ad9e-8f7a6b5c4d3e` |

> **Note:** Task IDs must not change after initial publication. If you fork this repo, generate fresh UUIDs before first publish.

## Version bumping

Run the version bump script before publishing — it updates all six manifests atomically:

```bash
npm run version:bump          # increment patch  (0.1.0 → 0.1.1)
npm run version:bump:minor    # increment minor  (0.1.0 → 0.2.0)
npm run version:bump:major    # increment major  (0.1.0 → 1.0.0)
```

Files updated by the script:

- `vss-extension.json`
- `package.json` (root)
- `cycodescan/task.json`
- `cycodescan/package.json`
- `cycodeapigate/task.json`
- `cycodeapigate/package.json`
