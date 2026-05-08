# Cycode Security Scan — Azure DevOps Extension

Integrate [Cycode](https://cycode.com) security scanning into your Azure Pipelines with two pipeline tasks and a dedicated build results tab.

---

## Tasks

### Cycode Security Scan (`cycodescan`)

Runs the Cycode CLI on your repository and publishes an interactive HTML report as a new **Cycode Scan Results** tab in the build results view.

**Features:**
- Installs the Cycode CLI automatically if not present (requires Python 3 + pip on the agent)
- Supports all scan types: **SAST**, **SCA**, **Secrets**, and **IaC** — individually or all at once
- Two scan modes: **full path scan** (default) or **commit history scan** (changes since the previous commit)
- Rich, filterable HTML report attached directly to the build
- Configurable severity threshold for pipeline gating
- Works on Linux and Windows hosted/self-hosted agents

**Example usage — full path scan:**

```yaml
- task: cycodescan@0
  displayName: 'Cycode Security Scan'
  inputs:
    CycodeClientID: $(CycodeClientID)
    CycodeClientSecret: $(CycodeClientSecret)
    scanPath: $(Build.SourcesDirectory)
    scanType: sast
    severityThreshold: High
    breakPipeline: true
```

**Example usage — commit history scan (faster, incremental):**

```yaml
steps:
  - checkout: self
    fetchDepth: 2   # required — provides the previous commit for diff scanning

  - task: cycodescan@0
    displayName: 'Cycode Security Scan'
    inputs:
      CycodeClientID: $(CycodeClientID)
      CycodeClientSecret: $(CycodeClientSecret)
      scanPath: $(Build.SourcesDirectory)
      scanType: all
      scanMode: commitHistory
      severityThreshold: High
      breakPipeline: true
```

> `fetchDepth: 2` is required for `commitHistory` mode. Without it, the agent checks out only the latest commit and the task cannot resolve a previous commit to diff against. If the previous commit is unavailable, the task falls back to a full path scan automatically.

---

### Cycode API Gate (`cycodeapigate`)

Queries the Cycode **Risk Intelligence Graph (RIG)** for Open violations already triaged on the platform and fails the pipeline if any match. No CLI installation required — uses the Cycode REST API directly.

**Features:**
- Filters by severity, scan category, and minimum risk score
- Outputs the top 20 matching violations to the build log
- Detects when the result set exceeds the 200-item page cap

**Example usage:**

```yaml
- task: cycodeapigate@0
  displayName: 'Cycode API Gate'
  inputs:
    CycodeClientID: $(CycodeClientID)
    CycodeClientSecret: $(CycodeClientSecret)
    repoName: my-service
    severityMin: High
    category: SAST
    breakPipeline: true
```

---

## Credentials

Both tasks require a Cycode **API Client ID** and **Client Secret**. Generate these in the Cycode Console under **Settings → API Tokens**. Store them as secret pipeline variables — they are passed as environment variables and never appear in logs.

---

## Requirements

| Task | Agent requirement |
|------|------------------|
| `cycodescan` | Python 3 + pip (auto-installs Cycode CLI if missing) |
| `cycodeapigate` | None (uses built-in HTTPS) |

Both tasks support **Node 22** execution on Azure Pipelines hosted agents (Ubuntu, Windows, macOS).
