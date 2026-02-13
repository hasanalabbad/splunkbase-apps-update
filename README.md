# Splunkbase Apps update

A command-line tool to automate checking for updates and upgrading [Splunkbase](https://splunkbase.splunk.com/) apps on [Splunk Cloud](https://www.splunk.com/en_us/products/splunk-cloud-platform.html) using the [Admin Config Service (ACS) API](https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ACSAPI).

## Overview

Managing Splunkbase apps across a Splunk Cloud deployment can be tedious when done manually. This tool automates the process with a two-phase workflow:

1. **Check for updates** -- Queries your Splunk Cloud stack for all installed Splunkbase apps, checks the Splunkbase API for newer versions, validates compatibility, and exports results to a JSON file.
2. **Upgrade apps** -- Reads the JSON file, authenticates with Splunkbase, and upgrades each compatible app via the ACS API, with automatic backup of the current version before upgrading.

## How It Works

### Architecture

```
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│  Splunk Cloud     │       │  Splunkbase API   │       │  ACS API         │
│  (your stack)     │       │  (public)         │       │  (admin.splunk)  │
└────────┬─────────┘       └────────┬──────────┘       └────────┬─────────┘
         │                          │                           │
         │  GET installed apps      │                           │
         │◄─────────────────────────┼───────────────────────────┤
         │                          │                           │
         │                          │  GET releases per app     │
         │                          │◄──────────────────────────┤
         │                          │                           │
         │                          │  GET license URL          │
         │                          │◄──────────────────────────┤
         │                          │                           │
         │  PATCH upgrade app       │                           │
         │◄─────────────────────────┼───────────────────────────┤
         │                          │                           │
```

### Phase 1: Check Updates (`--check-updates`)

1. **Fetch installed apps** -- Calls the ACS API (`/apps/victoria`) to list all Splunkbase apps currently installed on your stack.
2. **Query Splunkbase for releases** -- For each installed app, queries the Splunkbase API for all available release versions.
3. **Filter newer versions** -- Compares installed versions against available releases and identifies apps with newer versions.
4. **Validate compatibility** -- For each newer release, checks:
   - **CIM version compatibility** -- Does the release support the CIM version installed on your stack?
   - **Splunk version compatibility** -- Does the release support your Splunk Cloud version?
   - **Cloud compatibility** -- Is the release marked as cloud-compatible?
   - **No restart required** -- Does the app require a restart to change state? (Apps requiring restart are skipped in normal mode.)
5. **Export to JSON** -- Writes the full app inventory with update/compatibility data to `splunkbase_apps.json`.

### Phase 2: Upgrade Apps (`--upgrade-apps`)

1. **Load JSON** -- Reads the previously exported JSON file containing the app inventory and update information.
2. **Authenticate** -- Obtains a Splunkbase authentication token using your Splunk credentials (needed for downloading app packages).
3. **For each app with `update_available: true`**:
   - Checks if the app is in the exclusion list (skips if so).
   - Validates compatibility (unless `--force` is used).
   - **Backs up** the currently installed version by exporting the app package as a `.tar.gz` file to the artifacts directory.
   - **Upgrades** the app via the ACS API (`PATCH /apps/victoria/{appID}`).
   - **Polls** the installation status until the app reports `installed` or a 5-minute timeout is reached.

### Compatibility Checks

An app release is considered compatible for upgrade when **all** of the following are true:

| Check | Description |
|-------|-------------|
| CIM version | The release supports the CIM version currently installed on the stack |
| Splunk version | The release supports the Splunk Cloud version running on the stack |
| Cloud compatible | The release is flagged as cloud-compatible on Splunkbase |
| No restart required | The app's `stateChangeRequiresRestart` is `false` |

Use `--force` to bypass all compatibility checks (use with caution).

## Prerequisites

- **Python 3.10+**
- **Splunk Cloud** with ACS API access enabled
- **Splunk ACS API token** (JWT) with permissions to manage apps
- **Splunk account credentials** (username/password for Splunkbase authentication, used during upgrades)

## Installation

```bash
git clone https://github.com/hasanalabbad/splunkbase-apps-update.git
cd splunkbase-apps-update
pip install -r requirements.txt
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SPLUNK_API_TOKEN` | Yes | Splunk Cloud ACS API token (JWT) |
| `SPLUNK_STACK` | Yes | Your Splunk Cloud stack name (e.g., `mycompany`) |
| `SPLUNK_USER` | For upgrades | Splunk account username (for Splunkbase authentication) |
| `SPLUNK_PASS` | For upgrades | Splunk account password (for Splunkbase authentication) |

```bash
export SPLUNK_API_TOKEN="your-acs-api-token"
export SPLUNK_STACK="your-stack-name"
export SPLUNK_USER="your-splunk-username"
export SPLUNK_PASS="your-splunk-password"
```

### Exclusion List (`config.yml`)

To prevent specific apps from being automatically upgraded, add them to `config.yml`:

```yaml
excluded_apps:
  - splunkbase_id: "1621"
    reason: "Manual upgrade required - critical dependency"
    excluded_date: "2025-01-15"

  - splunkbase_id: "3435"
    reason: "Testing compatibility first"
    excluded_date: "2025-02-01"
```

## Usage

```bash
python splunkbase_apps.py [ACTION] [OPTIONS]
```

### Actions

| Flag | Description |
|------|-------------|
| `--check-updates` | Check for app updates and export results to JSON |
| `--upgrade-apps <JSON_FILE>` | Upgrade apps from the specified JSON file |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--force` | Bypass compatibility checks and upgrade to the latest version | `false` |
| `--output-dir <DIR>` | Output directory for JSON export and app backups | `artifacts` |
| `--config-file <FILE>` | Path to config file for exclusion list | `config.yml` |

### Examples

```bash
# Check for available updates and export results
python splunkbase_apps.py --check-updates

# Check updates with a custom output directory
python splunkbase_apps.py --check-updates --output-dir /tmp/exports

# Upgrade apps from the exported JSON file
python splunkbase_apps.py --upgrade-apps artifacts/splunkbase_apps.json

# Force upgrade (bypass all compatibility checks)
python splunkbase_apps.py --upgrade-apps artifacts/splunkbase_apps.json --force

# Use a custom config file for the exclusion list
python splunkbase_apps.py --upgrade-apps artifacts/splunkbase_apps.json --config-file my_config.yml
```

## JSON File Format

The exported `splunkbase_apps.json` file has the following structure (see `example_apps.json` for a full example):

```json
{
  "stack": "your-stack-name",
  "total_apps": 24,
  "apps": [
    {
      "appID": "Splunk_SA_CIM",
      "label": "Splunk Common Information Model",
      "splunkbaseID": "1621",
      "stateChangeRequiresRestart": false,
      "status": "installed",
      "version": "6.3.0",
      "update_available": false,
      "available_versions": []
    }
  ]
}
```

Each app in the `apps` array contains:

| Field | Description |
|-------|-------------|
| `appID` | The app identifier on your Splunk Cloud stack |
| `label` | Human-readable app name |
| `splunkbaseID` | Numeric Splunkbase catalog ID |
| `version` | Currently installed version |
| `update_available` | `true` if a newer version exists |
| `available_versions` | List of newer releases with compatibility metadata |
| `stateChangeRequiresRestart` | Whether changing the app state requires a stack restart |

## Files

| File | Description |
|------|-------------|
| `splunkbase_apps.py` | Main Python script |
| `config.yml` | Exclusion list and configuration |
| `requirements.txt` | Python dependencies |
| `example_apps.json` | Example JSON output showing the data format |

## CI/CD Integration

This tool is designed to fit into a two-stage CI/CD pipeline:

### Stage 1: Scheduled Check

Run `--check-updates` on a schedule (e.g., weekly or monthly). Review the generated JSON and commit it to version control via a pull/merge request for team review.

### Stage 2: Triggered Upgrade

After the JSON is reviewed and merged, trigger `--upgrade-apps` with the committed JSON file. The tool will back up each app before upgrading and log all actions.

Example pipeline pseudocode:

```yaml
# Stage 1: Check for updates (scheduled)
check-updates:
  schedule: "0 0 1 */3 *"  # Every 3 months
  script:
    - python splunkbase_apps.py --check-updates
    - # commit and open PR with the updated JSON

# Stage 2: Upgrade apps (triggered on merge)
upgrade-apps:
  trigger:
    - changes to splunkbase_apps.json on main branch
  script:
    - python splunkbase_apps.py --upgrade-apps splunkbase_apps.json
```

## Known Bugs

- **ACS API does not return all installed Splunkbase apps** -- The ACS Splunk Cloud endpoint (`GET /apps/victoria?splunkbase=true`) used to list installed apps does not always return the complete set of Splunkbase apps. Some apps may be missing from the response, which means updates for those apps will not be detected or managed by this tool.

## License

This project is released under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
