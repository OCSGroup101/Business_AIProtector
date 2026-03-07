# OpenClaw Rule Development Kit

Validate, test, and publish detection rules for OpenClaw.

## Installation

```bash
pip install openclaw-rdk
# or run from source:
pip install -e .
```

## Quick Start

```bash
# Validate a rule file
oclaw-rdk validate rules/my-rule.toml

# Run a rule against a test event
oclaw-rdk test rules/my-rule.toml --event tests/events/process-create.json

# Run the full test suite for a rule pack
oclaw-rdk test-pack rule-packs/openclaw-core-v1/

# Check false positive rate against a dataset
oclaw-rdk fp-check rules/my-rule.toml --dataset datasets/benign-events.ndjson

# Sign a rule pack (requires minisign key)
oclaw-rdk sign rule-packs/openclaw-core-v1/ --key-file signing.key
```

## Rule Schema

See [../../docs/architecture/rule-schema.md](../../docs/architecture/rule-schema.md).

## Test Event Format

Test events follow the TelemetryEvent schema:

```json
{
  "schema_version": "1.0",
  "event_type": "process.create",
  "collector": "process",
  "payload": {
    "process_name": "powershell.exe",
    "parent_name": "winword.exe",
    "cmdline": "powershell.exe -enc BASE64==",
    "pid": 1234,
    "ppid": 5678
  }
}
```

## False Positive Requirements

Rules submitted to `openclaw-core-v1` must achieve:
- <0.1% false positive rate against the benign event dataset
- <1ms average evaluation time

Run `oclaw-rdk fp-check` to verify before submitting.
