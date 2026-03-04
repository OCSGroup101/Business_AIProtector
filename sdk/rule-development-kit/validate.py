#!/usr/bin/env python3
"""
OpenClaw Rule Validator
Validates TOML detection rules against the rule schema.
"""

import sys
import tomllib
from pathlib import Path
from typing import Any

REQUIRED_RULE_FIELDS = {"id", "name", "enabled", "match", "response"}
VALID_MATCH_TYPES = {"ioc", "behavioral", "heuristic"}
VALID_OPERATORS = {"in", "eq", "contains", "starts_with", "ends_with", "in_ioc_set"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_AUTO_CONTAIN = {
    "terminate_process", "quarantine_file", "block_network",
    "disable_persistence", "isolate_host",
}


def validate_rule(rule: dict[str, Any], filename: str, rule_index: int) -> list[str]:
    """Validate a single rule dict. Returns list of error messages."""
    errors: list[str] = []
    prefix = f"{filename}[{rule_index}]"

    rule_id = rule.get("id", f"<unknown-{rule_index}>")

    # Required fields
    missing = REQUIRED_RULE_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"{prefix} Rule '{rule_id}': missing required fields: {missing}")

    # ID format
    if "id" in rule and not rule["id"].startswith(("OC-IOC-", "OC-BEH-", "OC-HEU-")):
        errors.append(f"{prefix} Rule ID '{rule['id']}' must start with OC-IOC-, OC-BEH-, or OC-HEU-")

    # Match block
    match = rule.get("match", {})
    if "type" in match:
        if match["type"] not in VALID_MATCH_TYPES:
            errors.append(f"{prefix} '{rule_id}': invalid match type '{match['type']}'")

        if match["type"] == "heuristic":
            if "lua_script" not in match or not match["lua_script"].strip():
                errors.append(f"{prefix} '{rule_id}': heuristic rule requires lua_script")
            if not match.get("window_seconds", 0):
                errors.append(f"{prefix} '{rule_id}': heuristic rule requires window_seconds > 0")
        else:
            if not match.get("conditions"):
                errors.append(f"{prefix} '{rule_id}': non-heuristic rule requires at least one condition")

        # Validate conditions
        for i, cond in enumerate(match.get("conditions", [])):
            if "field" not in cond:
                errors.append(f"{prefix} '{rule_id}' condition[{i}]: missing 'field'")
            if "operator" not in cond:
                errors.append(f"{prefix} '{rule_id}' condition[{i}]: missing 'operator'")
            elif cond["operator"] not in VALID_OPERATORS:
                errors.append(f"{prefix} '{rule_id}' condition[{i}]: invalid operator '{cond['operator']}'")
            if cond.get("operator") == "in_ioc_set" and "ioc_type" not in cond:
                errors.append(f"{prefix} '{rule_id}' condition[{i}]: in_ioc_set requires ioc_type")

    # Response block
    response = rule.get("response", {})
    if "severity" in response:
        if response["severity"] not in VALID_SEVERITIES:
            errors.append(f"{prefix} '{rule_id}': invalid severity '{response['severity']}'")
    else:
        errors.append(f"{prefix} '{rule_id}': response missing 'severity'")

    for action in response.get("auto_contain", []):
        if action not in VALID_AUTO_CONTAIN:
            errors.append(f"{prefix} '{rule_id}': unknown auto_contain action '{action}'")

    return errors


def validate_file(path: Path) -> list[str]:
    """Validate all rules in a TOML file."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        return [f"{path}: TOML parse error: {e}"]

    errors: list[str] = []
    rules = data.get("rules", [])
    if not rules:
        errors.append(f"{path}: no [[rules]] entries found")

    for i, rule in enumerate(rules):
        errors.extend(validate_rule(rule, str(path), i))

    return errors


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: validate.py <rule-file.toml> [...]")
        sys.exit(1)

    all_errors: list[str] = []
    for arg in sys.argv[1:]:
        path = Path(arg)
        if not path.exists():
            all_errors.append(f"File not found: {path}")
            continue
        errors = validate_file(path)
        all_errors.extend(errors)

    if all_errors:
        print("VALIDATION FAILED:")
        for error in all_errors:
            print(f"  ERROR: {error}")
        sys.exit(1)
    else:
        print(f"OK: All {len(sys.argv) - 1} file(s) validated successfully.")


if __name__ == "__main__":
    main()
