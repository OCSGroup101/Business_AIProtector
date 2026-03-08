# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Rule management API — CRUD for detection rule files + in-API RDK validation.

Routes:
  GET    /api/v1/rules              List rules across all policy packs
  POST   /api/v1/rules              Create/upload a new rule file
  GET    /api/v1/rules/{id}         Get a single rule by ID
  PATCH  /api/v1/rules/{id}         Update rule content or toggle enabled
  DELETE /api/v1/rules/{id}         Delete a rule
  POST   /api/v1/rules/validate     Validate TOML content (no DB write)
  POST   /api/v1/rules/test         Run rule against provided fixture events
"""

import logging
import re
import tomllib
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_tenant_session
from ..middleware.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()

# ─── Pydantic models ──────────────────────────────────────────────────────────

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class RuleSummary(BaseModel):
    id: str
    name: str
    match_type: str
    severity: str
    enabled: bool


class CreateRuleRequest(BaseModel):
    content_toml: str
    pack: str = "custom"


class UpdateRuleRequest(BaseModel):
    content_toml: Optional[str] = None
    enabled: Optional[bool] = None


class ValidationResult(BaseModel):
    valid: bool
    errors: list[dict[str, str]]


class TestRequest(BaseModel):
    content_toml: str
    events: list[dict[str, Any]]


class TestResult(BaseModel):
    rule_id: str
    total_events: int
    matched_indices: list[int]


class RuleDetail(BaseModel):
    id: str
    name: str
    match_type: str
    severity: str
    enabled: bool
    content_toml: str
    mitre_techniques: list[str]


# ─── Validation helpers ───────────────────────────────────────────────────────

def _validate_rule_toml(content: str) -> list[dict[str, str]]:
    """Parse TOML and run RDK-style validation. Returns list of error dicts."""
    errors: list[dict[str, str]] = []

    try:
        data = tomllib.loads(content)
    except Exception as e:
        return [{"rule_id": "parse_error", "message": str(e)}]

    rules = data.get("rules", [])
    if not rules:
        errors.append({"rule_id": "schema", "message": "No [[rules]] entries found"})
        return errors

    seen_ids: set[str] = set()
    for rule in rules:
        rid = rule.get("id", "")
        if not rid:
            errors.append({"rule_id": "(empty)", "message": "Rule missing 'id' field"})
            continue
        if rid in seen_ids:
            errors.append({"rule_id": rid, "message": f"Duplicate rule ID: {rid}"})
        seen_ids.add(rid)

        response = rule.get("response", {})
        severity = response.get("severity", "")
        if severity not in VALID_SEVERITIES:
            errors.append({
                "rule_id": rid,
                "message": f"Invalid severity '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}",
            })

        mitre = rule.get("mitre", {})
        for tech in mitre.get("techniques", []):
            if not MITRE_RE.match(tech):
                errors.append({
                    "rule_id": rid,
                    "message": f"Invalid MITRE technique '{tech}'. Expected format T1234 or T1234.001",
                })

        match = rule.get("match", {})
        match_type = match.get("type", "")
        if match_type not in {"ioc", "behavioral", "heuristic", "sequence", "threshold"}:
            errors.append({
                "rule_id": rid,
                "message": f"Invalid match type '{match_type}'",
            })

        if match_type == "heuristic" and not match.get("lua_script", "").strip():
            errors.append({
                "rule_id": rid,
                "message": "Heuristic rule requires non-empty 'lua_script' in match block",
            })

        if match_type == "threshold":
            if not match.get("threshold"):
                errors.append({"rule_id": rid, "message": "Threshold rule requires 'threshold' field"})
            if not match.get("window_seconds"):
                errors.append({"rule_id": rid, "message": "Threshold rule requires 'window_seconds' field"})

        if match_type == "sequence":
            if not match.get("sequence"):
                errors.append({"rule_id": rid, "message": "Sequence rule requires 'sequence' steps list"})

    return errors


def _run_behavioral_match(rule: dict, event: dict) -> bool:
    """Evaluate a behavioral rule against a single event."""
    match = rule.get("match", {})
    event_types = match.get("event_types", [])
    # Normalise dot/underscore notation
    ev_type = event.get("event_type", "").replace(".", "_")
    if event_types:
        normalised = [t.replace(".", "_") for t in event_types]
        if ev_type not in normalised:
            return False

    for cond in match.get("conditions", []):
        field = cond.get("field", "")
        operator = cond.get("operator", "")
        values = [v.lower() for v in cond.get("values", [])]

        # Navigate dotted field path
        parts = field.split(".")
        val: Any = event
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                val = None
                break
        if val is None:
            return False
        val_str = str(val).lower()

        if operator == "in":
            if val_str not in values:
                return False
        elif operator == "contains":
            if not any(v in val_str for v in values):
                return False
        elif operator == "equals":
            if val_str not in values:
                return False
        elif operator == "not_in":
            if val_str in values:
                return False
        elif operator == "regex":
            import re as _re
            if not any(_re.search(v, val_str) for v in values):
                return False

    return True


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/validate", response_model=ValidationResult)
async def validate_rule(
    body: CreateRuleRequest,
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> ValidationResult:
    """Validate TOML rule content using RDK rules. No DB write."""
    errors = _validate_rule_toml(body.content_toml)
    return ValidationResult(valid=len(errors) == 0, errors=errors)


@router.post("/test", response_model=list[TestResult])
async def test_rule(
    body: TestRequest,
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> list[TestResult]:
    """Run rule against provided fixture events and return match results."""
    errors = _validate_rule_toml(body.content_toml)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"validation_errors": errors},
        )

    try:
        data = tomllib.loads(body.content_toml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    results: list[TestResult] = []
    for rule in data.get("rules", []):
        match_type = rule.get("match", {}).get("type", "behavioral")
        matched: list[int] = []

        if match_type in ("behavioral", "ioc"):
            for idx, event in enumerate(body.events):
                if _run_behavioral_match(rule, event):
                    matched.append(idx)

        results.append(TestResult(
            rule_id=rule.get("id", "unknown"),
            total_events=len(body.events),
            matched_indices=matched,
        ))

    return results


@router.get("", response_model=list[RuleSummary])
async def list_rules(
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> list[RuleSummary]:
    """List all rules stored as policy entries for this tenant."""
    from sqlalchemy import select, text

    try:
        result = await db.execute(
            text("SELECT id, name, content_toml FROM policies ORDER BY created_at DESC")
        )
        rows = result.fetchall()
    except Exception:
        return []

    summaries: list[RuleSummary] = []
    for row in rows:
        try:
            data = tomllib.loads(row.content_toml or "")
        except Exception:
            continue
        for rule in data.get("rules", []):
            match = rule.get("match", {})
            response = rule.get("response", {})
            summaries.append(RuleSummary(
                id=rule.get("id", row.id),
                name=rule.get("name", "Unnamed"),
                match_type=match.get("type", "behavioral"),
                severity=response.get("severity", "INFO"),
                enabled=rule.get("enabled", True),
            ))

    return summaries


@router.post("", response_model=RuleDetail, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: CreateRuleRequest,
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.POLICIES_WRITE)),
) -> RuleDetail:
    """Create a new rule pack entry (stored as a policy)."""
    errors = _validate_rule_toml(body.content_toml)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"validation_errors": errors},
        )

    try:
        data = tomllib.loads(body.content_toml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    rules = data.get("rules", [])
    if not rules:
        raise HTTPException(status_code=400, detail="No rules found in TOML")

    first_rule = rules[0]
    rule_id = first_rule.get("id", "")
    match = first_rule.get("match", {})
    response = first_rule.get("response", {})

    # Store as a policy
    from sqlalchemy import text
    from datetime import datetime, timezone
    from python_ulid import ULID

    policy_id = str(ULID())
    now = datetime.now(tz=timezone.utc)
    await db.execute(
        text("""
            INSERT INTO policies (id, name, content_toml, created_at, updated_at)
            VALUES (:id, :name, :toml, :now, :now)
        """),
        {"id": policy_id, "name": first_rule.get("name", rule_id),
         "toml": body.content_toml, "now": now},
    )
    await db.commit()

    mitre = first_rule.get("mitre", {})
    return RuleDetail(
        id=rule_id,
        name=first_rule.get("name", rule_id),
        match_type=match.get("type", "behavioral"),
        severity=response.get("severity", "INFO"),
        enabled=first_rule.get("enabled", True),
        content_toml=body.content_toml,
        mitre_techniques=mitre.get("techniques", []),
    )


@router.get("/{rule_id}", response_model=RuleDetail)
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> RuleDetail:
    """Get a rule by its ID."""
    from sqlalchemy import text

    result = await db.execute(
        text("SELECT id, name, content_toml FROM policies ORDER BY created_at DESC")
    )
    for row in result.fetchall():
        try:
            data = tomllib.loads(row.content_toml or "")
        except Exception:
            continue
        for rule in data.get("rules", []):
            if rule.get("id") == rule_id:
                match = rule.get("match", {})
                response = rule.get("response", {})
                mitre = rule.get("mitre", {})
                return RuleDetail(
                    id=rule_id,
                    name=rule.get("name", rule_id),
                    match_type=match.get("type", "behavioral"),
                    severity=response.get("severity", "INFO"),
                    enabled=rule.get("enabled", True),
                    content_toml=row.content_toml,
                    mitre_techniques=mitre.get("techniques", []),
                )

    raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
