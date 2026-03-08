# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""MITRE ATT&CK coverage heatmap endpoint."""

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission
from ..models.incident import Incident

logger = logging.getLogger(__name__)

router = APIRouter()

# MITRE technique ID prefix → tactic name
# Source: MITRE ATT&CK Enterprise v14
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1595": "Reconnaissance", "T1592": "Reconnaissance", "T1589": "Reconnaissance",
    "T1590": "Reconnaissance", "T1591": "Reconnaissance", "T1598": "Reconnaissance",
    "T1597": "Reconnaissance",
    "T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
    "T1200": "Initial Access", "T1091": "Initial Access", "T1195": "Initial Access",
    "T1189": "Initial Access", "T1199": "Initial Access",
    "T1059": "Execution", "T1203": "Execution", "T1053": "Execution",
    "T1569": "Execution", "T1204": "Execution", "T1047": "Execution",
    "T1129": "Execution", "T1106": "Execution", "T1559": "Execution",
    "T1547": "Persistence", "T1543": "Persistence", "T1546": "Persistence",
    "T1136": "Persistence", "T1098": "Persistence", "T1197": "Persistence",
    "T1037": "Persistence", "T1176": "Persistence", "T1574": "Persistence",
    "T1548": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1055": "Privilege Escalation", "T1068": "Privilege Escalation",
    "T1562": "Defense Evasion", "T1070": "Defense Evasion", "T1036": "Defense Evasion",
    "T1027": "Defense Evasion", "T1553": "Defense Evasion", "T1112": "Defense Evasion",
    "T1202": "Defense Evasion", "T1218": "Defense Evasion", "T1220": "Defense Evasion",
    "T1110": "Credential Access", "T1003": "Credential Access", "T1558": "Credential Access",
    "T1555": "Credential Access", "T1552": "Credential Access", "T1187": "Credential Access",
    "T1087": "Discovery", "T1083": "Discovery", "T1057": "Discovery",
    "T1049": "Discovery", "T1069": "Discovery", "T1018": "Discovery",
    "T1046": "Discovery", "T1082": "Discovery", "T1016": "Discovery",
    "T1021": "Lateral Movement", "T1080": "Lateral Movement", "T1550": "Lateral Movement",
    "T1534": "Lateral Movement", "T1563": "Lateral Movement",
    "T1560": "Collection", "T1074": "Collection", "T1114": "Collection",
    "T1056": "Collection", "T1113": "Collection", "T1125": "Collection",
    "T1041": "Exfiltration", "T1020": "Exfiltration", "T1048": "Exfiltration",
    "T1011": "Exfiltration", "T1567": "Exfiltration",
    "T1485": "Impact", "T1486": "Impact", "T1490": "Impact",
    "T1489": "Impact", "T1498": "Impact", "T1499": "Impact",
}


class TechniqueCount(BaseModel):
    technique_id: str
    tactic: str
    count: int


class CoverageHeatmap(BaseModel):
    period_days: int
    total_incidents: int
    techniques: list[TechniqueCount]
    tactic_totals: dict[str, int]


@router.get(
    "/mitre-heatmap",
    response_model=CoverageHeatmap,
    status_code=status.HTTP_200_OK,
)
async def get_mitre_heatmap(
    period_days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INCIDENTS_READ)),
) -> CoverageHeatmap:
    """
    Return a MITRE ATT&CK coverage heatmap for the tenant.

    Shows which techniques have been detected and how frequently,
    grouped by tactic — useful for assessing detection coverage.
    """
    since = datetime.now(tz=timezone.utc) - timedelta(days=period_days)

    result = await db.execute(
        select(Incident.mitre_techniques)
        .where(
            Incident.first_seen_at >= since,
            Incident.mitre_techniques.is_not(None),
        )
        .limit(50000)
    )
    rows = result.scalars().all()

    technique_counter: Counter[str] = Counter()
    for techniques in rows:
        if isinstance(techniques, list):
            for t in techniques:
                if t:
                    technique_counter[t] += 1

    def base_id(t: str) -> str:
        return t.split(".")[0]

    techniques_out: list[TechniqueCount] = []
    tactic_totals: Counter[str] = Counter()

    for technique, count in technique_counter.most_common(50):
        tactic = _TECHNIQUE_TACTIC.get(base_id(technique), "Other")
        techniques_out.append(
            TechniqueCount(technique_id=technique, tactic=tactic, count=count)
        )
        tactic_totals[tactic] += count

    return CoverageHeatmap(
        period_days=period_days,
        total_incidents=len(rows),
        techniques=techniques_out,
        tactic_totals=dict(tactic_totals),
    )
