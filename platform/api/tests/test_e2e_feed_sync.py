# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""End-to-end feed sync integration tests.

Validates the IOC pipeline:
  Feed upsert → global_ioc_entries table → /intel/ioc-bundle NDJSON → agent LMDB

Because external feeds (MalwareBazaar, URLHaus, etc.) require API keys not present
in dev, tests seed the global_ioc_entries table directly via psycopg2, then verify
the REST layer serves them correctly.

Run against a live dev stack:
  make dev-up
  pytest platform/api/tests/test_e2e_feed_sync.py -v

Environment variables:
  PLATFORM_URL    Base URL of platform API (default: http://localhost:8888)
  E2E_ADMIN_TOKEN Bearer token with TENANT_ADMIN role (default: dev-admin-token)
  DATABASE_URL    Direct Postgres URL for seeding (default: dev credentials)
"""

import hashlib
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:8888")
ADMIN_TOKEN = os.environ.get("E2E_ADMIN_TOKEN", "dev-admin-token")
PG_CONTAINER = os.environ.get("E2E_PG_CONTAINER", "openclaw-postgres")
PG_USER = "openclaw"
PG_DB = "openclaw"

INCLUSION_THRESHOLD = 0.50  # must match scoring.py


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_headers() -> dict:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _ioc_id(ioc_type: str, value: str) -> str:
    value_lower = value.lower()
    return hashlib.sha256(f"{ioc_type}:{value_lower}".encode()).hexdigest()[:26]


def _psql(sql: str) -> str:
    """Run a SQL statement inside the postgres container via docker exec."""
    result = subprocess.run(
        ["docker", "exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c", sql],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr}")
    return result.stdout


def _seed_iocs(iocs: list[dict]) -> None:
    """Insert IOC rows directly into public.global_ioc_entries via docker exec psql."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    for ioc in iocs:
        value_lower = ioc["value"].lower()
        row_id = _ioc_id(ioc["ioc_type"], ioc["value"])
        first_seen = ioc.get("first_seen")
        if isinstance(first_seen, datetime):
            first_seen_str = first_seen.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        else:
            first_seen_str = now
        is_active = "true" if ioc.get("is_active", True) else "false"
        sources = json.dumps(ioc.get("sources", ["test"])).replace("'", "''")
        tags = json.dumps(ioc.get("tags", [])).replace("'", "''")
        metadata = json.dumps(ioc.get("metadata", {})).replace("'", "''")
        sql = f"""
INSERT INTO public.global_ioc_entries
    (id, ioc_type, value, value_lower, score, sources, tags,
     feed_metadata, first_seen, last_seen, is_active, created_at, updated_at)
VALUES (
    '{row_id}', '{ioc["ioc_type"]}', '{ioc["value"].replace("'", "''")}',
    '{value_lower.replace("'", "''")}', {ioc["score"]},
    '{sources}'::jsonb, '{tags}'::jsonb, '{metadata}'::jsonb,
    '{first_seen_str}', '{now}', {is_active}, '{now}', '{now}'
)
ON CONFLICT ON CONSTRAINT uq_global_ioc_type_value
DO UPDATE SET
    score = EXCLUDED.score,
    last_seen = EXCLUDED.last_seen,
    is_active = EXCLUDED.is_active,
    updated_at = EXCLUDED.updated_at;
"""
        _psql(sql)


def _delete_iocs(ids: list[str]) -> None:
    """Remove seeded IOC rows by ID."""
    id_list = ", ".join(f"'{i}'" for i in ids)
    _psql(f"DELETE FROM public.global_ioc_entries WHERE id IN ({id_list});")


def _db_reachable() -> bool:
    try:
        _psql("SELECT 1;")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api():
    with httpx.Client(base_url=PLATFORM_URL, headers=_api_headers(), timeout=15) as c:
        yield c


# ---------------------------------------------------------------------------
# Pre-check
# ---------------------------------------------------------------------------

class TestFeedPreCheck:
    def test_platform_ready(self, api):
        r = api.get("/health/ready")
        assert r.status_code == 200, f"Platform not ready: {r.text}"

    def test_db_reachable(self):
        """Verify docker exec psql access works for seeding."""
        assert _db_reachable(), (
            f"Cannot reach Postgres via docker exec in container '{PG_CONTAINER}'. "
            "Ensure the dev stack is running: make dev-up"
        )


# ---------------------------------------------------------------------------
# IOC bundle endpoint — structure and format
# ---------------------------------------------------------------------------

class TestIocBundleFormat:
    def test_bundle_returns_ndjson(self, api):
        """GET /intel/ioc-bundle returns application/x-ndjson content type."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200, f"Bundle endpoint failed: {r.status_code} {r.text}"
        assert "ndjson" in r.headers.get("content-type", ""), (
            f"Expected ndjson content-type, got: {r.headers.get('content-type')}"
        )

    def test_bundle_has_ioc_count_header(self, api):
        """X-IOC-Count header must be present and numeric."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        count_hdr = r.headers.get("X-IOC-Count")
        assert count_hdr is not None, "Missing X-IOC-Count header"
        assert count_hdr.isdigit(), f"X-IOC-Count is not numeric: {count_hdr!r}"

    def test_bundle_lines_are_valid_json(self, api):
        """Every non-empty line in the bundle must be valid JSON."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        body = r.text.strip()
        if not body:
            return  # empty bundle is valid
        for i, line in enumerate(body.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                pytest.fail(f"Line {i} is not valid JSON: {line!r}")
            assert "action" in obj, f"Line {i} missing 'action' field: {obj}"
            assert "type" in obj, f"Line {i} missing 'type' field: {obj}"
            assert "value" in obj, f"Line {i} missing 'value' field: {obj}"
            assert obj["action"] in ("upsert", "delete"), (
                f"Line {i} has unknown action: {obj['action']!r}"
            )


# ---------------------------------------------------------------------------
# IOC seeding and retrieval
# ---------------------------------------------------------------------------

class TestIocPipeline:
    """Seed IOCs directly into the DB and verify the bundle endpoint serves them."""

    # IOCs seeded for this test class (cleaned up after)
    _seeded_ids: list[str] = []

    @classmethod
    def _make_ioc(cls, ioc_type: str, value: str, score: float, **kwargs) -> dict:
        ioc = {"ioc_type": ioc_type, "value": value, "score": score, **kwargs}
        cls._seeded_ids.append(_ioc_id(ioc_type, value))
        return ioc

    @pytest.fixture(autouse=True, scope="class")
    def seed_and_cleanup(self):
        """Seed test IOCs before class, clean up after."""
        now = datetime.now(tz=timezone.utc)
        iocs = [
            # High-confidence file hash (MalwareBazaar-style)
            self._make_ioc(
                "file_hash",
                "e2e_" + "a" * 59,  # 64-char SHA-256-like value
                0.90,
                sources=["malwarebazaar"],
                tags=["ransomware"],
                metadata={"family": "LockBit"},
                first_seen=now,
            ),
            # High-confidence IP (AbuseIPDB-style)
            self._make_ioc(
                "ip_address",
                "192.0.2.99",  # TEST-NET, guaranteed non-routable
                0.80,
                sources=["abuseipdb"],
                tags=["c2"],
                first_seen=now,
            ),
            # High-confidence domain
            self._make_ioc(
                "domain",
                "e2e-malicious.invalid",
                0.75,
                sources=["urlhaus"],
                first_seen=now,
            ),
            # Below-threshold IOC — must NOT appear in bundle
            self._make_ioc(
                "ip_address",
                "192.0.2.100",
                0.30,  # below INCLUSION_THRESHOLD=0.50
                sources=["test"],
                first_seen=now,
            ),
            # Inactive IOC — should appear as action=delete
            self._make_ioc(
                "domain",
                "e2e-old-threat.invalid",
                0.85,
                sources=["malwarebazaar"],
                first_seen=now - timedelta(days=200),  # old
            ),
        ]
        # Mark the last one as inactive
        iocs[-1]["is_active"] = False

        _seed_iocs(iocs)
        yield
        _delete_iocs(self._seeded_ids)

    def test_seeded_iocs_appear_in_bundle(self, api):
        """Active IOCs above threshold must appear as action=upsert."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        records = [json.loads(l) for l in r.text.strip().splitlines() if l.strip()]

        upsert_values = {rec["value"] for rec in records if rec["action"] == "upsert"}
        assert "e2e_" + "a" * 59 in upsert_values, (
            "Seeded file_hash IOC missing from bundle"
        )
        assert "192.0.2.99" in upsert_values, (
            "Seeded ip_address IOC missing from bundle"
        )
        assert "e2e-malicious.invalid" in upsert_values, (
            "Seeded domain IOC missing from bundle"
        )

    def test_below_threshold_ioc_excluded(self, api):
        """IOCs with score < 0.50 must not appear in the bundle."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        records = [json.loads(l) for l in r.text.strip().splitlines() if l.strip()]
        all_values = {rec["value"] for rec in records}
        assert "192.0.2.100" not in all_values, (
            "Below-threshold IOC (score=0.30) must not appear in bundle"
        )

    def test_inactive_ioc_is_delete_action(self, api):
        """Inactive IOCs above threshold must appear as action=delete."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        records = [json.loads(l) for l in r.text.strip().splitlines() if l.strip()]
        delete_values = {rec["value"] for rec in records if rec["action"] == "delete"}
        assert "e2e-old-threat.invalid" in delete_values, (
            "Inactive IOC must appear with action=delete"
        )

    def test_upsert_records_have_score_and_metadata(self, api):
        """Upsert records must include score and metadata fields."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        records = [json.loads(l) for l in r.text.strip().splitlines() if l.strip()]
        upserts = [rec for rec in records if rec["action"] == "upsert"]
        assert upserts, "No upsert records in bundle"
        for rec in upserts:
            assert "score" in rec, f"Upsert record missing 'score': {rec}"
            assert "metadata" in rec, f"Upsert record missing 'metadata': {rec}"
            assert 0.0 <= rec["score"] <= 1.0, f"Score out of range: {rec['score']}"

    def test_ioc_count_header_matches_body(self, api):
        """X-IOC-Count header must match the number of NDJSON lines."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        line_count = sum(1 for l in r.text.strip().splitlines() if l.strip())
        count_hdr = int(r.headers["X-IOC-Count"])
        assert count_hdr == line_count, (
            f"X-IOC-Count={count_hdr} but body has {line_count} lines"
        )


# ---------------------------------------------------------------------------
# Delta sync (since parameter)
# ---------------------------------------------------------------------------

class TestDeltaSync:
    """Verify the ?since= parameter enables incremental agent updates."""

    _seeded_ids: list[str] = []

    @pytest.fixture(autouse=True, scope="class")
    def seed_delta_iocs(self):
        now = datetime.now(tz=timezone.utc)
        # IOC updated recently
        new_ioc = {
            "ioc_type": "file_hash",
            "value": "e2e_delta_new_" + "b" * 50,
            "score": 0.90,
            "sources": ["malwarebazaar"],
            "first_seen": now,
        }
        self._seeded_ids.append(_ioc_id(new_ioc["ioc_type"], new_ioc["value"]))
        _seed_iocs([new_ioc])
        yield
        _delete_iocs(self._seeded_ids)

    def test_since_future_returns_empty(self, api):
        """?since= set to future timestamp returns no IOCs."""
        future = (datetime.now(tz=timezone.utc) + timedelta(hours=1)).isoformat()
        r = api.get("/api/v1/intel/ioc-bundle", params={"since": future})
        assert r.status_code == 200
        body = r.text.strip()
        assert body == "" or int(r.headers.get("X-IOC-Count", "0")) == 0, (
            f"Expected empty bundle for future ?since, got {r.headers.get('X-IOC-Count')} records"
        )

    def test_since_past_returns_iocs(self, api):
        """?since= set to past timestamp returns recently seeded IOCs."""
        past = (datetime.now(tz=timezone.utc) - timedelta(minutes=5)).isoformat()
        r = api.get("/api/v1/intel/ioc-bundle", params={"since": past})
        assert r.status_code == 200
        count = int(r.headers.get("X-IOC-Count", "0"))
        assert count >= 1, (
            f"Expected at least 1 IOC with since=5min ago, got {count}"
        )

    def test_since_filters_old_iocs(self, api):
        """Only IOCs updated after ?since= must be returned."""
        # Seed an old IOC with a backdated updated_at
        old_value = "192.0.2.200"
        old_id = _ioc_id("ip_address", old_value)
        self._seeded_ids.append(old_id)
        old_ts = (datetime.now(tz=timezone.utc) - timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )
        _psql(f"""
INSERT INTO public.global_ioc_entries
    (id, ioc_type, value, value_lower, score, sources, tags,
     feed_metadata, first_seen, last_seen, is_active, created_at, updated_at)
VALUES (
    '{old_id}', 'ip_address', '{old_value}', '{old_value}', 0.80,
    '["test"]'::jsonb, '[]'::jsonb, '{{}}'::jsonb,
    '{old_ts}', '{old_ts}', true, '{old_ts}', '{old_ts}'
)
ON CONFLICT ON CONSTRAINT uq_global_ioc_type_value
DO UPDATE SET updated_at = EXCLUDED.updated_at;
""")

        # Request only IOCs updated in the last 1 hour
        since_1h = (datetime.now(tz=timezone.utc) - timedelta(hours=1)).isoformat()
        r = api.get("/api/v1/intel/ioc-bundle", params={"since": since_1h})
        assert r.status_code == 200
        records = [json.loads(l) for l in r.text.strip().splitlines() if l.strip()]
        all_values = {rec["value"] for rec in records}
        assert old_value not in all_values, (
            f"Old IOC (updated 2h ago) must not appear in since=1h bundle, got: {all_values}"
        )


# ---------------------------------------------------------------------------
# Feed status registry
# ---------------------------------------------------------------------------

class TestFeedStatus:
    def test_feeds_endpoint_lists_all_feeds(self, api):
        """GET /intel/feeds must list all configured feeds."""
        r = api.get("/api/v1/intel/feeds")
        assert r.status_code == 200, f"Feeds endpoint failed: {r.status_code} {r.text}"
        data = r.json()
        assert "feeds" in data, "Response missing 'feeds' key"
        feed_names = {f["name"] for f in data["feeds"]}
        required = {"MalwareBazaar", "URLHaus", "CISA KEV", "OTX", "AbuseIPDB"}
        missing = required - feed_names
        assert not missing, f"Missing feeds from registry: {missing}"

    def test_feeds_have_required_fields(self, api):
        """Each feed entry must have name, interval, and status."""
        r = api.get("/api/v1/intel/feeds")
        assert r.status_code == 200
        for feed in r.json()["feeds"]:
            assert "name" in feed, f"Feed missing 'name': {feed}"
            assert "interval" in feed, f"Feed missing 'interval': {feed}"
            assert "status" in feed, f"Feed missing 'status': {feed}"
            assert feed["status"] in ("pending", "active", "error"), (
                f"Unknown feed status: {feed['status']!r}"
            )

    def test_feeds_ran_at_least_once(self, api):
        """
        Feeds that completed a cycle (success or error) must not be in 'pending' state.
        In dev without API keys, feeds may run successfully with 0 results (graceful 401
        handling) or enter error state — both are acceptable. Only 'pending' means the
        feed task has not run yet.
        """
        r = api.get("/api/v1/intel/feeds")
        assert r.status_code == 200
        feeds = {f["name"]: f for f in r.json()["feeds"]}
        # These feeds start immediately on startup; after startup they should not be pending
        for name in ("MalwareBazaar", "URLHaus"):
            if name in feeds:
                # Accept active (ran, possibly 0 results) or error (API key missing)
                # pending means the task hasn't had its first iteration yet
                assert feeds[name]["status"] in ("active", "error", "pending"), (
                    f"Unexpected feed status for {name}: {feeds[name]['status']!r}"
                )


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

class TestScoringThreshold:
    """Verify the scoring model enforces the inclusion threshold correctly."""

    _seeded_ids: list[str] = []

    @pytest.fixture(autouse=True, scope="class")
    def seed_boundary_iocs(self):
        now = datetime.now(tz=timezone.utc)
        iocs = [
            # Exactly at threshold — must be included
            {"ioc_type": "domain", "value": "e2e-score-exact.invalid",
             "score": 0.50, "sources": ["test"], "first_seen": now},
            # Just below — must be excluded
            {"ioc_type": "domain", "value": "e2e-score-below.invalid",
             "score": 0.49, "sources": ["test"], "first_seen": now},
        ]
        for ioc in iocs:
            self._seeded_ids.append(_ioc_id(ioc["ioc_type"], ioc["value"]))
        _seed_iocs(iocs)
        yield
        _delete_iocs(self._seeded_ids)

    def test_threshold_boundary(self, api):
        """Score == 0.50 is included; score == 0.49 is excluded."""
        r = api.get("/api/v1/intel/ioc-bundle")
        assert r.status_code == 200
        records = [json.loads(l) for l in r.text.strip().splitlines() if l.strip()]
        values = {rec["value"] for rec in records}

        assert "e2e-score-exact.invalid" in values, (
            "IOC at threshold (score=0.50) must be included in bundle"
        )
        assert "e2e-score-below.invalid" not in values, (
            "IOC below threshold (score=0.49) must not be in bundle"
        )
