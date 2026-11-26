"""Snapshot of the external contract, so a change cannot ship without a version bump.

``docs/contract.json`` holds the contract of the current ``API_VERSION``: the API
schema without prose, every check with its criteria, outcomes and evidence keys,
the criteria with the checks they need, and the callback payload keys. The test
suite fails when the code and the snapshot differ; ``vidis-report contract``
writes a new snapshot and refuses to do so unless the version was bumped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .version import API_VERSION

SNAPSHOT_PATH = Path(__file__).resolve().parents[2] / "docs" / "contract.json"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_PROSE = {"description", "summary", "title", "examples", "example"}


def _without_prose(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_prose(item) for key, item in value.items() if key not in _PROSE}
    if isinstance(value, list):
        return [_without_prose(item) for item in value]
    return value


def current_contract() -> dict[str, Any]:
    from .callbacks import build_payload
    from .catalog import CHECKS, EVIDENCE_KEYS, OUTCOMES, REASONS, checks_needed_for
    from .cli import load_criteria
    from .server import app

    openapi = _without_prose(app.openapi())
    openapi.pop("info", None)
    request = SimpleNamespace(checks=[], target_url=None)
    payload = build_payload(SimpleNamespace(id="x", status="completed", error=None, updated_at="", request=request, result=None), "")
    return {
        "openapi": openapi,
        "checks": {
            check.id: {
                "source": check.source,
                "criteria": list(check.criteria),
                "enabled_by": check.enabled_by,
                "outcomes": sorted({f"{status}/{reason}" for status, reason, _when in OUTCOMES.get(check.id, ())}),
                "evidence_keys": list(EVIDENCE_KEYS.get(check.id, ())),
            }
            for check in CHECKS
        },
        "criteria": {
            code: {"required": checks_needed_for(code)["required"], "optional": [o["check"] for o in checks_needed_for(code)["optional"]]}
            for code in load_criteria().items
        },
        "reasons": sorted(REASONS),
        "callback_payload": sorted(payload) + sorted(f"summary.{key}" for key in payload["summary"]) + sorted(f"links.{key}" for key in payload["links"]),
    }


def load_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_snapshot(path: Path = SNAPSHOT_PATH) -> Path:
    contract = current_contract()
    if path.exists():
        previous = load_snapshot(path)
        if previous["contract"] != contract and previous["api_version"] == API_VERSION:
            raise ValueError(
                f"the contract changed but the version is still {API_VERSION}; bump version in pyproject.toml "
                "(MAJOR: removed/renamed/changed meaning, MINOR: added, PATCH: no format change) and add a CHANGELOG.md entry"
            )
    path.write_text(json.dumps({"api_version": API_VERSION, "contract": contract}, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
