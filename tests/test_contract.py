from __future__ import annotations

from fastapi.testclient import TestClient

from vidis_compliance import server
from vidis_compliance.contract import SEMVER, current_contract, load_snapshot, write_snapshot
from vidis_compliance.version import API_VERSION, HEADER


def test_contract_matches_the_snapshot_of_this_version() -> None:
    # Fails when the external contract changed: bump the version in pyproject.toml,
    # add a CHANGELOG.md entry and run `uv run vidis-report contract`.
    snapshot = load_snapshot()
    assert snapshot["api_version"] == API_VERSION, "version changed: run `uv run vidis-report contract`"
    assert current_contract() == snapshot["contract"], "contract changed: bump the version, then `uv run vidis-report contract`"


def test_version_is_semver() -> None:
    assert SEMVER.match(API_VERSION)


def test_snapshot_cannot_change_without_a_version_bump(tmp_path) -> None:
    path = tmp_path / "contract.json"
    write_snapshot(path)
    stale = load_snapshot(path)
    stale["contract"]["reasons"] = ["something-else"]
    path.write_text(__import__("json").dumps(stale), encoding="utf-8")
    try:
        write_snapshot(path)
    except ValueError as exc:
        assert "bump" in str(exc)
    else:
        raise AssertionError("snapshot was rewritten without a version bump")


def test_every_response_and_artifact_carries_the_version() -> None:
    client = TestClient(server.app)
    response = client.get("/discovery")
    assert response.headers[HEADER] == API_VERSION
    assert response.json()["api_version"] == API_VERSION
    assert client.get("/health").headers[HEADER] == API_VERSION
    assert client.get("/openapi.json").json()["info"]["version"] == API_VERSION
