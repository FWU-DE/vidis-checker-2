from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vidis_compliance import callbacks, server
from vidis_compliance.catalog import CHECKS, OUTCOMES, REASONS
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.cli import load_criteria
from vidis_compliance.models import CheckFinding
from vidis_compliance.sources.site.crawl import PageCapture


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))

    def fake_crawl(url, pages=5, headless=True, screenshot_dir=None):
        shots = []
        if screenshot_dir is not None:
            Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
            (Path(screenshot_dir) / "page-1.png").write_bytes(b"png")
            shots.append({"label": "page-1", "url": url, "filename": "page-1.png", "path": str(Path(screenshot_dir) / "page-1.png")})
        return PageCapture(
            url=url,
            cookies=[{"name": "acme_id", "domain": "app.example.test", "value": "x"}],
            local_storage={"acme.widgetState": "1"},
            session_storage={},
            scripts=[],
            requests=["https://app.example.test/", "https://cdn.tracker.test/p.gif"],
            visited_urls=[url],
            screenshots=shots,
        )

    monkeypatch.setattr(server.cli_module, "crawl", fake_crawl)
    monkeypatch.setattr(server.cli_module, "check_site_transport", lambda url: [CheckFinding(criterion="ITS-ENC-359", status="PASS", note="ok")])
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(source_url=url, visited_urls=[], impressum=LegalPageResult(kind="impressum"), privacy=LegalPageResult(kind="privacy")),
    )
    return TestClient(server.app)


def _run(client: TestClient, path: str, body: dict) -> dict:
    job_id = client.post(path, json=body).json()["id"]
    deadline = time.monotonic() + 5
    while (job := client.get(f"/jobs/{job_id}").json())["status"] not in {"completed", "failed"}:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert job["status"] == "completed", job.get("error")
    return job


def test_manual_finding_carries_reason_evidence_hint_and_links(client: TestClient) -> None:
    job = _run(client, "/checks/site.browser_storage", {"target_url": "https://app.example.test"})
    finding = job["result"]["findings"][0]

    assert finding["criterion"] == "RDS-CUC-374"
    assert finding["status"] == "MANUELL"
    assert finding["reason"] == "needs_review"
    assert finding["check"] == "site.browser_storage"
    assert finding["evidence"]["local_storage_keys"] == ["acme.widgetState"]
    assert finding["evidence"]["pages"] == ["https://app.example.test/"]
    assert "Storage-Schlüssel" in finding["review_hint"]
    assert finding["artifacts"] == [f"/jobs/{job['id']}/artifacts/capture.json"]
    assert client.get(finding["artifacts"][0]).status_code == 200


def test_result_json_artifact_has_the_same_links(client: TestClient) -> None:
    job = _run(client, "/checks/site.browser_storage", {"target_url": "https://app.example.test"})

    stored = client.get(f"/jobs/{job['id']}/artifacts/result.json").json()

    assert stored["findings"][0]["artifacts"] == job["result"]["findings"][0]["artifacts"]


def test_pass_and_fail_are_automated(client: TestClient) -> None:
    job = _run(client, "/checks/site.transport", {"target_url": "https://app.example.test"})

    finding = next(f for f in job["result"]["findings"] if f["criterion"] == "ITS-ENC-359")
    assert finding["reason"] == "automated" and finding["review_hint"] is None


def test_every_finding_of_a_full_run_has_a_reason(client: TestClient) -> None:
    job = _run(client, "/jobs", {"target_url": "https://app.example.test"})

    findings = job["result"]["findings"]
    assert {f["criterion"] for f in findings} == set(load_criteria().items)
    assert all(f["reason"] in REASONS for f in findings)
    for f in findings:
        if f["reason"] == "not_automated":
            assert f["check"] is None
            assert not any(f["criterion"] in check.criteria for check in CHECKS if check.source in {"site", "documents", "code"})


def test_criteria_without_their_check_say_what_is_missing(client: TestClient) -> None:
    job = _run(client, "/checks/documents.analysis", {"target_url": "https://app.example.test"})

    cuc453 = next(f for f in job["result"]["findings"] if f["criterion"] == "RDS-CUC-453")
    assert cuc453["reason"] == "missing_input"
    assert "site.cookie_descriptions" in cuc453["note"]
    assert cuc453["note"] != "Not yet implemented"


def test_site_criteria_without_a_url_are_missing_input(client: TestClient) -> None:
    from vidis_compliance.sources.documents import analyze

    original = analyze.fetch_document
    analyze.fetch_document = lambda d: (b"text", "text/plain", d.location, d.kind)
    try:
        job = _run(client, "/jobs", {"agb_url": "https://app.example.test/agb"})
    finally:
        analyze.fetch_document = original

    cookies = next(f for f in job["result"]["findings"] if f["criterion"] == "RDS-CUC-371")
    assert cookies["reason"] == "missing_input"
    assert "target_url" in cookies["note"]


def test_vision_checks_link_public_screenshots(client: TestClient) -> None:
    job = _run(client, "/checks/site.advertising", {"target_url": "https://app.example.test"})

    finding = job["result"]["findings"][0]
    assert f"/jobs/{job['id']}/artifacts/screenshots/page-1.png" in finding["artifacts"]


def test_discovery_explains_outcomes_and_result_format(client: TestClient) -> None:
    payload = client.get("/discovery").json()

    assert set(payload["result_format"]["reasons"]) == {"automated", "needs_review", "not_automated", "missing_input", "not_reachable"}
    assert payload["result_format"]["example"]["reason"] == "needs_review"
    for check in payload["checks"]:
        if not check["id"].startswith("evidence."):
            assert check["outcomes"], check["id"]
            assert {o["status"] for o in check["outcomes"]} <= {"PASS", "FAIL", "MANUELL"}
            assert {o["reason"] for o in check["outcomes"]} <= set(REASONS)
    assert set(OUTCOMES) == {check.id for check in CHECKS}


def test_callback_summary_counts_reasons(client: TestClient) -> None:
    job = _run(client, "/checks/site.browser_storage", {"target_url": "https://app.example.test"})

    payload = callbacks.build_payload(server._read_metadata(job["id"]), "https://x.test")

    assert payload["summary"]["reasons"] == {"needs_review": 1}


def test_manual_lists_every_outcome_from_the_catalog() -> None:
    from html import escape

    manual = (Path(__file__).resolve().parents[1] / "docs" / "manual.html").read_text(encoding="utf-8")

    for check_id, outcomes in OUTCOMES.items():
        for _status, reason, when in outcomes:
            assert escape(when) in manual, (check_id, when)
    for reason, meaning in REASONS.items():
        assert f"<code>{reason}</code>" in manual and escape(meaning) in manual


def test_discovery_says_which_checks_each_criterion_needs(client: TestClient) -> None:
    criteria = {item["code"]: item for item in client.get("/discovery").json()["criteria"]}

    assert criteria["RDS-CUC-374"]["required_checks"] == ["site.browser_storage"]
    assert criteria["RDS-CUC-377"]["required_checks"] == ["site.tracking_mechanisms", "documents.analysis"]
    assert criteria["RDS-CUC-453"]["required_checks"] == ["site.cookie_descriptions"]
    assert criteria["RDS-AGB-368"]["required_checks"] == ["documents.analysis"]
    assert criteria["ITS-ENC-361"]["run"]["body"]["checks"] == ["site.transport"]
    assert criteria["RDS-CDN-379"]["required_checks"] == [] and criteria["RDS-CDN-379"]["run"] is None
    assert {o["check"] for o in criteria["RDS-CDN-379"]["optional_checks"]} == {"code.inspection"}
    for item in criteria.values():
        for check_id in item["required_checks"]:
            assert item["code"] in next(c for c in CHECKS if c.id == check_id).criteria


def test_required_checks_give_an_automatic_finding(client: TestClient) -> None:
    criteria = {item["code"]: item for item in client.get("/discovery").json()["criteria"]}

    job = _run(client, "/jobs", {"target_url": "https://app.example.test", "checks": criteria["RDS-CUC-374"]["required_checks"]})

    finding = next(f for f in job["result"]["findings"] if f["criterion"] == "RDS-CUC-374")
    assert finding["reason"] not in {"missing_input", "not_automated"}


def test_placeholder_does_not_suggest_the_check_that_ran(client: TestClient) -> None:
    job = _run(client, "/checks/documents.analysis", {"target_url": "https://app.example.test"})

    cuc453 = next(f for f in job["result"]["findings"] if f["criterion"] == "RDS-CUC-453")
    assert "site.cookie_descriptions" in cuc453["note"] and "documents.analysis" not in cuc453["note"]


def test_manual_has_the_criteria_table() -> None:
    from vidis_compliance.catalog import checks_needed_for

    manual = (Path(__file__).resolve().parents[1] / "docs" / "manual.html").read_text(encoding="utf-8")
    for code in load_criteria().items:
        row = manual.split(f"<tr><td><code>{code}</code></td>", 1)[1].split("</tr>", 1)[0]
        for check_id in checks_needed_for(code)["required"]:
            assert f"<code>{check_id}</code>" in row, (code, check_id)
