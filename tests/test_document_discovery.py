from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vidis_compliance import cli, server
from vidis_compliance.checks.site import ipf
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.sources.documents import analyze

PAGES = {
    "https://anbieter.test/": '<a href="/agb">AGB</a> <a href="/datenschutz">Datenschutzerklärung</a> <a href="/impressum">Impressum</a>'
    '<a href="https://other.test/avv">AVV</a>',
    "https://anbieter.test/agb": 'Nutzungsbedingungen <a href="/vertrag/auftragsverarbeitung">Vertrag zur Auftragsverarbeitung</a>',
    "https://anbieter.test/datenschutz": "Datenschutz",
    "https://anbieter.test/impressum": "Impressum",
}


def fake_fetch(url: str):
    return (200, PAGES[url]) if url in PAGES else (404, "")


def test_finds_agb_privacy_and_avv_linked_from_a_legal_page() -> None:
    result = ipf.discover_document_links("https://anbieter.test/", fetch=fake_fetch)

    assert result["found"] == {
        "agb": "https://anbieter.test/agb",
        "privacy": "https://anbieter.test/datenschutz",
        "avv": "https://anbieter.test/vertrag/auftragsverarbeitung",
    }
    assert result["missing"] == []
    assert len(result["searched"]) <= 5


def test_only_wanted_kinds_and_same_site_links() -> None:
    result = ipf.discover_document_links("https://anbieter.test/", fetch=lambda url: (200, PAGES["https://anbieter.test/"]), wanted=("avv",))

    assert result["found"] == {}  # the AVV link on the start page points to another site
    assert result["missing"] == ["avv"]


def test_unreachable_start_page_is_reported() -> None:
    def broken(url: str):
        raise httpx.ConnectError("down")

    result = ipf.discover_document_links("https://anbieter.test/", fetch=broken)

    assert result["found"] == {} and result["errors"]


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(server.cli_module, "check_site_transport", lambda url: [])
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(source_url=url, visited_urls=[], impressum=LegalPageResult(kind="impressum"), privacy=LegalPageResult(kind="privacy")),
    )
    return TestClient(server.app)


def _run(client: TestClient, path: str, body: dict) -> dict:
    response = client.post(path, json=body)
    assert response.status_code == 202, response.text
    job_id = response.json()["id"]
    deadline = time.monotonic() + 5
    while (job := client.get(f"/jobs/{job_id}").json())["status"] not in {"completed", "failed"}:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    return job


def test_document_check_needs_only_the_site(client: TestClient, monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "discover_document_links", lambda url, wanted=(), **k: ipf.discover_document_links(url, fetch=fake_fetch, wanted=wanted))
    fetched: list[str] = []

    def fake_document(document):
        fetched.append(document.location)
        if document.kind == "avv":
            raise httpx.HTTPStatusError("404", request=httpx.Request("GET", document.location), response=httpx.Response(404))
        return b"<p>Die Nutzung ist werbefrei.</p>", "text/html", document.location, document.kind

    monkeypatch.setattr(analyze, "fetch_document", fake_document)

    job = _run(client, "/checks/documents.analysis", {"target_url": "https://anbieter.test/"})

    assert job["status"] == "completed", job.get("error")
    assert set(fetched) == {"https://anbieter.test/agb", "https://anbieter.test/datenschutz", "https://anbieter.test/vertrag/auftragsverarbeitung"}
    codes = {finding["criterion"] for finding in job["result"]["findings"]}
    # RDS-CUC-377 is decided by site.tracking_mechanisms when a URL is given.
    assert set(analyze.DOCUMENT_CRITERIA) - {"RDS-CUC-377"} <= codes
    assert "RDS-CUC-377" not in codes
    capture = client.get(f"/jobs/{job['id']}/artifacts/document_capture.json").json()
    assert capture["discovery"]["found"]["agb"] == "https://anbieter.test/agb"
    assert capture["skipped"] == [{"location": "https://anbieter.test/vertrag/auftragsverarbeitung", "kind": "avv", "error": "HTTPStatusError"}]


def test_supplied_urls_win_and_only_the_rest_is_searched(client: TestClient, monkeypatch) -> None:
    asked: dict = {}

    def spy(url, wanted=(), **kwargs):
        asked["wanted"] = wanted
        return {"found": {}, "missing": list(wanted), "searched": [url], "errors": []}

    monkeypatch.setattr(cli, "discover_document_links", spy)
    monkeypatch.setattr(analyze, "fetch_document", lambda d: (b"Datenschutz", "text/plain", d.location, d.kind))

    job = _run(client, "/checks/documents.analysis", {"target_url": "https://anbieter.test/", "privacy_url": "https://anbieter.test/ds"})

    assert job["status"] == "completed", job.get("error")
    assert asked["wanted"] == ("agb", "avv")


def test_nothing_found_gives_manual_with_a_clear_note(client: TestClient) -> None:
    job = _run(client, "/checks/documents.analysis", {"target_url": "https://anbieter.test/"})

    assert job["status"] == "completed", job.get("error")
    findings = {f["criterion"]: f for f in job["result"]["findings"]}
    assert set(findings) == set(analyze.DOCUMENT_CRITERIA)
    for code in analyze.DOCUMENT_CRITERIA:
        assert findings[code]["status"] == "MANUELL"
        assert "Keine AGB, Datenschutzerklärung oder AVV auf anbieter.test gefunden" in findings[code]["note"]


def test_supplied_documents_still_fail_loudly(client: TestClient, monkeypatch) -> None:
    def broken(document):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(analyze, "fetch_document", broken)

    job = _run(client, "/checks/documents.analysis", {"agb_url": "https://anbieter.test/agb"})

    assert job["status"] == "failed"


def test_www_and_bare_domain_count_as_the_same_site() -> None:
    pages = {"https://www.anbieter.test/": '<a href="https://anbieter.test/datenschutz/">Datenschutz</a> <a href="https://anbieter.test/agb/">AGB</a>'}

    result = ipf.discover_document_links("https://www.anbieter.test/", fetch=lambda u: (200, pages.get(u, "")) if u in pages else (404, ""))

    assert result["found"]["privacy"] == "https://anbieter.test/datenschutz/"
    assert result["found"]["agb"] == "https://anbieter.test/agb/"
    assert ipf._legal_url("https://www.anbieter.test/", "https://evil-anbieter.test/x") is None


def test_known_framework_storage_keys_are_functional() -> None:
    from vidis_compliance.checks.site.cookies import classify_local_storage

    status, note = classify_local_storage({"session_storage": {"htmx-current-path-for-history": "/", "wpEmojiSettingsSupports": "{}"}}, "beide")

    assert status == "PASS", note
