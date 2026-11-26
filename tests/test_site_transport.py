from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from typer.testing import CliRunner

import vidis_compliance.cli as cli
from vidis_compliance.cli import app
from vidis_compliance.models import CheckFinding
from vidis_compliance.sources.site.crawl import PageCapture
from vidis_compliance.checks.site.basic_http import check_site_transport


runner = CliRunner()


@dataclass
class FakeResponse:
    status_code: int
    headers: dict[str, str]


def _fake_http_get(responses: dict[str, FakeResponse]):
    def get(url: str, **_kwargs) -> FakeResponse:
        parsed = urlparse(url)
        key = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        return responses[key]

    return get


def test_site_transport_passes_for_https_redirect_and_rejected_obsolete_tls() -> None:
    findings = check_site_transport(
        "example.test/login?token=secret",
        http_get=_fake_http_get(
            {
                "https://example.test/login": FakeResponse(200, {}),
                "http://example.test/": FakeResponse(301, {"Location": "https://example.test/"}),
            }
        ),
        tls_probe=lambda host, port: {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False},
    )

    by_code = {finding.criterion: finding for finding in findings}
    assert by_code["ITS-ENC-359"].status == "PASS"
    assert by_code["ITS-ENC-360"].status == "PASS"
    assert by_code["ITS-ENC-361"].status == "PASS"
    assert "token=secret" not in " ".join(finding.note for finding in findings)
    assert "https://example.test/login" in by_code["ITS-ENC-359"].note


def test_site_transport_fails_when_http_serves_content_and_tls10_is_accepted() -> None:
    findings = check_site_transport(
        "https://example.test/",
        http_get=_fake_http_get(
            {
                "https://example.test/": FakeResponse(200, {}),
                "http://example.test/": FakeResponse(200, {}),
            }
        ),
        tls_probe=lambda host, port: {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": False},
    )

    by_code = {finding.criterion: finding for finding in findings}
    assert by_code["ITS-ENC-359"].status == "FAIL"
    assert "HTTP 200" in by_code["ITS-ENC-359"].note
    assert by_code["ITS-ENC-360"].status == "FAIL"
    assert by_code["ITS-ENC-361"].status == "FAIL"
    assert "TLSv1.0 accepted" in by_code["ITS-ENC-361"].note


def test_cli_check_url_writes_transport_findings_without_placeholders(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli,
        "crawl",
        lambda url, pages, headless: PageCapture(
            url="https://example.test/",
            cookies=[],
            local_storage={},
            session_storage={},
            scripts=[],
            requests=[],
            visited_urls=["https://example.test/"],
        ),
    )
    monkeypatch.setattr(
        cli,
        "check_site_transport",
        lambda url: [
            CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS reachable"),
            CheckFinding(criterion="ITS-ENC-360", status="PASS", note="HTTP redirects to HTTPS"),
            CheckFinding(criterion="ITS-ENC-361", status="PASS", note="obsolete TLS rejected"),
        ],
    )

    result = runner.invoke(app, ["check", "--url", "https://example.test/", "--output", "sitejob"])

    assert result.exit_code == 0, result.output
    payload = json.loads((tmp_path / "results" / "sitejob" / "result.json").read_text(encoding="utf-8"))
    by_code = {finding["criterion"]: finding for finding in payload["findings"]}
    for code in ["ITS-ENC-359", "ITS-ENC-360", "ITS-ENC-361"]:
        assert by_code[code]["status"] == "PASS"
        assert by_code[code]["check"] is not None and by_code[code]["reason"] not in {"not_automated", "missing_input"}
