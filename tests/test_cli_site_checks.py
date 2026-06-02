from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vidis_compliance.cli import app
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.sources.site.crawl import PageCapture


def test_url_check_emits_advertising_and_youth_protection_findings_without_placeholders(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)

    def fake_crawl(url: str, pages: int, headless: bool) -> PageCapture:
        return PageCapture(
            url=url,
            cookies=[],
            local_storage={},
            session_storage={},
            scripts=["https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"],
            requests=["https://securepubads.g.doubleclick.net/tag/js/gpt.js"],
            resources=[
                {
                    "type": "iframe",
                    "url": "https://adservice.google.com/adsid/integrator.html",
                    "selector": "iframe#ad-slot",
                }
            ],
            links=[
                {
                    "url": "https://shop.example.test/book?utm_source=school&utm_medium=banner&aff_id=42",
                    "text": "Sponsor Angebot",
                    "selector": "a.sponsor-link",
                }
            ],
            visible_text=[
                "Anzeige: Lernspiel gesponsert von ExampleCo",
                "Bitte bestätige, dass du mindestens 18 Jahre alt bist.",
                "Casino Bonus und Wetten ab 18",
            ],
        )

    monkeypatch.setattr("vidis_compliance.cli.crawl", fake_crawl)
    monkeypatch.setattr("vidis_compliance.cli.check_site_transport", lambda url: [])
    monkeypatch.setattr(
        "vidis_compliance.cli.analyze_ipf_site",
        lambda url: IpfSiteAnalysis(
            source_url=url,
            visited_urls=[url],
            impressum=LegalPageResult(kind="impressum"),
            privacy=LegalPageResult(kind="privacy"),
        ),
    )
    monkeypatch.setattr("vidis_compliance.cli.findings_from_ipf_analysis", lambda analysis: [])

    result = CliRunner().invoke(
        app,
        ["check", "--url", "https://example.test", "--output", "local", "--audience", "SuS"],
    )

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "results" / "local" / "result.json").read_text())
    findings = {item["criterion"]: item for item in data["findings"]}
    for criterion in ["RDS-WER-384", "RDS-WER-385", "RDS-VIN-354"]:
        assert findings[criterion]["note"] != "Not yet implemented"
    assert findings["RDS-WER-384"]["status"] == "FAIL"
    assert findings["RDS-WER-385"]["status"] == "MANUELL"
    assert findings["RDS-VIN-354"]["status"] == "FAIL"
