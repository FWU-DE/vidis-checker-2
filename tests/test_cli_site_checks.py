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



def test_url_check_can_attach_lighthouse_and_webinspector_exports(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    def fake_crawl(url: str, pages: int, headless: bool, **kwargs) -> PageCapture:
        return PageCapture(
            url=url,
            cookies=[],
            local_storage={},
            session_storage={},
            scripts=[],
            requests=["https://example.test/app.js"],
            resources=[],
            links=[],
            visible_text=[],
        )

    def fake_lighthouse(url: str, output_dir: Path) -> dict:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "report.json").write_text('{"categories": {}}', encoding="utf-8")
        (output_dir / "report.html").write_text('<html>Lighthouse</html>', encoding="utf-8")
        return {
            "available": True,
            "json": "lighthouse/report.json",
            "html": "lighthouse/report.html",
            "scores": {"performance": 0.91},
        }

    monkeypatch.setattr("vidis_compliance.cli.crawl", fake_crawl)
    monkeypatch.setattr("vidis_compliance.cli.run_lighthouse", fake_lighthouse)
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
        [
            "check",
            "--url",
            "https://example.test",
            "--output",
            "evidence",
            "--lighthouse",
            "--webinspector-export",
        ],
    )

    assert result.exit_code == 0, result.output
    capture = json.loads((tmp_path / "results" / "evidence" / "capture.json").read_text())
    assert capture["lighthouse"]["scores"] == {"performance": 0.91}
    assert capture["webinspector"]["network"] == "webinspector/network.json"
    assert (tmp_path / "results" / "evidence" / "lighthouse" / "report.json").exists()
    assert (tmp_path / "results" / "evidence" / "webinspector" / "network.json").exists()
