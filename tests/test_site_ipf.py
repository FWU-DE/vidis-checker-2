from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import vidis_compliance.cli as cli
from vidis_compliance.checks.site.ipf import (
    IpfSiteAnalysis,
    LegalPageResult,
    analyze_ipf_site,
    discover_legal_links,
    findings_from_ipf_analysis,
)
from vidis_compliance.cli import app
from vidis_compliance.models import CheckFinding
from vidis_compliance.sources.site.crawl import PageCapture


def _fetcher(pages: dict[str, tuple[int, str]]):
    def fetch(url: str):
        return pages[url]

    return fetch


def test_discover_legal_links_normalizes_relative_privacy_and_impressum_urls():
    html = """
    <footer>
      <a href="/impressum#top">Impressum</a>
      <a href="datenschutz">Datenschutzerklärung</a>
      <a href="https://other.test/privacy">Privacy</a>
      <a href="mailto:hello@example.test">Kontakt</a>
    </footer>
    """

    links = discover_legal_links("https://example.test/app/", html)

    assert links == {
        "impressum": "https://example.test/impressum",
        "privacy": "https://example.test/app/datenschutz",
    }


def test_ipf_analysis_produces_four_non_placeholder_pass_findings_for_complete_pages():
    home = """
    <a href="/impressum">Impressum</a>
    <a href="/datenschutz">Datenschutzerklärung</a>
    """
    impressum = """
    Impressum Diensteanbieter: Example Learning GmbH, Musterstraße 1, 10115 Berlin.
    Vertreten durch Geschäftsführerin Erika Muster. Kontakt: info@example.test, Telefon 030 123456.
    """
    privacy = """
    Datenschutzerklärung. Verantwortlicher ist Example Learning GmbH, Musterstraße 1, Berlin.
    Datenschutzbeauftragter: datenschutz@example.test. Wir erläutern die Zwecke der Verarbeitung,
    die Rechtsgrundlagen nach Art. 6 DSGVO, Empfänger und Auftragsverarbeiter, Speicherdauer und Löschung
    sowie Betroffenenrechte auf Auskunft, Berichtigung, Löschung und Widerspruch.
    """

    analysis = analyze_ipf_site(
        "https://example.test/",
        fetch=_fetcher(
            {
                "https://example.test/": (200, home),
                "https://example.test/impressum": (200, impressum),
                "https://example.test/datenschutz": (200, privacy),
            }
        ),
    )
    findings = {finding.criterion: finding for finding in findings_from_ipf_analysis(analysis)}

    assert set(findings) == {"RDS-IPF-364", "RDS-IPF-365", "RDS-IPF-366", "RDS-IPF-367"}
    assert {finding.status for finding in findings.values()} == {"PASS"}
    assert "Not yet implemented" not in " ".join(finding.note for finding in findings.values())
    assert "https://example.test/impressum" in findings["RDS-IPF-364"].note
    assert "https://example.test/datenschutz" in findings["RDS-IPF-367"].note


def test_ipf_analysis_fails_missing_live_impressum_and_privacy_pages():
    analysis = analyze_ipf_site(
        "https://example.test/",
        fetch=_fetcher({"https://example.test/": (200, "<main>Keine Pflichtlinks</main>")}),
    )
    findings = {finding.criterion: finding for finding in findings_from_ipf_analysis(analysis)}

    assert findings["RDS-IPF-364"].status == "FAIL"
    assert findings["RDS-IPF-365"].status == "FAIL"
    assert findings["RDS-IPF-366"].status == "FAIL"
    assert findings["RDS-IPF-367"].status == "FAIL"
    assert "kein impressum-link" in findings["RDS-IPF-364"].note.lower()
    assert "keine datenschutzerklärung" in findings["RDS-IPF-365"].note.lower()


def test_ipf_analysis_distinguishes_reachable_but_incomplete_pages():
    home = """
    <a href="/impressum">Impressum</a>
    <a href="/privacy">Privacy Policy</a>
    """

    analysis = analyze_ipf_site(
        "https://example.test/",
        fetch=_fetcher(
            {
                "https://example.test/": (200, home),
                "https://example.test/impressum": (200, "Impressum Example Learning GmbH"),
                "https://example.test/privacy": (200, "Privacy policy. We process data."),
            }
        ),
    )
    findings = {finding.criterion: finding for finding in findings_from_ipf_analysis(analysis)}

    assert findings["RDS-IPF-364"].status == "PASS"
    assert findings["RDS-IPF-365"].status == "PASS"
    assert findings["RDS-IPF-366"].status == "FAIL"
    assert findings["RDS-IPF-367"].status == "FAIL"
    assert "fehlend" in findings["RDS-IPF-366"].note.lower()
    assert "kontakt" in findings["RDS-IPF-366"].note.lower()
    assert "rechtsgrundlagen" in findings["RDS-IPF-367"].note.lower()


def test_cli_site_check_writes_ipf_urls_to_capture_and_report(tmp_path: Path, monkeypatch):
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
        lambda url: [CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS ok")],
    )
    monkeypatch.setattr(
        cli,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(
            source_url="https://example.test/",
            visited_urls=[
                "https://example.test/",
                "https://example.test/impressum",
                "https://example.test/datenschutz",
            ],
            impressum=LegalPageResult(
                kind="impressum",
                url="https://example.test/impressum",
                reachable=True,
                status_code=200,
                found_signals=["Anbieter/Identität", "Anschrift", "Kontakt"],
            ),
            privacy=LegalPageResult(
                kind="privacy",
                url="https://example.test/datenschutz",
                reachable=True,
                status_code=200,
                found_signals=[
                    "Verantwortlicher",
                    "DSB/Kontakt",
                    "Zwecke",
                    "Rechtsgrundlagen",
                    "Empfänger",
                    "Speicherdauer",
                    "Betroffenenrechte",
                ],
            ),
        ),
    )

    result = CliRunner().invoke(
        app,
        [
            "check",
            "--url",
            "https://example.test/",
            "--output",
            "ipfjob",
            "--md",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads((tmp_path / "results" / "ipfjob" / "result.json").read_text(encoding="utf-8"))
    by_code = {finding["criterion"]: finding for finding in payload["findings"]}
    assert by_code["RDS-IPF-364"]["status"] == "PASS"
    assert "https://example.test/impressum" in by_code["RDS-IPF-366"]["note"]
    capture = json.loads((tmp_path / "results" / "ipfjob" / "capture.json").read_text(encoding="utf-8"))
    assert capture["ipf"]["visited_urls"] == [
        "https://example.test/",
        "https://example.test/impressum",
        "https://example.test/datenschutz",
    ]
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "https://example.test/impressum" in report_text
    assert "https://example.test/datenschutz" in report_text
