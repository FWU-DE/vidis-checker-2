from __future__ import annotations

from pathlib import Path

from vidis_compliance.models import CheckFinding, JobResult
from vidis_compliance.report.markdown import generate_markdown
from vidis_compliance.report.pdf import generate_pdf


def test_generate_markdown_includes_criterion_text_evidence_and_raw_capture(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-CUC-371", status="FAIL", note="Tracker-Cookies: _ga")],
    )
    raw_capture = {"url": "https://example.test", "cookies": [{"name": "_ga"}]}
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "# VIDIS Prüfkriterien V0.2" in text
    assert "### RDS-CUC-371: Nicht essenzielle Cookies" in text
    assert "Das MUSS-Kriterium" in text
    assert "| Anzahl Cookies | 1 |" in text
    assert "## Anhang: Rohdaten der Erfassung" in text
    assert '"cookies"' in text


def test_generate_markdown_includes_ipf_evidence_urls(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-IPF-366",
                status="PASS",
                note="Impressum vollständig wirkend: https://example.test/impressum",
            )
        ],
    )
    raw_capture = {
        "url": "https://example.test/",
        "ipf": {
            "visited_urls": ["https://example.test/", "https://example.test/impressum"],
            "impressum_url": "https://example.test/impressum",
            "privacy_url": "https://example.test/datenschutz",
        },
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Impressum-URL | https://example.test/impressum |" in text
    assert "| Besuchte IPF-URLs | https://example.test/, https://example.test/impressum |" in text


def test_generate_markdown_lists_browser_signal_evidence_without_storage_values(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-CUC-375",
                status="MANUELL",
                note="Device-/Browser-Storage-APIs genutzt: indexedDB.open",
            ),
            CheckFinding(
                criterion="RDS-CUC-376",
                status="MANUELL",
                note="Browserfingerprinting-/Entropy-APIs genutzt: canvas.toDataURL",
            ),
        ],
    )
    raw_capture = {
        "browser_signals": {
            "device_storage": [{"api": "indexedDB.open", "count": 1}],
            "fingerprinting": [{"api": "canvas.toDataURL", "count": 2}],
        },
        "local_storage": {"sensitive": "large-secret-value"},
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Device-/Browser-Storage-APIs | indexedDB.open (1×) |" in text
    assert "| Fingerprinting-/Entropy-APIs | canvas.toDataURL (2×) |" in text
    assert "large-secret-value" not in text


def test_generate_pdf_writes_non_empty_report(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS 200")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test"})

    assert output.stat().st_size > 1000
