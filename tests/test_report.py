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


def test_generate_pdf_writes_non_empty_report(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS 200")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test"})

    assert output.stat().st_size > 1000
