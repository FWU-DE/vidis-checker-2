from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vidis_compliance.cli import app
from vidis_compliance.sources.documents.analyze import analyze_documents, extract_text


runner = CliRunner()


def test_analyze_html_and_text_documents_maps_strong_evidence_to_vidis_findings(tmp_path: Path) -> None:
    privacy = tmp_path / "privacy.html"
    privacy.write_text(
        """
        <html><body>
          <h1>Datenschutzerklärung</h1>
          <p>Wir verarbeiten personenbezogene Daten ausschließlich zu den genannten Zwecken und gemäß DSGVO.</p>
          <p>Unser Datenschutzbeauftragter ist datenschutz@example.test.</p>
        </body></html>
        """,
        encoding="utf-8",
    )
    avv = tmp_path / "avv.txt"
    avv.write_text(
        """
        Auftragsverarbeitungsvertrag gemäß Art. 28 DSGVO.
        Nach Vertragsende werden personenbezogene Daten nach Wahl des Auftraggebers gelöscht oder zurückgegeben.
        Technische und organisatorische Maßnahmen (TOMs) inklusive Verschlüsselung und Zugriffskontrolle sichern die Verarbeitung.
        """,
        encoding="utf-8",
    )

    findings, capture = analyze_documents([privacy, avv])
    by_code = {finding.criterion: finding for finding in findings}

    assert by_code["RDS-DEV-380"].status == "PASS"
    assert "personenbezogene Daten" in by_code["RDS-DEV-380"].note
    assert by_code["RDS-DEV-381"].status == "PASS"
    assert "Vertragsende" in by_code["RDS-DEV-381"].note
    assert by_code["RDS-DEV-466"].status == "PASS"
    assert "TOM" in by_code["RDS-DEV-466"].note
    assert by_code["RDS-DSO-383"].status == "PASS"
    assert "datenschutz@example.test" in by_code["RDS-DSO-383"].note
    assert by_code["RDS-AGB-368"].status == "PASS"
    assert by_code["RDS-AGB-369"].status == "PASS"
    assert capture["documents"][0]["location"] == str(privacy)
    assert capture["evidence"]["RDS-DEV-381"]


def test_pdf_text_fallback_extracts_literal_strings_without_optional_pdf_dependency() -> None:
    pdf_bytes = b"%PDF-1.4\n1 0 obj<<>>stream\nBT (Auftragsverarbeitungsvertrag Art. 28 DSGVO) Tj ET\nendstream\nendobj\n%%EOF"

    text = extract_text(pdf_bytes, content_type="application/pdf", location="fixture.pdf")

    assert "Auftragsverarbeitungsvertrag Art. 28 DSGVO" in text


def test_cli_help_documents_document_options() -> None:
    result = runner.invoke(app, ["check", "--help"])

    assert result.exit_code == 0, result.output
    assert "--document" in result.output
    assert "--agb-url" in result.output
    assert "--privacy-url" in result.output
    assert "--avv-url" in result.output


def test_cli_check_document_inputs_outputs_document_capture_and_replaces_placeholders(tmp_path: Path, monkeypatch) -> None:
    document = tmp_path / "contract.txt"
    document.write_text(
        """
        Datenschutzerklärung: Personenbezogene Daten werden gemäß DSGVO verarbeitet.
        Datenschutzbeauftragter: dsb@example.test.
        AVV: Auftragsverarbeitungsvertrag nach Art. 28 DSGVO.
        Nach Vertragsende werden Daten gelöscht oder zurückgegeben.
        TOMs: Verschlüsselung, Zugriffskontrolle und sichere Datenverarbeitung.
        """,
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["check", "--document", str(document), "--output", "docjob"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads((tmp_path / "results" / "docjob" / "result.json").read_text(encoding="utf-8"))
    by_code = {finding["criterion"]: finding for finding in payload["findings"]}
    for code in ["RDS-AGB-368", "RDS-AGB-369", "RDS-DEV-380", "RDS-DEV-381", "RDS-DEV-466", "RDS-DSO-383"]:
        assert by_code[code]["note"] != "Not yet implemented"
    assert by_code["RDS-AGB-369"]["status"] == "PASS"
    assert (tmp_path / "results" / "docjob" / "document_capture.json").exists()
