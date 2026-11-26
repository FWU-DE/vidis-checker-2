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
        Sponsoring und wirtschaftliche Unterstützer werden transparent gekennzeichnet und offengelegt.
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
    assert by_code["RDS-SPE-370"].status == "PASS"
    assert "Sponsoring" in by_code["RDS-SPE-370"].note
    assert capture["documents"][0]["location"] == str(privacy)
    assert capture["evidence"]["RDS-DEV-381"]
    assert capture["evidence"]["RDS-SPE-370"]


def test_analyze_documents_flags_undisclosed_sponsoring_for_rds_spe_370(tmp_path: Path) -> None:
    terms = tmp_path / "terms.txt"
    terms.write_text(
        """
        Dieses Lernangebot enthält gesponserte Inhalte und Produktplatzierungen.
        Sponsoren und wirtschaftliche Interessen werden gegenüber Nutzenden nicht offengelegt.
        """,
        encoding="utf-8",
    )

    findings, _capture = analyze_documents([terms])
    by_code = {finding.criterion: finding for finding in findings}

    assert by_code["RDS-SPE-370"].status == "FAIL"
    assert "nicht offengelegt" in by_code["RDS-SPE-370"].note


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
    for code in ["RDS-AGB-368", "RDS-AGB-369", "RDS-SPE-370", "RDS-DEV-380", "RDS-DEV-381", "RDS-DEV-466", "RDS-DSO-383"]:
        assert by_code[code]["check"] is not None and by_code[code]["reason"] not in {"not_automated", "missing_input"}
    assert by_code["RDS-AGB-369"]["status"] == "PASS"
    assert (tmp_path / "results" / "docjob" / "document_capture.json").exists()


def test_rds_spe_370_is_in_registry_and_coverage_matrix() -> None:
    from vidis_compliance.cli import load_criteria
    from vidis_compliance.coverage_matrix import build_coverage_matrix

    criteria = load_criteria()
    matrix = build_coverage_matrix()
    criterion_row = next(row for row in matrix["rows"] if row["code"] == "RDS-SPE-370")

    assert "RDS-SPE-370" in criteria.items
    assert criteria.items["RDS-SPE-370"].name == "Sponsoring"
    assert criterion_row["new_platform_status"] == "automated"
    assert "document_capture.json" in criterion_row["evidence_artifacts"]
