from __future__ import annotations

from collections import Counter
from pathlib import Path

from vidis_compliance.coverage_matrix import (
    DEFAULT_COVERAGE_HTML,
    DEFAULT_COVERAGE_JSON,
    PLATFORM_GAP_AREAS,
    build_coverage_matrix,
    write_coverage_matrix,
)
from vidis_compliance.report.data import load_criteria


def test_coverage_matrix_lists_every_registry_criterion_exactly_once() -> None:
    matrix = build_coverage_matrix()
    registry_codes = set(load_criteria().items)
    criterion_rows = [row for row in matrix["rows"] if row["kind"] == "criterion"]

    counts = Counter(row["code"] for row in criterion_rows)

    assert set(counts) == registry_codes
    assert all(count == 1 for count in counts.values())
    assert len(criterion_rows) == len(registry_codes)


def test_coverage_matrix_includes_required_platform_gap_rows() -> None:
    matrix = build_coverage_matrix()
    feature_codes = {row["code"] for row in matrix["rows"] if row["kind"] == "platform_gap"}

    assert set(PLATFORM_GAP_AREAS) <= feature_codes
    for code in [
        "PLATFORM-AUTH-PERSONA-CRAWL",
        "PLATFORM-SCREENSHOT-VISION",
        "PLATFORM-API-AUTH-JOBS-ZIP",
        "PLATFORM-FASTAPI-DOCUMENT-URLS",
        "PLATFORM-RDS-SPE-370-STATUS",
    ]:
        row = next(row for row in matrix["rows"] if row["code"] == code)
        assert row["implementation_status"] in {"partial", "not implemented", "planned", "resolved"}
        assert row["known_limitations"]

    spe_row = next(row for row in matrix["rows"] if row["code"] == "PLATFORM-RDS-SPE-370-STATUS")
    assert spe_row["implementation_status"] == "partial"
    assert "document classifier" in spe_row["automation_level"]


def test_default_coverage_outputs_are_under_docs_results() -> None:
    assert DEFAULT_COVERAGE_JSON.as_posix().endswith("/docs/results/coverage_matrix.json")
    assert DEFAULT_COVERAGE_HTML.as_posix().endswith("/docs/results/coverage_matrix.html")


def test_write_coverage_matrix_outputs_html_and_json(tmp_path: Path) -> None:
    json_path = tmp_path / DEFAULT_COVERAGE_JSON.name
    html_path = tmp_path / DEFAULT_COVERAGE_HTML.name

    write_coverage_matrix(json_path=json_path, html_path=html_path)

    html = html_path.read_text(encoding="utf-8")
    assert "VIDIS Coverage Matrix" in html
    assert "Platform status" in html
    assert "RDS-SPE-370" in html
    assert json_path.exists()


def test_rds_cuc_453_coverage_documents_privacy_text_requirement() -> None:
    matrix = build_coverage_matrix()

    row = next(row for row in matrix["rows"] if row["code"] == "RDS-CUC-453")

    assert row["implementation_status"] == "partially automated"
    assert "target URL" in row["input_needed"]
    assert "document" in row["input_needed"].lower()
    assert "document_capture.json" in row["evidence_artifacts"]
    assert "Datenschutzerklärungstexte" in row["known_limitations"]


def test_rds_cuc_375_coverage_distinguishes_signal_collection_from_manual_decision() -> None:
    matrix = build_coverage_matrix()

    row = next(row for row in matrix["rows"] if row["code"] == "RDS-CUC-375")

    assert row["implementation_status"] == "partially automated"
    assert "automated signal collection" in row["automation_level"]
    assert "legal-purpose decision manual" in row["automation_level"]
    assert "IndexedDB/Cache/ServiceWorker" in row["known_limitations"]



def test_document_only_criteria_name_target_url_as_input() -> None:
    # documents.analysis finds AGB, privacy policy and AVV via the target URL.
    matrix = build_coverage_matrix()
    rows = {row["code"]: row for row in matrix["rows"]}

    for code in ["RDS-SPE-370", "RDS-AGB-368", "RDS-AGB-369", "PLATFORM-RDS-SPE-370-STATUS", "PLATFORM-FASTAPI-DOCUMENT-URLS"]:
        assert rows[code]["input_needed"].startswith("target URL"), code
