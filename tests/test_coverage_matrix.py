from __future__ import annotations

from collections import Counter
from pathlib import Path

from vidis_compliance.coverage_matrix import (
    DEFAULT_COVERAGE_HTML,
    DEFAULT_COVERAGE_JSON,
    LEGACY_FEATURE_AREAS,
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


def test_coverage_matrix_includes_required_legacy_gap_rows() -> None:
    matrix = build_coverage_matrix()
    feature_codes = {row["code"] for row in matrix["rows"] if row["kind"] == "legacy_feature"}

    assert set(LEGACY_FEATURE_AREAS) <= feature_codes
    for code in [
        "LEGACY-AGENT-LOGIN-PERSONAS",
        "LEGACY-SCREENSHOT-VISION",
        "LEGACY-API-AUTH-JOBS-ZIP",
        "LEGACY-FASTAPI-DOCUMENT-URLS",
        "LEGACY-RDS-SPE-370-MAPPING",
    ]:
        row = next(row for row in matrix["rows"] if row["code"] == code)
        assert row["new_platform_status"] in {"partial-migration", "not-migrated", "planned-gap"}
        assert row["known_limitations"]


def test_default_coverage_outputs_are_under_docs_results() -> None:
    assert DEFAULT_COVERAGE_JSON.as_posix().endswith("/docs/results/coverage_matrix.json")
    assert DEFAULT_COVERAGE_HTML.as_posix().endswith("/docs/results/coverage_matrix.html")


def test_write_coverage_matrix_outputs_html_and_json(tmp_path: Path) -> None:
    json_path = tmp_path / DEFAULT_COVERAGE_JSON.name
    html_path = tmp_path / DEFAULT_COVERAGE_HTML.name

    write_coverage_matrix(json_path=json_path, html_path=html_path)

    html = html_path.read_text(encoding="utf-8")
    assert "VIDIS Migration Coverage Matrix" in html
    assert "Old checker status" in html
    assert "RDS-SPE-370" in html
    assert json_path.exists()
