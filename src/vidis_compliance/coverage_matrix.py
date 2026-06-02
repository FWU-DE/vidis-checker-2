from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report.data import load_criteria

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COVERAGE_JSON = REPO_ROOT / "docs" / "results" / "coverage_matrix.json"
DEFAULT_COVERAGE_HTML = REPO_ROOT / "docs" / "results" / "coverage_matrix.html"

COLUMNS = [
    "code",
    "name",
    "old_checker_status",
    "new_platform_status",
    "input_needed",
    "automation_level",
    "evidence_artifacts",
    "cli_api_availability",
    "known_limitations",
]

LEGACY_FEATURE_AREAS: dict[str, dict[str, str]] = {
    "LEGACY-AGENT-LOGIN-PERSONAS": {
        "name": "Agent login and persona based flows",
        "old_checker_status": "available in legacy checker/browser agent concept",
        "new_platform_status": "not-migrated",
        "input_needed": "Human-operated credentials, role/persona definitions, tenant-specific login steps.",
        "automation_level": "manual gap",
        "evidence_artifacts": "None yet; future artifact should capture authenticated journey transcript.",
        "cli_api_availability": "No CLI/API endpoint currently accepts login personas.",
        "known_limitations": "Authenticated checks are intentionally not automated until credential handling, consent, and replay safety are designed.",
    },
    "LEGACY-SCREENSHOT-VISION": {
        "name": "Screenshot and visual inspection",
        "old_checker_status": "partially available through browser screenshots/vision review",
        "new_platform_status": "partial-migration",
        "input_needed": "Target URL and pages; optional visual review prompt is still external.",
        "automation_level": "browser capture automated, vision judgement manual",
        "evidence_artifacts": "capture.json contains DOM/network/browser signals; screenshots are not yet first-class report artifacts.",
        "cli_api_availability": "CLI site crawl exists; API jobs exist for submitted checks, but no dedicated screenshot export route.",
        "known_limitations": "Visual-only claims such as banner prominence or deceptive layouts still require human review.",
    },
    "LEGACY-API-AUTH-JOBS-ZIP": {
        "name": "API authentication, job list, and ZIP artifact download",
        "old_checker_status": "legacy operator workflow expected protected API/artifact access",
        "new_platform_status": "partial-migration",
        "input_needed": "API deployment policy, auth mechanism, artifact retention, and ZIP manifest requirements.",
        "automation_level": "job creation automated, ops hardening open",
        "evidence_artifacts": "result.json, capture.json, code_capture.json, document_capture.json, report PDFs/Markdown.",
        "cli_api_availability": "FastAPI async job endpoints exist; auth, list filtering, and ZIP bundle endpoint are not complete.",
        "known_limitations": "Do not expose the current API beyond trusted local/internal contexts without auth and artifact access controls.",
    },
    "LEGACY-FASTAPI-DOCUMENT-URLS": {
        "name": "FastAPI document URL ingestion",
        "old_checker_status": "document URLs were part of the migration requirement set",
        "new_platform_status": "partial-migration",
        "input_needed": "AGB, privacy, and AVV URLs or local server-side document files.",
        "automation_level": "CLI/API automated for local documents and HTTP(S) document URLs",
        "evidence_artifacts": "document_capture.json and criterion notes from document analysis.",
        "cli_api_availability": "CLI supports --agb-url, --privacy-url, --avv-url, and --document; FastAPI accepts document_paths plus agb_url, privacy_url, and avv_url.",
        "known_limitations": "Remote document fetches are limited to HTTP(S); local document paths must exist on the API server.",
    },
    "LEGACY-RDS-SPE-370-MAPPING": {
        "name": "RDS-SPE-370 criterion mapping",
        "old_checker_status": "legacy/spec comparison identified a mapping question",
        "new_platform_status": "partial-migration",
        "input_needed": "AGB/privacy/AVV document files or URLs.",
        "automation_level": "conservative document classifier plus manual fallback",
        "evidence_artifacts": "result.json, Markdown/PDF report, document_capture.json.",
        "cli_api_availability": "RDS-SPE-370 is now in the active registry and emitted by document analysis for CLI/API result output.",
        "known_limitations": "PASS/FAIL requires explicit Sponsoring/economic-interest evidence; absence remains MANUELL because the old checker also relied on semantic AGB review.",
    },
}

_AUTOMATED_BY_SITE = {
    "ITS-ENC-359",
    "ITS-ENC-360",
    "ITS-ENC-361",
    "RDS-CUC-371",
    "RDS-CUC-372",
    "RDS-CUC-373",
    "RDS-CUC-374",
    "RDS-CUC-375",
    "RDS-CUC-376",
    "RDS-CUC-377",
    "RDS-IPF-364",
    "RDS-IPF-365",
    "RDS-IPF-366",
    "RDS-IPF-367",
    "RDS-VIN-354",
    "RDS-WER-384",
    "RDS-WER-385",
}
_AUTOMATED_BY_CODE = {
    "RDS-CDN-379",
    "RDS-CUC-371",
    "RDS-CUC-372",
    "RDS-CUC-373",
    "RDS-CUC-374",
    "RDS-CUC-375",
    "RDS-CUC-376",
    "RDS-CUC-377",
    "RDS-DEV-380",
    "RDS-IPF-364",
    "RDS-IPF-365",
}
_AUTOMATED_BY_DOCUMENTS = {
    "RDS-AGB-368",
    "RDS-AGB-369",
    "RDS-DEV-380",
    "RDS-DEV-381",
    "RDS-DEV-466",
    "RDS-DSO-383",
    "RDS-SPE-370",
}
_MANUAL_OVERLAY = {
    "RDS-CUC-453": "Datenschutzerklärung muss weiterhin gegen reale Cookies/Consent-Texte abgeglichen werden.",
    "RDS-CUC-375": "Device-storage signals können nur Indizien liefern; Zweckbindung bleibt reviewpflichtig.",
    "RDS-CUC-376": "Fingerprinting-Signale sind technisch erkennbar, Rechts-/Zweckbewertung bleibt reviewpflichtig.",
    "RDS-CUC-377": "Nicht-pädagogischer Zweck ist nur mit Produktkontext sicher bewertbar.",
}


def build_coverage_matrix() -> dict[str, Any]:
    criteria = load_criteria()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows: list[dict[str, str]] = []
    for code, criterion in criteria.items.items():
        sources = _sources_for(code)
        rows.append(
            {
                "kind": "criterion",
                "code": code,
                "name": criterion.name,
                "area": criterion.area,
                "old_checker_status": _old_checker_status(code),
                "new_platform_status": _new_platform_status(code, sources),
                "input_needed": _input_needed(code, sources),
                "automation_level": _automation_level(code, sources),
                "evidence_artifacts": _evidence_artifacts(code, sources),
                "cli_api_availability": _cli_api_availability(code, sources),
                "known_limitations": _known_limitations(code, sources),
            }
        )
    for code, row in LEGACY_FEATURE_AREAS.items():
        rows.append({"kind": "legacy_feature", "code": code, "area": "legacy", **row})
    return {
        "title": "VIDIS Migration Coverage Matrix",
        "generated_at": generated_at,
        "criteria_registry": "src/vidis_compliance/criteria/vidis_v0_2.yaml",
        "columns": COLUMNS,
        "rows": rows,
    }


def write_coverage_matrix(
    *,
    json_path: Path = DEFAULT_COVERAGE_JSON,
    html_path: Path = DEFAULT_COVERAGE_HTML,
) -> tuple[Path, Path]:
    matrix = build_coverage_matrix()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_coverage_html(matrix), encoding="utf-8")
    return json_path, html_path


def render_coverage_html(matrix: dict[str, Any]) -> str:
    rows = matrix["rows"]
    criterion_count = sum(1 for row in rows if row["kind"] == "criterion")
    legacy_count = sum(1 for row in rows if row["kind"] == "legacy_feature")
    body_rows = "\n".join(_render_row(row) for row in rows)
    generated = html.escape(str(matrix["generated_at"]))
    return f"""<!doctype html>
<html lang=\"de\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>VIDIS Migration Coverage Matrix</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#0f172a; --panel:#111827; --text:#e5e7eb; --muted:#94a3b8; --line:#334155; --accent:#38bdf8; }}
    body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; background:var(--bg); color:var(--text); }}
    header, main {{ max-width: 1280px; margin: 0 auto; padding: 28px 20px; }}
    h1 {{ margin: 0 0 8px; font-size: clamp(2rem, 4vw, 4rem); }}
    .lead {{ color: var(--muted); max-width: 920px; }}
    .summary {{ display:flex; flex-wrap:wrap; gap:12px; margin:20px 0; }}
    .pill {{ border:1px solid var(--line); border-radius:999px; padding:8px 12px; background:rgba(56,189,248,.10); }}
    .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:18px; background:var(--panel); }}
    table {{ width:100%; border-collapse:collapse; min-width:1300px; }}
    th, td {{ border-bottom:1px solid var(--line); padding:10px; text-align:left; vertical-align:top; font-size:.92rem; }}
    th {{ position:sticky; top:0; background:#0f172a; color:var(--accent); z-index:1; }}
    tr.kind-legacy_feature {{ background:rgba(245,158,11,.10); }}
    code {{ color:#bae6fd; white-space:nowrap; }}
    .muted {{ color:var(--muted); }}
    @media (prefers-color-scheme: light) {{ :root {{ --bg:#f8fafc; --panel:#ffffff; --text:#0f172a; --muted:#475569; --line:#cbd5e1; }} th {{ background:#e0f2fe; }} code {{ color:#0369a1; }} }}
  </style>
</head>
<body>
  <header>
    <p class=\"muted\">Generated {generated}</p>
    <h1>VIDIS Migration Coverage Matrix</h1>
    <p class=\"lead\">Operator-facing old-vs-new coverage inventory for every active VIDIS criterion and migrated legacy feature area. The JSON sibling file is machine-readable; this page is the easy-to-open dashboard.</p>
    <div class=\"summary\">
      <span class=\"pill\">{criterion_count} registry criteria</span>
      <span class=\"pill\">{legacy_count} legacy feature/gap rows</span>
      <span class=\"pill\">Source: src/vidis_compliance/criteria/vidis_v0_2.yaml</span>
    </div>
  </header>
  <main>
    <div class=\"table-wrap\">
      <table aria-label=\"VIDIS migration coverage matrix\">
        <thead><tr>{''.join(f'<th>{html.escape(_heading(column))}</th>' for column in COLUMNS)}</tr></thead>
        <tbody>
{body_rows}
        </tbody>
      </table>
    </div>
  </main>
</body>
</html>
"""


def _render_row(row: dict[str, str]) -> str:
    cells = []
    for column in COLUMNS:
        value = html.escape(str(row.get(column, "—")))
        if column == "code":
            value = f"<code>{value}</code>"
        cells.append(f"<td>{value}</td>")
    kind = html.escape(row.get("kind", "row"))
    return f"          <tr class=\"kind-{kind}\">{''.join(cells)}</tr>"


def _heading(column: str) -> str:
    return {
        "code": "Code/area",
        "name": "Name",
        "old_checker_status": "Old checker status",
        "new_platform_status": "New platform status",
        "input_needed": "Input needed",
        "automation_level": "Automation level",
        "evidence_artifacts": "Evidence artifacts",
        "cli_api_availability": "CLI/API availability",
        "known_limitations": "Known limitations",
    }[column]


def _sources_for(code: str) -> set[str]:
    sources = set()
    if code in _AUTOMATED_BY_SITE:
        sources.add("site")
    if code in _AUTOMATED_BY_CODE:
        sources.add("code")
    if code in _AUTOMATED_BY_DOCUMENTS:
        sources.add("documents")
    return sources


def _old_checker_status(code: str) -> str:
    if code.startswith("RDS-CUC"):
        return "migrated/extended from legacy browser and cookie checks"
    if code.startswith("ITS-ENC"):
        return "extended beyond legacy with live transport/TLS checks"
    if code.startswith("RDS-IPF"):
        return "extended beyond legacy with live legal-page discovery"
    if code.startswith(("RDS-AGB", "RDS-DEV", "RDS-DSO")):
        return "new document-analysis coverage from migration gap list"
    if code == "RDS-SPE-370":
        return "migrated from legacy terms-of-use/AGB semantic check"
    if code.startswith(("RDS-WER", "RDS-VIN")):
        return "new site-signal coverage from migration gap list"
    return "covered as registry/manual inventory item"


def _new_platform_status(code: str, sources: set[str]) -> str:
    if not sources:
        return "manual-inventory"
    if code in _MANUAL_OVERLAY:
        return "partially automated"
    return "automated"


def _input_needed(code: str, sources: set[str]) -> str:
    needed = []
    if "site" in sources:
        needed.append("target URL")
    if "code" in sources:
        needed.append("source-code path")
    if "documents" in sources:
        needed.append("AGB/privacy/AVV document files or URLs")
    if not needed:
        return "Human assessment and product documentation."
    if code in _MANUAL_OVERLAY:
        needed.append("human context review")
    return ", ".join(needed) + "."


def _automation_level(code: str, sources: set[str]) -> str:
    if not sources:
        return "manual"
    if code in _MANUAL_OVERLAY:
        return "automated signal collection plus manual decision"
    return "fully automated signal/check result for supplied inputs"


def _evidence_artifacts(code: str, sources: set[str]) -> str:
    artifacts = ["result.json", "Markdown/PDF report"]
    if "site" in sources:
        artifacts.append("capture.json")
    if "code" in sources:
        artifacts.append("code_capture.json")
    if "documents" in sources:
        artifacts.append("document_capture.json")
    return ", ".join(artifacts) + "."


def _cli_api_availability(code: str, sources: set[str]) -> str:
    parts = []
    if sources:
        parts.append("CLI: vidis check")
        parts.append("reports: vidis-report report")
        parts.append("API: FastAPI job endpoints for async runs")
    else:
        parts.append("CLI/API emit MANUELL fallback when no automated source is wired")
    if "documents" in sources:
        parts.append("document URL/file inputs available in CLI")
    return "; ".join(parts) + "."


def _known_limitations(code: str, sources: set[str]) -> str:
    if code in _MANUAL_OVERLAY:
        return _MANUAL_OVERLAY[code]
    if not sources:
        return "No automated detector is wired; buyer/operator must review external evidence."
    if "documents" in sources:
        return "Text-pattern analysis is evidence-oriented and can miss semantic/legal nuance."
    if "site" in sources:
        return "Network/browser checks depend on public reachability and the captured unauthenticated page state."
    return "Static inspection can miss dynamically loaded behavior and runtime configuration."


if __name__ == "__main__":
    json_out, html_out = write_coverage_matrix()
    print(json_out)
    print(html_out)
