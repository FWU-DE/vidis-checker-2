VIDIS Compliance Suite (Unified)

Purpose
- One toolkit for vendors and FWU to check apps and websites against VIDIS Prüfkriterien (V0.2).
- Unifies two approaches:
  1) Code inspection (when source code is available)
  2) On-site/browser evaluation (when only the running site/app is accessible)

Outcomes
- Machine-readable JSON report per criterion with PASS | FAIL | MANUELL
- Human PDF report in German
- CLI for local use (vendors)
- FastAPI server for batch/automation (FWU)

Status
- Initial scaffold. Wiring existing modules from FWU-DE/skills and FWU-DE/vidis-checker in follow-up commits.

Quick start
- Python 3.12+
- uv (recommended): https://docs.astral.sh/uv/

Manual
- Open `docs/manual.html` in a browser for the full usage guide.

Commands
- vidis check --url https://example.com [--pages 8] [--pdf out/report.pdf] [--md out/report.md]
- vidis check --document agb.html --document avv.pdf [--privacy-url https://example.com/datenschutz] [--agb-url https://example.com/agb] [--avv-url https://example.com/avv]
- vidis check --code-path /path/to/repo
- vidis-report --input job_id [--capture results/job_id/capture.json] [--pdf out/report.pdf] [--md out/report.md]
- vidis serve  # FastAPI

Document checks
- `--document PATH` can be repeated for local HTML, text/Markdown, or PDF files.
- `--agb-url`, `--privacy-url`, and `--avv-url` fetch remote AGB, Datenschutz, and AVV documents.
- When document inputs are present, `vidis check` emits `results/<job_id>/document_capture.json` with extracted snippets for RDS-AGB-368, RDS-AGB-369, RDS-DEV-380, RDS-DEV-381, RDS-DEV-466, and RDS-DSO-383.
- Classification is conservative: PASS requires explicit document evidence, FAIL requires clear contradictions, otherwise the criterion remains MANUELL with an evidence-gap note.

Structure
- src/vidis_compliance/
  - criteria/vidis_v0_2.yaml           # Canonical criteria registry
  - models.py                           # Pydantic models for criteria and results
  - sources/
    - site/                             # Crawl + capture (browser-use/Playwright)
    - code/                             # Static/code inspection extractors
  - checks/                             # Mappings from criteria -> signals
  - report/                             # PDF/HTML report builders
  - cli.py                              # Typer-based CLI
  - server.py                           # FastAPI wrapper
- docs/
  - unification.md                      # Mapping old -> new
  - VIDIS_SKILL.md                      # Imported skill reference for operators

License
- MIT (see LICENSE).