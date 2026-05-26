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

Commands (planned)
- vidis check --url https://example.com [--login USER:PASS] [--pages 10]
- vidis check-code --path /path/to/repo
- vidis report --input job_id --pdf out/report.pdf
- vidis serve  # FastAPI

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
- TBD with FWU (MIT/Apache-2 recommended).