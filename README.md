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
- Unified toolkit for VIDIS-oriented website, source-code, document, report, and API automation workflows.

Quick start
- Python 3.12+
- uv (recommended): https://docs.astral.sh/uv/

Manual
- Open `docs/manual.html` in a browser for the full usage guide.

Commands
- vidis check --url https://example.com [--pages 8] [--pdf out/report.pdf] [--md out/report.md]
- VIDIS_AGENT_USERNAME=user VIDIS_AGENT_PASSWORD='***' vidis check --url https://app.example.com --agentic --agent-task legal --agent-task student --agent-persona SuS --output auth-scan
- vidis check --document agb.html --document avv.pdf [--privacy-url https://example.com/datenschutz] [--agb-url https://example.com/agb] [--avv-url https://example.com/avv]
- vidis check --code-path /path/to/repo
- vidis-report --input job_id [--capture results/job_id/capture.json] [--pdf out/report.pdf] [--md out/report.md]
- vidis serve  # FastAPI

Cookie and storage classification
- Cookie/browser-storage checks use a bundled copy of the Open Cookie Database EDPB: https://github.com/jkwakman/Open-Cookie-Database/blob/master/open-cookie-database-edpb.json
- Update the bundled copy with `uv run python scripts/update_cookie_db.py`.

API automation
- `uv run vidis serve --host 127.0.0.1 --port 8645` starts the FastAPI server.
- Local development is open by default. Set `VIDIS_API_KEY` to require `Authorization: Bearer ***` on every endpoint.
- `POST /jobs` starts an async check and returns a status URL.
- `GET /jobs?status=completed&limit=100&offset=0` lists persisted jobs without embedding full result payloads.
- `GET /jobs/<job_id>` returns job metadata, result, report links, and artifact links.
- Public screenshot evidence from site crawls is exposed as safe `screenshot_*` artifact links; authenticated/local-only screenshots stay on disk and are only referenced for manual review.
- `POST /jobs/<job_id>/reports` creates `report.md` or `report.pdf` for completed jobs.
- `GET /jobs/<job_id>/archive.zip` downloads the bounded evidence package (`job.json`, `result.json`, allowed captures, and reports) while excluding arbitrary files/secrets.

Document checks
- `--document PATH` can be repeated for local HTML, text/Markdown, or PDF files.
- `--agb-url`, `--privacy-url`, and `--avv-url` fetch remote AGB, Datenschutz, and AVV documents.
- When document inputs are present, `vidis check` emits `results/<job_id>/document_capture.json` with extracted snippets for RDS-AGB-368, RDS-AGB-369, RDS-DEV-380, RDS-DEV-381, RDS-DEV-466, and RDS-DSO-383.
- Classification is conservative: PASS requires explicit document evidence, FAIL requires clear contradictions, otherwise the criterion remains MANUELL with an evidence-gap note.

Agentic persona crawl
- `--agentic` is opt-in and intended for authenticated/walled-garden applications where public deterministic scans miss logged-in legal pages or persona-specific student/teacher areas.
- Supported `--agent-task` values: `legal`, `student`, `teacher`, `register`, `logout`; repeat the flag to choose a subset, otherwise all tasks run.
- Credentials come from `--agent-username`/`--agent-password` or `VIDIS_AGENT_USERNAME`/`VIDIS_AGENT_PASSWORD`. Passwords and token-like fields are redacted from JSON artifacts and traces.
- Outputs are written to `results/<job_id>/agent/` (`agent_capture.json`, `step_result.jsonl`, `screenshots/`, `pdfs/`) and a safe summary is exposed as `results/<job_id>/agent_capture.json` / FastAPI artifact `agent_capture_json`.

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
  - unification.md                      # Platform architecture notes
  - VIDIS_SKILL.md                      # Imported skill reference for operators

License
- MIT (see LICENSE).
