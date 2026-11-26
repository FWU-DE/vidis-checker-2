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
- vidis check --url https://example.com [--pages 8] [--pdf out/report.pdf] [--md out/report.md] [--ai-model provider:model]
- VIDIS_AGENT_USERNAME=user VIDIS_AGENT_PASSWORD='***' vidis check --url https://app.example.com --agentic --agent-vidis-portal 'Test Landesportal' [--agent-vidis-login-label 'Mit VIDIS einloggen'] [--agent-instruction 'Gehe auf Assistenten und prüfe die Übersicht'] --pages 10 --agent-task legal --agent-task student --agent-persona SuS --output auth-scan
- vidis check --document agb.html --document avv.pdf [--privacy-url https://example.com/datenschutz] [--agb-url https://example.com/agb] [--avv-url https://example.com/avv]
- vidis check --code-path /path/to/repo
- vidis-report --input job_id [--capture results/job_id/capture.json] [--pdf out/report.pdf] [--md out/report.md]
- vidis check --url https://example.com --check site.transport [--check site.legal_pages]  # only these checks
- vidis checks  # list check ids
- vidis serve  # API, see below

Cookie and storage classification
- Cookie/browser-storage checks use a bundled copy of the Open Cookie Database EDPB: https://github.com/jkwakman/Open-Cookie-Database/blob/master/open-cookie-database-edpb.json
- Update the bundled copy with `uv run python scripts/update_cookie_db.py`.

API automation
- `VIDIS_API_KEYS=key1,key2 uv run vidis serve --host 0.0.0.0 --port 8645` starts the API. Without keys, `vidis serve` only runs on 127.0.0.1 and is open there.
- Every `/jobs` endpoint requires `Authorization: Bearer <key>` or `X-API-Key: <key>`. Without configured keys the job endpoints answer 503 unless `VIDIS_AUTH_DISABLED=1`.
- `GET /discovery` (also `/.well-known/vidis-checks`) is public and lists every available check with its criteria and required inputs, plus endpoints and auth schemes. `/health`, `/criteria`, `/docs` and `/openapi.json` are public too.
- `POST /jobs` starts an async check with the same checks as `vidis check` and returns a status URL.
- `"checks": ["site.cookies", "site.transport"]` in `POST /jobs` runs only those checks; `POST /checks/<check_id>` starts a job for exactly one check (same body without `checks`). `GET /checks` lists the ids. Results then only hold the selected checks' criteria.
- A browser crawl of the same URL and page count is reused for 30 minutes (screenshots and their AI review included); `"crawl_max_age": 0` in a job (or `--crawl-max-age 0`) forces a fresh crawl.
- Optional AI screenshot review with Gemini on Vertex AI: set `GOOGLE_SA_JSON` (service-account key JSON), optionally `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `VIDIS_LLM_MODEL_STRONG`/`VIDIS_LLM_MODEL_FAST`. It adds evidence to reports and never changes PASS/FAIL. `GET /health` shows the LLM status under `llm`.
- `GET /status` (public) checks which configured models answer (cached 10 minutes, `?refresh=true` at most once a minute) and shows job counts and crawl-cache entries; `status` is `degraded` when no model answers.
- `GET /jobs?status=completed&limit=100&offset=0` lists persisted jobs without embedding full result payloads.
- `GET /jobs/<job_id>` returns job metadata, result, report links, and artifact links.
- Public screenshot evidence from site crawls is exposed as `screenshot_*` artifact links; screenshots from logged-in areas stay on the server.
- `POST /jobs/<job_id>/reports` creates `report.md` or `report.pdf` for completed jobs.
- `GET /jobs/<job_id>/archive.zip` downloads the bounded evidence package (`job.json`, `result.json`, allowed captures, and reports).
- Targets in private networks are refused (`VIDIS_ALLOW_PRIVATE_TARGETS=1` allows them); `VIDIS_ALLOWED_PATH_ROOTS` limits `code_path`/`document_paths` to given directories.

Deployment (Docker, Coolify)
- `VIDIS_API_KEYS="$(openssl rand -hex 32)" docker compose up -d --build` runs the API with Chromium on port 8645.
- Coolify: create an application with the Docker Compose build pack, set `VIDIS_API_KEYS`, and give the `vidis-checker` service a domain on port 8645. Results persist in the `vidis-results` volume.

Document checks
- `--document PATH` can be repeated for local HTML, text/Markdown, or PDF files.
- `--agb-url`, `--privacy-url`, and `--avv-url` fetch remote AGB, Datenschutz, and AVV documents.
- When document inputs are present, `vidis check` emits `results/<job_id>/document_capture.json` with extracted snippets for RDS-AGB-368, RDS-AGB-369, RDS-DEV-380, RDS-DEV-381, RDS-DEV-466, and RDS-DSO-383.
- Classification is conservative: PASS requires explicit document evidence, FAIL requires clear contradictions, otherwise the criterion remains MANUELL with an evidence-gap note.

Agentic persona crawl
- `--agentic` is opt-in and intended for authenticated/walled-garden applications where public deterministic scans miss logged-in legal pages or persona-specific student/teacher areas. It does not replace the normal deterministic website checks: cookie/storage/tracking/advertising/youth-protection/HTTPS/legal-page heuristics still run, and authenticated agent evidence is merged on top without downgrading existing PASS/FAIL results to generic MANUELL notes.
- Supported `--agent-task` values: `legal`, `student`, `teacher`, `register`, `logout`; repeat the flag to choose a subset, otherwise all tasks run.
- Credentials come from `--agent-username`/`--agent-password` or `VIDIS_AGENT_USERNAME`/`VIDIS_AGENT_PASSWORD`. Passwords and token-like fields are redacted from JSON artifacts and traces.
- Use `--agent-vidis-portal` or `VIDIS_AGENT_VIDIS_PORTAL` for VIDIS broker flows that require choosing a Landesportal/Schulportal such as `Test Landesportal` before username/password entry. The VIDIS/SSO start button is auto-detected from common labels (`VIDIS`, `Schulportal`, `Landesportal`, `SSO`); set `--agent-vidis-login-label` or `VIDIS_AGENT_VIDIS_LOGIN_LABEL` when a product uses a custom label.
- After login, agentic mode follows internal click paths from visible links, deduplicates URLs, and continues until `--pages` is reached where possible. Repeat `--agent-instruction` to prioritize natural-language navigation hints such as `Gehe auf Assistenten und prüfe die Übersicht`; hidden or non-clickable internal links can still be visited through link discovery/Goto. With `--agent-task legal`, the runner automatically tries common profile/user-menu legal paths such as profile, account, Impressum, and privacy; candidates are surfaced as report evidence for manual review.
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
