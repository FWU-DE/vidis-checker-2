# Platform architecture notes

## Goals

- Provide one CLI/server that can run code inspection, on-site/browser checks, document analysis, report generation, and API-based automation.
- Use `src/vidis_compliance/criteria/vidis_v0_2.yaml` as the canonical criteria registry.
- Keep user-facing documentation generated or maintained from the same platform concepts used by the CLI and API.

## Current platform areas

- `src/vidis_compliance/criteria/vidis_v0_2.yaml` — source of truth for active VIDIS criteria.
- `src/vidis_compliance/sources/site/` — browser/site crawl, transport, storage, cookies, screenshots, and visual review support.
- `src/vidis_compliance/sources/code/` — static source-code inspection.
- `src/vidis_compliance/sources/documents/` — AGB, Datenschutz, AVV, and related document extraction.
- `src/vidis_compliance/checks/` — mappings from captured signals to VIDIS findings.
- `src/vidis_compliance/report/` — Markdown/PDF report data and renderers.
- `src/vidis_compliance/server.py` — FastAPI automation surface.
- `docs/manual.html` — rollout-facing user manual.

## Documentation rule

When changing CLI flags, API endpoints, outputs, report content, criteria coverage, authentication, or automation flows, update `docs/manual.html` in the same change. Keep documentation free of local developer paths and internal project-history references.

## Open platform questions

- Confirm the final operational policy for API authentication and artifact retention.
- Decide where authenticated screenshot artifacts may be stored and whether they may be included in downloadable archives.
- Keep the coverage matrix explicit about manual-review criteria and not-yet-covered areas.
- `RDS-SPE-370` is present in the active registry as Sponsoring and should remain visible in unification/coverage outputs; its current automation path is Dokumentklassifikation with conservative manual fallback.
