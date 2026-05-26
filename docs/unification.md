# Unification plan

Goals
- Single CLI/server that can run both code-inspection and on-site checks.
- Canonical criteria registry in YAML; generate both the CLI logic and human docs from it.
- Backward-compatible import path for existing vidis-checker modules to minimize rewrite.

Mapping (old -> new)
- skills/vidis-check/SKILL.md -> docs/VIDIS_SKILL.md (operator guidance; non-executable)
- vidis-checker/src/models/vidis_criteria.py -> src/vidis_compliance/criteria/vidis_v0_2.yaml (source of truth)
- vidis-checker/src/classification/* -> src/vidis_compliance/checks/site/* (reused with thin adapters)
- future code-inspection (static) -> src/vidis_compliance/checks/code/*

Incremental wiring
1) Import criteria from vidis-checker into YAML (done, partial).
2) Wire site checks: cookies, ipf, encryption -> CLI check --url ...
3) Add report builder reusing ReportLab code from vidis-checker.
4) Add FastAPI endpoints that mirror the three-phase pipeline.
5) Implement code-inspection extractors (ripgrep-based + heuristics) mirroring SKILL.md guidance.

Open questions
- License alignment across repos.
- Azure/OpenAI provider config via env.
- Auth for server endpoints (Bearer like vidis-checker).
