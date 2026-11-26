from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _open_api_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """The API refuses requests without configured keys; tests opt into the dev mode."""
    for name in (
        "VIDIS_API_KEYS",
        "VIDIS_API_KEY",
        "API_KEY",
        "VIDIS_ALLOWED_PATH_ROOTS",
        "GOOGLE_SA_JSON",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "VIDIS_LLM_DISABLED",
        "VIDIS_CRAWL_CACHE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    from vidis_compliance.util import llm

    llm._PROBE.clear()
    monkeypatch.setenv("VIDIS_AUTH_DISABLED", "1")
    monkeypatch.setenv("VIDIS_ALLOW_PRIVATE_TARGETS", "1")


@pytest.fixture(autouse=True)
def _no_document_discovery_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Document discovery would fetch the target site; tests that need it patch it."""
    from vidis_compliance import cli

    monkeypatch.setattr(
        cli,
        "discover_document_links",
        lambda url, wanted=(), **kwargs: {"found": {}, "missing": list(wanted), "searched": [url], "errors": []},
    )
