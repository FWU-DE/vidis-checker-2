from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vidis_compliance import server
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.sources.site import crawl_cache, vision
from vidis_compliance.sources.site.crawl import PageCapture
from vidis_compliance.util import llm

FAKE_SA = json.dumps({"type": "service_account", "project_id": "demo-project", "client_email": "x@demo.iam.gserviceaccount.com"})


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    return TestClient(server.app)


@pytest.fixture
def crawls(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    calls: list[dict] = []

    def fake_crawl(url, pages=5, headless=True, screenshot_dir=None):
        calls.append({"url": url, "pages": pages})
        shots = []
        if screenshot_dir is not None:
            Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
            path = Path(screenshot_dir) / "page-1.png"
            path.write_bytes(b"\x89PNG fake")
            shots.append({"label": "page-1", "url": url, "filename": "page-1.png", "path": str(path)})
        return PageCapture(url=url, cookies=[], local_storage={}, session_storage={}, scripts=[], requests=[], screenshots=shots)

    monkeypatch.setattr(server.cli_module, "crawl", fake_crawl)
    monkeypatch.setattr(server.cli_module, "check_site_transport", lambda url: [])
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(source_url=url, visited_urls=[], impressum=LegalPageResult(kind="impressum"), privacy=LegalPageResult(kind="privacy")),
    )
    return calls


def _run(client: TestClient, body: dict) -> dict:
    response = client.post("/jobs", json=body)
    assert response.status_code == 202, response.text
    job_id = response.json()["id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        payload = client.get(f"/jobs/{job_id}").json()
        if payload["status"] in {"completed", "failed"}:
            assert payload["status"] == "completed", payload.get("error")
            return payload
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def _capture(tmp_path: Path, job_id: str) -> dict:
    return json.loads((tmp_path / "results" / job_id / "capture.json").read_text(encoding="utf-8"))


def test_single_checks_reuse_one_crawl(client: TestClient, crawls: list, tmp_path: Path) -> None:
    first = _run(client, {"target_url": "https://app.example.test", "checks": ["site.cookies"]})
    second = _run(client, {"target_url": "https://app.example.test", "checks": ["site.advertising"]})

    assert len(crawls) == 1
    assert _capture(tmp_path, first["id"])["crawl"]["cached"] is False
    cached = _capture(tmp_path, second["id"])
    assert cached["crawl"]["cached"] is True
    assert cached["crawl"]["age_seconds"] >= 0
    assert (tmp_path / "results" / second["id"] / "screenshots" / "page-1.png").is_file()
    assert "screenshot_page_1" in second["artifacts"]


def test_crawl_max_age_zero_forces_a_fresh_crawl(client: TestClient, crawls: list) -> None:
    _run(client, {"target_url": "https://app.example.test", "checks": ["site.cookies"]})
    _run(client, {"target_url": "https://app.example.test", "checks": ["site.cookies"], "crawl_max_age": 0})

    assert len(crawls) == 2


def test_cache_is_keyed_by_url_and_pages_and_expires(client: TestClient, crawls: list, tmp_path: Path) -> None:
    _run(client, {"target_url": "https://app.example.test", "pages": 2, "checks": ["site.cookies"]})
    _run(client, {"target_url": "https://app.example.test", "pages": 3, "checks": ["site.cookies"]})
    _run(client, {"target_url": "https://other.example.test", "pages": 2, "checks": ["site.cookies"]})
    assert len(crawls) == 3

    entry = tmp_path / "results" / ".crawl-cache" / crawl_cache.cache_key("https://app.example.test/", 2)
    meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
    meta["created"] -= 3600
    (entry / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    _run(client, {"target_url": "https://app.example.test", "pages": 2, "checks": ["site.cookies"]})
    assert len(crawls) == 4


def test_crawl_max_age_is_validated(client: TestClient, crawls: list) -> None:
    assert client.post("/jobs", json={"target_url": "https://app.example.test", "crawl_max_age": -1}).status_code == 422
    assert client.post("/jobs", json={"target_url": "https://app.example.test", "crawl_max_age": 86401}).status_code == 422
    _run(client, {"target_url": "https://app.example.test", "checks": ["site.cookies"]})
    response = client.post("/checks/site.cookies", json={"target_url": "https://app.example.test", "crawl_max_age": 0})
    assert response.status_code == 202
    deadline = time.monotonic() + 5
    while client.get(f"/jobs/{response.json()['id']}").json()["status"] not in {"completed", "failed"}:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert len(crawls) == 2


def test_cache_dir_is_not_listed_as_a_job(client: TestClient, crawls: list) -> None:
    _run(client, {"target_url": "https://app.example.test", "checks": ["site.cookies"]})

    assert client.get("/jobs").json()["total"] == 1


def test_health_reports_llm_status_without_secrets(client: TestClient, monkeypatch) -> None:
    assert client.get("/health").json()["llm"]["configured"] is False

    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    status = client.get("/health").json()["llm"]
    assert status["configured"] is True
    assert status["provider"] == "vertex"
    assert status["tasks"]["screenshot_review"] == llm.DEFAULT_MODELS["strong"]
    assert "x@demo" not in json.dumps(status)
    assert client.get("/discovery").json()["llm"]["configured"] is True

    monkeypatch.setenv("VIDIS_LLM_MODEL_STRONG", "gemini-custom-pro")
    assert client.get("/health").json()["llm"]["tasks"]["screenshot_review"] == "gemini-custom-pro"
    monkeypatch.setenv("VIDIS_LLM_DISABLED", "1")
    assert client.get("/health").json()["llm"]["configured"] is False


def test_strong_model_falls_back_to_fast_when_missing(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    used: list[str] = []
    body = {"candidates": [{"content": {"parts": [{"text": '{"status": "PASS", "note": "ok"}'}]}}]}

    def fake_post(config, model, payload, method="generateContent"):
        used.append(model)
        if model == config.models["strong"]:
            return httpx.Response(404)
        return httpx.Response(200, json=body)

    monkeypatch.setattr(llm, "_post", fake_post)
    result = llm.generate_json("x", task="screenshot_review")

    assert used == [llm.DEFAULT_MODELS["strong"], llm.DEFAULT_MODELS["fast"]]
    assert result["_model"] == llm.DEFAULT_MODELS["fast"]


def test_screenshot_provider_sanitises_model_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    shot = tmp_path / "page-1.png"
    shot.write_bytes(b"\x89PNG fake")
    monkeypatch.setattr(
        llm,
        "generate_json",
        lambda *a, **k: {"status": "fail", "note": "Werbebanner\n oben  rechts", "criterion_suggestions": ["RDS-WER-384", "EVIL-1"], "_model": "gemini-x"},
    )

    provider = vision.gemini_screenshot_provider()
    assert provider is not None
    review = vision.review_screenshots([{"label": "p1", "path": str(shot), "url": "https://a.test"}], provider=provider)[0]

    assert review["status"] == "FAIL"
    assert review["criterion_suggestions"] == ["RDS-WER-384"]
    assert review["note"].startswith("Werbebanner oben rechts")
    assert review["model"] == "gemini-x"


def test_screenshot_provider_errors_and_private_shots_stay_manual(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    shot = tmp_path / "page-1.png"
    shot.write_bytes(b"\x89PNG fake")
    sent: list = []

    def failing(*a, **k):
        sent.append(k)
        raise llm.LlmError("Vertex AI answered HTTP 500")

    monkeypatch.setattr(llm, "generate_json", failing)
    provider = vision.gemini_screenshot_provider()
    reviews = vision.review_screenshots(
        [{"label": "p1", "path": str(shot)}, {"label": "login", "path": str(shot), "authenticated": True, "local_only": True}],
        provider=provider,
    )

    assert [r["status"] for r in reviews] == ["MANUELL", "MANUELL"]
    assert "HTTP 500" in reviews[0]["note"]
    assert len(sent) == 1


def test_vision_reviews_are_cached_with_the_crawl(client: TestClient, crawls: list, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    calls: list = []

    def fake_generate(*a, **k):
        calls.append(k.get("task"))
        return {"status": "MANUELL", "note": "nichts Auffälliges", "criterion_suggestions": [], "_model": "gemini-x"}

    monkeypatch.setattr(llm, "generate_json", fake_generate)
    first = _run(client, {"target_url": "https://app.example.test", "checks": ["site.advertising"]})
    second = _run(client, {"target_url": "https://app.example.test", "checks": ["site.youth_protection"]})

    assert calls == ["screenshot_review"]
    for job in (first, second):
        capture = _capture(tmp_path, job["id"])
        assert capture["vision_reviews"][0]["model"] == "gemini-x"
        assert any(entry.get("model") == "gemini-x" for entry in capture.get("ai_models", []))


def test_checks_without_visual_criteria_do_not_call_the_model(client: TestClient, crawls: list, monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    monkeypatch.setattr(llm, "generate_json", lambda *a, **k: pytest.fail("model must not be called"))

    _run(client, {"target_url": "https://app.example.test", "checks": ["site.fingerprinting"]})


def _fake_vertex(monkeypatch, missing: set[str] | None = None) -> list[str]:
    monkeypatch.setenv("GOOGLE_SA_JSON", FAKE_SA)
    calls: list[str] = []

    def fake_post(config, model, payload, method="generateContent"):
        assert method == "countTokens", "status checks must not generate content"
        assert "generationConfig" not in payload
        calls.append(model)
        return httpx.Response(404 if model in (missing or set()) else 200, json={})

    monkeypatch.setattr(llm, "_post", fake_post)
    return calls


def test_status_without_llm(client: TestClient) -> None:
    payload = client.get("/status").json()

    assert payload["status"] == "ok"
    assert payload["llm"] == {"configured": False, "disabled": False}
    assert payload["jobs"]["queued"] == 0
    assert payload["crawl_cache"]["entries"] == 0


def test_status_lists_available_models_and_caches_the_check(client: TestClient, monkeypatch) -> None:
    calls = _fake_vertex(monkeypatch)

    first = client.get("/status").json()
    second = client.get("/status").json()

    models = first["llm"]["availability"]["models"]
    assert set(models) == set(llm.DEFAULT_MODELS.values())
    assert all(entry["available"] for entry in models.values())
    assert models[llm.DEFAULT_MODELS["strong"]]["tiers"] == ["strong"]
    assert sorted(calls) == sorted(llm.DEFAULT_MODELS.values())
    assert second["llm"]["availability"] == first["llm"]["availability"]
    assert len(calls) == 2
    assert "_checked" not in json.dumps(first)
    assert "x@demo" not in json.dumps(first)

    client.get("/status?refresh=true")
    assert len(calls) == 2  # forced refresh is rate-limited
    llm._PROBE["_checked"] -= llm.PROBE_MIN_INTERVAL_SECONDS + 1
    client.get("/status?refresh=true")
    assert len(calls) == 4


def test_health_shows_last_check_but_never_calls_the_model(client: TestClient, monkeypatch) -> None:
    calls = _fake_vertex(monkeypatch)

    assert "availability" not in client.get("/health").json()["llm"]
    assert calls == []
    client.get("/status")
    health = client.get("/health").json()["llm"]
    assert health["availability"]["models"][llm.DEFAULT_MODELS["fast"]]["available"] is True
    assert len(calls) == 2


def test_status_is_degraded_when_no_model_answers(client: TestClient, monkeypatch) -> None:
    _fake_vertex(monkeypatch, missing=set(llm.DEFAULT_MODELS.values()))

    payload = client.get("/status").json()

    assert payload["status"] == "degraded"
    assert payload["llm"]["availability"]["models"][llm.DEFAULT_MODELS["fast"]]["http_status"] == 404
