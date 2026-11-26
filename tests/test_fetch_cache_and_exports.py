from __future__ import annotations

import time
import zipfile
from io import BytesIO
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vidis_compliance import cli, fetch_cache, net, server
from vidis_compliance.sources.documents.analyze import DocumentInput, fetch_document


class _Transport:
    """Counts requests per URL and answers from a table."""

    def __init__(self, pages: dict[str, tuple[int, bytes]]) -> None:
        self.pages = pages
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        status, body = self.pages.get(str(request.url), (404, b"missing"))
        return httpx.Response(status, content=body, headers={"content-type": "text/html; charset=utf-8"})


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> _Transport:
    fake = _Transport({"https://docs.example/agb": (200, "<p>AGB Kündigung möglich</p>".encode())})
    real_client = httpx.Client
    monkeypatch.setattr(net.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(fake), **kw))
    return fake


def test_second_fetch_comes_from_the_cache(tmp_path: Path, transport: _Transport) -> None:
    cache = fetch_cache.FetchCache(tmp_path / "fetch", max_age=1800)
    with fetch_cache.active(cache):
        first = net.safe_get("https://docs.example/agb")
        second = net.safe_get("https://docs.example/agb")

    assert transport.calls == ["https://docs.example/agb"]
    assert second.content == first.content
    assert "möglich" in second.text
    assert cache.stats() == {"hits": 1, "fetched": 1, "max_age_seconds": 1800}


def test_cache_is_shared_between_runs_and_respects_max_age(tmp_path: Path, transport: _Transport) -> None:
    with fetch_cache.active(fetch_cache.FetchCache(tmp_path / "fetch", max_age=1800)):
        fetch_document(DocumentInput(location="https://docs.example/agb", kind="agb"))
    with fetch_cache.active(fetch_cache.FetchCache(tmp_path / "fetch", max_age=1800)):
        content, content_type, _location, _kind = fetch_document(DocumentInput(location="https://docs.example/agb", kind="agb"))
    assert len(transport.calls) == 1
    assert content_type.startswith("text/html")

    with fetch_cache.active(fetch_cache.FetchCache(tmp_path / "fetch", max_age=0)):
        net.safe_get("https://docs.example/agb")
    assert len(transport.calls) == 2


def test_expired_entries_and_errors_are_fetched_again(tmp_path: Path, transport: _Transport, monkeypatch) -> None:
    cache = fetch_cache.FetchCache(tmp_path / "fetch", max_age=60)
    with fetch_cache.active(cache):
        net.safe_get("https://docs.example/agb")
        net.safe_get("https://docs.example/missing")
        net.safe_get("https://docs.example/missing")
        later = time.time() + 120
        monkeypatch.setattr(fetch_cache.time, "time", lambda: later)
        net.safe_get("https://docs.example/agb")

    assert transport.calls.count("https://docs.example/missing") == 2
    assert transport.calls.count("https://docs.example/agb") == 2


def test_without_an_active_cache_nothing_is_cached(tmp_path: Path, transport: _Transport) -> None:
    net.safe_get("https://docs.example/agb")
    net.safe_get("https://docs.example/agb")
    assert len(transport.calls) == 2


def test_run_checks_caches_documents_and_reports_it(tmp_path: Path, transport: _Transport) -> None:
    for job in ("a", "b"):
        run = cli.run_checks(
            job_id=job,
            outdir=tmp_path / "results" / job,
            agb_url="https://docs.example/agb",
            checks=["documents.analysis"],
        )
    assert transport.calls == ["https://docs.example/agb"]
    assert run.document_capture["fetch_cache"]["hits"] >= 1


def test_webinspector_exports_are_downloadable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    client = TestClient(server.app)
    job_id = "a" * 32
    job_dir = server._job_dir(job_id)
    (job_dir / "webinspector").mkdir(parents=True)
    (job_dir / "webinspector" / "network.json").write_text('{"requests": ["https://example.test/"]}', encoding="utf-8")
    (job_dir / "webinspector" / "other.json").write_text("{}", encoding="utf-8")
    metadata = server.JobMetadata(
        id=job_id,
        status="completed",
        created_at=server._now(),
        updated_at=server._now(),
        request=server.JobCreateRequest(target_url="https://example.test", webinspector_export=True),
    )
    server._write_metadata(metadata)

    response = client.get(f"/jobs/{job_id}/artifacts/webinspector/network.json")
    assert response.status_code == 200
    assert response.json() == {"requests": ["https://example.test/"]}
    assert client.get(f"/jobs/{job_id}/artifacts/webinspector/other.json").status_code == 404
    assert server._artifact_urls(job_id)["webinspector_network_json"] == f"/jobs/{job_id}/artifacts/webinspector/network.json"

    archive = zipfile.ZipFile(BytesIO(client.get(f"/jobs/{job_id}/archive.zip").content))
    assert "webinspector/network.json" in archive.namelist()
    assert "webinspector/other.json" not in archive.namelist()
