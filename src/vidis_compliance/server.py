from __future__ import annotations

import hmac
import ipaddress
import json
import os
import socket
import threading
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from io import BytesIO
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response, Security, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, Field, HttpUrl, ValidationError, model_validator

from . import callbacks
from . import cli as cli_module
from .catalog import CHECK_IDS, CHECKS, checks_for_criterion, get_check, resolve_check_selection, runtime_availability
from .cli import load_criteria
from .util import llm as llm_module
from .util.llm import llm_status
from .models import JobResult
from .report.markdown import generate_markdown
from .report.pdf import generate_pdf

try:
    SERVICE_VERSION = package_version("vidis-compliance")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    SERVICE_VERSION = "0.0.0"

class Utf8JSONResponse(JSONResponse):
    """JSON with an explicit UTF-8 charset and indentation.

    Safari reads ``application/json`` without a charset as Latin-1 (``PrÃ¼fung``)
    and shows it unformatted; the charset and indentation make the public
    endpoints readable in any browser.
    """

    media_type = "application/json; charset=utf-8"

    def render(self, content) -> bytes:
        return json.dumps(content, ensure_ascii=False, allow_nan=False, indent=2).encode("utf-8")


app = FastAPI(
    default_response_class=Utf8JSONResponse,
    title="VIDIS Compliance API",
    version=SERVICE_VERSION,
    description=(
        "Prüft Websites, Quellcode und Dokumente gegen die VIDIS-Prüfkriterien. "
        "`GET /discovery` listet die verfügbaren Prüfungen; alle Job-Endpunkte brauchen einen API-Schlüssel."
    ),
)

@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException) -> Utf8JSONResponse:
    return Utf8JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError) -> Utf8JSONResponse:
    return Utf8JSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)


JobStatus = Literal["queued", "running", "completed", "failed"]
ALLOWED_ARTIFACTS = {"result.json", "capture.json", "code_capture.json", "document_capture.json", "agent_capture.json", "job.json"}
ALLOWED_REPORTS = {"report.md", "report.pdf"}
_STORE_LOCK = threading.RLock()
_JOB_EXECUTOR = ThreadPoolExecutor(max_workers=int(os.environ.get("VIDIS_JOB_WORKERS", "4")))


class JobCreateRequest(BaseModel):
    target_url: HttpUrl | None = None
    code_path: str | None = None
    document_path: str | None = None
    document_paths: list[str] = Field(default_factory=list)
    agb_url: HttpUrl | None = None
    privacy_url: HttpUrl | None = None
    avv_url: HttpUrl | None = None
    target_audience: Literal["SuS", "Lehrkraefte", "beide"] = "beide"
    pages: int = Field(default=8, ge=1, le=100)
    agentic: bool = False
    agent_tasks: list[Literal["legal", "student", "teacher", "register", "logout"]] = Field(default_factory=list)
    agent_username: str | None = None
    agent_password: str | None = Field(default=None, exclude=True, repr=False)
    agent_persona: Literal["SuS", "Lehrkraefte", "beide"] | None = None
    agent_vidis_portal: str | None = Field(default=None, max_length=200)
    agent_vidis_login_label: str | None = Field(default=None, max_length=200)
    agent_instructions: list[str] = Field(default_factory=list, max_length=20)
    crawl_max_age: int = Field(
        default=1800,
        ge=0,
        le=86400,
        description="Browser-Crawl derselben URL und Seitenzahl wiederverwenden, wenn er jünger ist (Sekunden). 0 erzwingt einen frischen Crawl.",
    )
    callback_url: HttpUrl | None = Field(
        default=None,
        description="Wird per POST aufgerufen, sobald der Job fertig ist (completed oder failed). Nur öffentliche HTTPS-Adressen.",
    )
    callback_secret: str | None = Field(
        default=None,
        min_length=16,
        max_length=200,
        exclude=True,
        repr=False,
        description="Optional: signiert den Callback mit HMAC-SHA256 (Header X-VIDIS-Signature). Wird nicht gespeichert.",
    )
    lighthouse: bool = False
    webinspector_export: bool = False
    checks: list[str] = Field(
        default_factory=list,
        max_length=len(CHECK_IDS),
        description="Nur diese Prüfungen ausführen (IDs aus GET /discovery). Leer: alle, die die Eingaben erlauben.",
        examples=[["site.cookies", "site.transport"]],
    )

    @model_validator(mode="after")
    def require_target(self) -> "JobCreateRequest":
        if not self.document_paths and self.document_path:
            self.document_paths = [self.document_path]
        if self.code_path:
            _require_allowed_local_path(self.code_path)
        for document_path in self.document_paths:
            _require_allowed_local_path(document_path)
            if not Path(document_path).is_file():
                raise ValueError(f"document path does not exist: {document_path}")
        for url in (self.target_url, self.agb_url, self.privacy_url, self.avv_url):
            if url is not None:
                _require_public_target(str(url))
        if not (
            self.target_url
            or self.code_path
            or self.document_paths
            or self.agb_url
            or self.privacy_url
            or self.avv_url
        ):
            raise ValueError("target_url, code_path, document_paths or document URL is required")
        if self.agentic and not self.target_url:
            raise ValueError("agentic mode requires target_url")
        self.checks = list(dict.fromkeys(self.checks))
        _validate_check_selection(self)
        if self.callback_url is not None:
            _require_callback_target(str(self.callback_url))
        if self.callback_secret and self.callback_url is None:
            raise ValueError("callback_secret requires callback_url")
        return self


class CheckRunRequest(BaseModel):
    """Body for POST /checks/{check_id}: the job inputs without a check list."""

    model_config = {"extra": "forbid"}

    target_url: HttpUrl | None = None
    code_path: str | None = None
    document_paths: list[str] = Field(default_factory=list)
    agb_url: HttpUrl | None = None
    privacy_url: HttpUrl | None = None
    avv_url: HttpUrl | None = None
    target_audience: Literal["SuS", "Lehrkraefte", "beide"] = "beide"
    pages: int = Field(default=8, ge=1, le=100)
    agent_tasks: list[Literal["legal", "student", "teacher", "register", "logout"]] = Field(default_factory=list)
    agent_username: str | None = None
    agent_password: str | None = Field(default=None, exclude=True, repr=False)
    agent_persona: Literal["SuS", "Lehrkraefte", "beide"] | None = None
    agent_vidis_portal: str | None = Field(default=None, max_length=200)
    agent_vidis_login_label: str | None = Field(default=None, max_length=200)
    agent_instructions: list[str] = Field(default_factory=list, max_length=20)
    crawl_max_age: int = Field(
        default=1800,
        ge=0,
        le=86400,
        description="Browser-Crawl derselben URL und Seitenzahl wiederverwenden, wenn er jünger ist (Sekunden). 0 erzwingt einen frischen Crawl.",
    )
    callback_url: HttpUrl | None = Field(
        default=None,
        description="Wird per POST aufgerufen, sobald der Job fertig ist (completed oder failed). Nur öffentliche HTTPS-Adressen.",
    )
    callback_secret: str | None = Field(
        default=None,
        min_length=16,
        max_length=200,
        exclude=True,
        repr=False,
        description="Optional: signiert den Callback mit HMAC-SHA256 (Header X-VIDIS-Signature). Wird nicht gespeichert.",
    )


def _validate_check_selection(request: "JobCreateRequest") -> None:
    resolve_check_selection(
        request.checks,
        has_url=request.target_url is not None,
        has_code=bool(request.code_path),
        has_documents=bool(request.document_paths or request.agb_url or request.privacy_url or request.avv_url),
        flags={"agentic": request.agentic, "lighthouse": request.lighthouse, "webinspector_export": request.webinspector_export},
    )


class JobCreatedResponse(BaseModel):
    id: str
    status: JobStatus
    status_url: str


class JobMetadata(BaseModel):
    id: str
    status: JobStatus
    created_at: str
    updated_at: str
    request: JobCreateRequest
    result: JobResult | None = None
    error: str | None = None
    artifacts: dict[str, str] = Field(default_factory=dict)
    reports: dict[str, str] = Field(default_factory=dict)
    callback: dict[str, Any] | None = None


class JobSummary(BaseModel):
    id: str
    status: JobStatus
    created_at: str
    updated_at: str
    request: JobCreateRequest
    error: str | None = None
    artifacts: dict[str, str] = Field(default_factory=dict)
    reports: dict[str, str] = Field(default_factory=dict)


class JobListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[JobSummary]


class ReportCreateRequest(BaseModel):
    format: Literal["md", "pdf"]


class ReportCreatedResponse(BaseModel):
    job_id: str
    format: Literal["md", "pdf"]
    download_url: str


_bearer = HTTPBearer(auto_error=False, description="API-Schlüssel als `Authorization: Bearer <key>`.")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="API-Schlüssel als `X-API-Key: <key>`.")


def require_api_key(
    bearer: HTTPAuthorizationCredentials | None = Security(_bearer),
    header_key: str | None = Security(_api_key_header),
) -> None:
    keys = _api_keys()
    if not keys:
        if _auth_disabled():
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured: set VIDIS_API_KEYS",
        )
    supplied = header_key or (bearer.credentials if bearer else "")
    if not supplied or not any(hmac.compare_digest(supplied.encode(), key.encode()) for key in keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )


public = APIRouter(tags=["public"])
protected = APIRouter(tags=["jobs"], dependencies=[Security(require_api_key)])


@public.get("/health")
def health():
    """Cheap liveness check; shows the last model check from /status but never starts one."""
    llm = llm_status()
    probe = llm_module.public_probe(llm_module.last_probe())
    if probe is not None:
        llm["availability"] = probe
    return {"status": "ok", "version": SERVICE_VERSION, "llm": llm}


@public.get("/status")
def service_status(refresh: bool = Query(default=False, description="Modelle sofort neu prüfen (sonst höchstens alle 10 Minuten)")):
    """Service status: which LLM models answer, job queue, crawl cache."""
    llm = llm_status()
    if llm.get("configured"):
        llm["availability"] = llm_module.public_probe(llm_module.probe_models(force=refresh))
    counts = {"queued": 0, "running": 0, "completed": 0, "failed": 0}
    for job in _list_metadata():
        counts[job.status] = counts.get(job.status, 0) + 1
    cache_dir = Path(os.environ.get("VIDIS_CRAWL_CACHE_DIR") or (_results_root() / ".crawl-cache"))
    entries = [entry for entry in cache_dir.iterdir() if entry.is_dir() and not entry.name.startswith(".")] if cache_dir.is_dir() else []
    degraded = bool(llm.get("configured")) and not any(
        model.get("available") for model in ((llm.get("availability") or {}).get("models") or {}).values()
    )
    return {
        "status": "degraded" if degraded else "ok",
        "version": SERVICE_VERSION,
        "llm": llm,
        "jobs": {**counts, "workers": _JOB_EXECUTOR._max_workers},
        "crawl_cache": {"entries": len(entries), "default_max_age_seconds": 1800},
    }


@public.get("/criteria")
def criteria():
    crit = load_criteria()
    return {"items": {k: v.model_dump() for k, v in crit.items.items()}}


@public.get("/discovery")
@public.get("/.well-known/vidis-checks", include_in_schema=False)
def discovery(request: Request):
    """Machine-readable list of the available checks, criteria and endpoints."""
    base = str(request.base_url).rstrip("/")
    crit = load_criteria()
    available = runtime_availability()
    checks = []
    for check in CHECKS:
        item = check.to_dict()
        item["available"] = available.get(check.id, True)
        item["run"] = {"method": "POST", "path": f"/checks/{check.id}", "auth": True}
        checks.append(item)
    criteria_items = []
    for code, criterion in crit.items.items():
        check_ids = checks_for_criterion(code)
        deterministic = [check_id for check_id in check_ids if check_id.split(".", 1)[0] in {"site", "code", "documents"}]
        criteria_items.append(
            {
                "code": code,
                "name": criterion.name,
                "area": criterion.area,
                "must": criterion.must,
                "checks": check_ids,
                "automated": bool(deterministic),
            }
        )
    return {
        "service": "vidis-compliance",
        "version": SERVICE_VERSION,
        "criteria_catalog": {"name": "VIDIS-Prüfkriterien", "version": "V0.2", "count": len(criteria_items)},
        "authentication": {
            "required": bool(_api_keys()) or not _auth_disabled(),
            "schemes": [
                {"type": "http", "scheme": "bearer", "header": "Authorization: Bearer <key>"},
                {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            ],
            "public_paths": ["/health", "/status", "/discovery", "/.well-known/vidis-checks", "/criteria", "/checks", "/docs", "/openapi.json"],
        },
        "endpoints": [
            {"method": "POST", "path": "/jobs", "auth": True, "description": "Prüfung starten (asynchron); optional nur einzelne Prüfungen über checks"},
            {"method": "GET", "path": "/checks", "auth": False, "description": "Verfügbare Prüfungen"},
            {"method": "GET", "path": "/status", "auth": False, "description": "Dienststatus: erreichbare KI-Modelle, Job-Warteschlange, Crawl-Cache"},
            {"method": "GET", "path": "/checks/{check_id}", "auth": False, "description": "Eine Prüfung mit Kriterien und nötigen Eingaben"},
            {"method": "POST", "path": "/checks/{check_id}", "auth": True, "description": "Genau diese eine Prüfung als Job starten (asynchron)"},
            {"method": "GET", "path": "/jobs", "auth": True, "description": "Jobs auflisten, Filter status, limit, offset"},
            {"method": "GET", "path": "/jobs/{job_id}", "auth": True, "description": "Status, Ergebnis und Artefakt-Links"},
            {"method": "POST", "path": "/jobs/{job_id}/reports", "auth": True, "description": "Bericht als md oder pdf erzeugen"},
            {"method": "GET", "path": "/jobs/{job_id}/reports/{report_name}", "auth": True, "description": "Bericht herunterladen"},
            {"method": "GET", "path": "/jobs/{job_id}/artifacts/{name}", "auth": True, "description": "Artefakt herunterladen"},
            {"method": "GET", "path": "/jobs/{job_id}/archive.zip", "auth": True, "description": "Beweispaket als ZIP"},
        ],
        "job_request": {
            "schema": f"{base}/openapi.json#/components/schemas/JobCreateRequest",
            "example": {
                "target_url": "https://anbieter.example",
                "privacy_url": "https://anbieter.example/datenschutz",
                "target_audience": "SuS",
                "pages": 8,
            },
            "single_check_example": {"target_url": "https://anbieter.example", "checks": ["site.transport"]},
        },
        "llm": {
            **llm_status(),
            "use": "Bewertet öffentliche Screenshots als zusätzlichen Hinweis im Bericht; ändert keine PASS/FAIL-Ergebnisse. Screenshots aus angemeldeten Bereichen werden nie gesendet.",
        },
        "callbacks": {
            "request_fields": ["callback_url", "callback_secret"],
            "method": "POST",
            "event": callbacks.EVENT,
            "headers": ["X-VIDIS-Event", "X-VIDIS-Delivery", "X-VIDIS-Timestamp", "X-VIDIS-Signature"],
            "signature": "sha256=HMAC-SHA256(callback_secret, '<X-VIDIS-Timestamp>.<body>') als Hex",
            "retries": list(callbacks.RETRY_DELAYS_SECONDS),
            "note": "Der Body enthält Status, Zusammenfassung und Links, nicht das ganze Ergebnis; Details per GET /jobs/{job_id} mit API-Schlüssel.",
        },
        "crawl_cache": {
            "default_max_age_seconds": 1800,
            "request_field": "crawl_max_age",
            "note": "Ein Browser-Crawl wird für dieselbe URL und Seitenzahl wiederverwendet; 0 erzwingt einen frischen Crawl.",
        },
        "checks": checks,
        "criteria": criteria_items,
        "links": {"openapi": f"{base}/openapi.json", "docs": f"{base}/docs"},
    }


@public.get("/checks")
def list_checks():
    """The checks that `POST /checks/{check_id}` and the `checks` job field accept."""
    available = runtime_availability()
    return {"items": [{**check.to_dict(), "available": available.get(check.id, True)} for check in CHECKS]}


@public.get("/checks/{check_id}")
def get_check_definition(check_id: str):
    check = _check_or_404(check_id)
    return {**check.to_dict(), "available": runtime_availability().get(check.id, True)}


@protected.post("/checks/{check_id}", response_model=JobCreatedResponse, status_code=status.HTTP_202_ACCEPTED)
def run_single_check(check_id: str, body: CheckRunRequest, http_request: Request) -> JobCreatedResponse:
    """Start a job that runs only this check; the result holds only its criteria."""
    _check_or_404(check_id)
    data = body.model_dump()
    data["checks"] = [check_id]
    if check_id == "agentic.persona_crawl":
        data["agentic"] = True
    try:
        request = JobCreateRequest.model_validate(data)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_url=False)) from exc
    request.agent_password = body.agent_password
    request.callback_secret = body.callback_secret
    return create_job(request, http_request)


def _check_or_404(check_id: str):
    check = get_check(check_id)
    if check is None:
        raise HTTPException(status_code=404, detail=f"unknown check {check_id}; see GET /checks")
    return check


@protected.post("/jobs", response_model=JobCreatedResponse, status_code=status.HTTP_202_ACCEPTED)
def create_job(request: JobCreateRequest, http_request: Request) -> JobCreatedResponse:
    job_id = uuid.uuid4().hex
    metadata = JobMetadata(
        id=job_id,
        status="queued",
        created_at=_now(),
        updated_at=_now(),
        request=request,
    )
    _job_dir(job_id).mkdir(parents=True, exist_ok=False)
    _write_metadata(metadata)
    # The request object still carries agent_password, which is never written to disk.
    _JOB_EXECUTOR.submit(_run_job, job_id, request, _public_base_url(http_request))
    return JobCreatedResponse(id=job_id, status=metadata.status, status_url=f"/jobs/{job_id}")


@protected.get("/jobs", response_model=JobListResponse)
def list_jobs(
    status_filter: JobStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> JobListResponse:
    jobs = _list_metadata(status_filter=status_filter)
    page = jobs[offset : offset + limit]
    return JobListResponse(
        total=len(jobs),
        limit=limit,
        offset=offset,
        items=[_job_summary(job) for job in page],
    )


@protected.get("/jobs/{job_id}", response_model=JobMetadata)
def get_job(job_id: str) -> JobMetadata:
    return _read_metadata(job_id)


@protected.get("/jobs/{job_id}/artifacts/{artifact_name:path}")
def get_artifact(job_id: str, artifact_name: str):
    path = _safe_named_file(job_id, artifact_name, ALLOWED_ARTIFACTS)
    if path.suffix == ".json":
        return Response(path.read_text(encoding="utf-8"), media_type="application/json; charset=utf-8")
    return FileResponse(path)


@protected.post(
    "/jobs/{job_id}/reports",
    response_model=ReportCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_report(job_id: str, request: ReportCreateRequest) -> ReportCreatedResponse:
    metadata = _read_metadata(job_id)
    if metadata.status != "completed" or metadata.result is None:
        raise HTTPException(status_code=409, detail="job is not completed")
    report_name = f"report.{request.format}"
    output = _job_dir(job_id) / report_name
    raw_capture = _load_optional_json(_job_dir(job_id) / "capture.json")
    if request.format == "md":
        generate_markdown(metadata.result, output, raw_capture=raw_capture)
    else:
        generate_pdf(metadata.result, output, raw_capture=raw_capture)
    metadata.reports[request.format] = f"/jobs/{job_id}/reports/{report_name}"
    metadata.updated_at = _now()
    _write_metadata(metadata)
    return ReportCreatedResponse(
        job_id=job_id,
        format=request.format,
        download_url=metadata.reports[request.format],
    )


@protected.get("/jobs/{job_id}/reports/{report_name}")
def get_report(job_id: str, report_name: str):
    path = _safe_named_file(job_id, report_name, ALLOWED_REPORTS)
    media_type = "text/markdown; charset=utf-8" if report_name.endswith(".md") else "application/pdf"
    if report_name.endswith(".md"):
        return Response(path.read_text(encoding="utf-8"), media_type=media_type)
    return FileResponse(path, media_type=media_type, filename=report_name)


@protected.get("/jobs/{job_id}/archive.zip")
def get_archive(job_id: str):
    metadata = _read_metadata(job_id)
    job_dir = _job_dir(job_id)
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(ALLOWED_ARTIFACTS):
            path = job_dir / name
            if path.exists() and path.is_file():
                archive.write(path, arcname=name)
        for report_name in sorted(ALLOWED_REPORTS):
            path = job_dir / report_name
            if path.exists() and path.is_file():
                archive.write(path, arcname=f"reports/{report_name}")
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="vidis-{metadata.id}.archive.zip"'},
    )


def _run_job(job_id: str, request: JobCreateRequest | None = None, base_url: str = "") -> None:
    metadata = _read_metadata(job_id)
    if request is not None:
        metadata.request = request
    try:
        metadata.status = "running"
        metadata.updated_at = _now()
        _write_metadata(metadata)

        result, raw_capture, code_capture, document_capture, agent_capture = _execute_check(job_id, request or metadata.request)
        job_dir = _job_dir(job_id)
        (job_dir / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
        if raw_capture is not None:
            (job_dir / "capture.json").write_text(
                json.dumps(raw_capture, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            _copy_public_screenshots(job_id, raw_capture)
        if code_capture is not None:
            (job_dir / "code_capture.json").write_text(
                json.dumps(code_capture, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        if document_capture is not None:
            (job_dir / "document_capture.json").write_text(
                json.dumps(document_capture, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        if agent_capture is not None:
            (job_dir / "agent_capture.json").write_text(
                json.dumps(agent_capture, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
        metadata.status = "completed"
        metadata.result = result
        metadata.artifacts = _artifact_urls(job_id)
    except Exception as exc:  # pragma: no cover - defensive job boundary
        metadata.status = "failed"
        metadata.error = str(exc)
    finally:
        metadata.updated_at = _now()
        _write_metadata(metadata)
    callback_request = request or metadata.request
    if callback_request.callback_url is not None:
        _schedule_callback(metadata, str(callback_request.callback_url), callback_request.callback_secret, base_url)


def _schedule_callback(metadata: JobMetadata, url: str, secret: str | None, base_url: str) -> None:
    payload = callbacks.build_payload(metadata, base_url)
    _update_callback(metadata.id, {"url": url, "delivered": False, "attempts": 0, "pending": True})

    def send() -> None:
        record = callbacks.deliver(url, payload, secret=secret, check_target=_require_callback_target)
        _update_callback(metadata.id, record)

    callbacks.submit(send)


def _update_callback(job_id: str, record: dict[str, Any]) -> None:
    with _STORE_LOCK:
        current = _read_metadata(job_id)
        current.callback = record
        _write_metadata(current)


def _public_base_url(request: Request) -> str:
    configured = os.environ.get("VIDIS_PUBLIC_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def _require_callback_target(url: str) -> None:
    """Callbacks go only to public HTTPS hosts that resolve right now."""
    if _env_flag("VIDIS_ALLOW_PRIVATE_TARGETS"):
        return
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("callback_url must use https")
    host = parts.hostname or ""
    try:
        infos = socket.getaddrinfo(host, parts.port or 443)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"callback host does not resolve: {host}") from exc
    _require_public_target(url)
    if not infos:
        raise ValueError(f"callback host does not resolve: {host}")


def _execute_check(job_id: str, request: JobCreateRequest) -> tuple[JobResult, dict | None, dict | None, dict | None, dict | None]:
    run = cli_module.run_checks(
        job_id=job_id,
        outdir=_job_dir(job_id),
        url=str(request.target_url) if request.target_url else None,
        code_path=request.code_path,
        pages=request.pages,
        audience=request.target_audience,
        documents=list(request.document_paths),
        agb_url=str(request.agb_url) if request.agb_url else None,
        privacy_url=str(request.privacy_url) if request.privacy_url else None,
        avv_url=str(request.avv_url) if request.avv_url else None,
        agentic=request.agentic,
        agent_tasks=list(request.agent_tasks),
        agent_persona=request.agent_persona,
        agent_username=request.agent_username,
        agent_password=request.agent_password,
        agent_vidis_portal=request.agent_vidis_portal,
        agent_vidis_login_label=request.agent_vidis_login_label,
        agent_instructions=list(request.agent_instructions),
        lighthouse=request.lighthouse,
        webinspector_export=request.webinspector_export,
        checks=list(request.checks) or None,
        crawl_max_age=request.crawl_max_age,
    )
    return run.result, run.raw_capture, run.code_capture, run.document_capture, run.agent_capture


def _results_root() -> Path:
    return Path(os.environ.get("VIDIS_RESULTS_DIR", "results")).resolve()


def _api_keys() -> list[str]:
    raw = [os.environ.get("VIDIS_API_KEYS", ""), os.environ.get("VIDIS_API_KEY", ""), os.environ.get("API_KEY", "")]
    return [key.strip() for value in raw for key in value.split(",") if key.strip()]


def _auth_disabled() -> bool:
    return _env_flag("VIDIS_AUTH_DISABLED")


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _require_allowed_local_path(value: str) -> None:
    """Restrict server-side paths when VIDIS_ALLOWED_PATH_ROOTS is set.

    Without the restriction any API caller could read files on the server through
    code_path or document_paths. The container image sets it to /data/inputs.
    """
    roots_value = os.environ.get("VIDIS_ALLOWED_PATH_ROOTS", "").strip()
    if not roots_value:
        return
    if roots_value.lower() == "none":
        raise ValueError("local paths are disabled on this server; use document URLs instead")
    path = Path(value).resolve()
    roots = [Path(root).resolve() for root in roots_value.split(os.pathsep) if root.strip()]
    if not any(path == root or root in path.parents for root in roots):
        raise ValueError(f"path is outside the allowed input directories: {value}")


def _require_public_target(url: str) -> None:
    """Refuse URLs that point into the server's own network unless explicitly allowed."""
    if _env_flag("VIDIS_ALLOW_PRIVATE_TARGETS"):
        return
    host = urlsplit(url).hostname or ""
    if host.lower() in {"localhost", "localhost.localdomain"} or host.lower().endswith(".localhost"):
        raise ValueError(f"target host is not public: {host}")
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return  # unresolvable here; the crawl will report it
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not address.is_global:
            raise ValueError(f"target host resolves to a non-public address: {host}")


def _job_dir(job_id: str) -> Path:
    if not job_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in job_id):
        raise HTTPException(status_code=404, detail="job not found")
    root = _results_root()
    path = (root / job_id).resolve()
    if root not in path.parents and path != root:
        raise HTTPException(status_code=400, detail="invalid job path")
    return path


def _metadata_path(job_id: str) -> Path:
    return _job_dir(job_id) / "job.json"


def _read_metadata(job_id: str) -> JobMetadata:
    path = _metadata_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="job not found")
    return JobMetadata.model_validate_json(path.read_text(encoding="utf-8"))


def _write_metadata(metadata: JobMetadata) -> None:
    with _STORE_LOCK:
        path = _metadata_path(metadata.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f"{path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as file:
            file.write(metadata.model_dump_json(indent=2))
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp_path, path)


def _list_metadata(status_filter: JobStatus | None = None) -> list[JobMetadata]:
    root = _results_root()
    if not root.exists():
        return []
    jobs: list[JobMetadata] = []
    for path in root.iterdir():
        metadata_path = path / "job.json"
        if not path.is_dir() or not metadata_path.exists():
            continue
        try:
            metadata = JobMetadata.model_validate_json(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if status_filter is None or metadata.status == status_filter:
            jobs.append(metadata)
    return sorted(jobs, key=lambda job: (job.created_at, job.id), reverse=True)


def _job_summary(metadata: JobMetadata) -> JobSummary:
    return JobSummary(
        id=metadata.id,
        status=metadata.status,
        created_at=metadata.created_at,
        updated_at=metadata.updated_at,
        request=metadata.request,
        error=metadata.error,
        artifacts=metadata.artifacts,
        reports=metadata.reports,
    )


def _safe_named_file(job_id: str, name: str, allowed: set[str]) -> Path:
    if "\\" in name or ".." in name:
        raise HTTPException(status_code=404, detail="file not found")
    if "/" not in name and name not in allowed:
        raise HTTPException(status_code=404, detail="file not found")
    if "/" in name and not name.startswith("screenshots/"):
        raise HTTPException(status_code=404, detail="file not found")
    path = (_job_dir(job_id) / name).resolve()
    job_dir = _job_dir(job_id).resolve()
    if job_dir not in path.parents or not path.exists():
        raise HTTPException(status_code=404, detail="file not found")
    return path


def _artifact_urls(job_id: str) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for name in sorted(ALLOWED_ARTIFACTS - {"job.json"}):
        if (_job_dir(job_id) / name).exists():
            key = name.replace(".", "_")
            artifacts[key] = f"/jobs/{job_id}/artifacts/{name}"
    screenshots_dir = _job_dir(job_id) / "screenshots"
    if screenshots_dir.exists():
        for path in sorted(screenshots_dir.glob("*.png")):
            key = "screenshot_" + path.stem.replace("-", "_")
            artifacts[key] = f"/jobs/{job_id}/artifacts/screenshots/{path.name}"
    return artifacts


def _copy_public_screenshots(job_id: str, raw_capture: dict) -> None:
    import shutil

    screenshots = raw_capture.get("screenshots") or []
    output_dir = _job_dir(job_id) / "screenshots"
    for item in screenshots:
        if item.get("local_only") or item.get("authenticated"):
            continue
        source = Path(str(item.get("path") or ""))
        filename = str(item.get("filename") or source.name)
        if not filename or not source.exists():
            continue
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / filename
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)


def _load_optional_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


app.include_router(public)
app.include_router(protected)
