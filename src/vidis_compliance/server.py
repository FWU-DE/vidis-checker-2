from __future__ import annotations

import hmac
import json
import os
import threading
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Literal, cast

from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, HttpUrl, model_validator

from . import cli as cli_module
from .cli import load_criteria
from .models import CheckFinding, JobConfig, JobResult, Status
from .report.markdown import generate_markdown
from .report.pdf import generate_pdf
from .sources.documents.analyze import build_document_inputs

app = FastAPI(title="VIDIS Compliance API")

JobStatus = Literal["queued", "running", "completed", "failed"]
ALLOWED_ARTIFACTS = {"result.json", "capture.json", "code_capture.json", "document_capture.json", "agent_capture.json", "job.json"}
ALLOWED_REPORTS = {"report.md", "report.pdf"}
_STORE_LOCK = threading.Lock()
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

    @model_validator(mode="after")
    def require_target(self) -> "JobCreateRequest":
        if not self.document_paths and self.document_path:
            self.document_paths = [self.document_path]
        for document_path in self.document_paths:
            if not Path(document_path).is_file():
                raise ValueError(f"document path does not exist: {document_path}")
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
        return self


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


@app.middleware("http")
async def require_bearer_auth(request: Request, call_next):
    api_key = _api_key()
    if api_key:
        expected = f"Bearer {api_key}"
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied, expected):
            return JSONResponse(
                {"detail": "Unauthorized"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/criteria")
def criteria():
    crit = load_criteria()
    return {"items": {k: v.model_dump() for k, v in crit.items.items()}}


@app.post("/jobs", response_model=JobCreatedResponse, status_code=status.HTTP_202_ACCEPTED)
def create_job(request: JobCreateRequest) -> JobCreatedResponse:
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
    _JOB_EXECUTOR.submit(_run_job, job_id)
    return JobCreatedResponse(id=job_id, status=metadata.status, status_url=f"/jobs/{job_id}")


@app.get("/jobs", response_model=JobListResponse)
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


@app.get("/jobs/{job_id}", response_model=JobMetadata)
def get_job(job_id: str) -> JobMetadata:
    return _read_metadata(job_id)


@app.get("/jobs/{job_id}/artifacts/{artifact_name:path}")
def get_artifact(job_id: str, artifact_name: str):
    path = _safe_named_file(job_id, artifact_name, ALLOWED_ARTIFACTS)
    if path.suffix == ".json":
        return Response(path.read_text(encoding="utf-8"), media_type="application/json")
    return FileResponse(path)


@app.post(
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


@app.get("/jobs/{job_id}/reports/{report_name}")
def get_report(job_id: str, report_name: str):
    path = _safe_named_file(job_id, report_name, ALLOWED_REPORTS)
    media_type = "text/markdown; charset=utf-8" if report_name.endswith(".md") else "application/pdf"
    if report_name.endswith(".md"):
        return Response(path.read_text(encoding="utf-8"), media_type=media_type)
    return FileResponse(path, media_type=media_type, filename=report_name)


@app.get("/jobs/{job_id}/archive.zip")
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


def _run_job(job_id: str) -> None:
    metadata = _read_metadata(job_id)
    try:
        metadata.status = "running"
        metadata.updated_at = _now()
        _write_metadata(metadata)

        result, raw_capture, code_capture, document_capture, agent_capture = _execute_check(job_id, metadata.request)
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


def _execute_check(job_id: str, request: JobCreateRequest) -> tuple[JobResult, dict | None, dict | None, dict | None, dict | None]:
    crit = load_criteria()
    cfg = JobConfig(
        job_id=job_id,
        target_url=str(request.target_url) if request.target_url else None,
        code_path=request.code_path,
        pages=request.pages,
        target_audience=request.target_audience,
    )
    findings: list[CheckFinding] = []
    raw_capture = None
    code_capture = None
    document_capture = None
    agent_capture = None

    if cfg.target_url and not request.agentic:
        cap = cli_module.crawl(
            cfg.target_url,
            pages=cfg.pages,
            headless=True,
            screenshot_dir=_job_dir(job_id) / "screenshots",
        )
        raw_capture = _capture_to_dict(cap)
        raw_capture["vision_reviews"] = raw_capture.get("vision_reviews") or cli_module.review_screenshots(raw_capture.get("screenshots") or [])
        page_signals = {
            "cookies": cap.cookies,
            "scripts": cap.scripts,
            "requests": cap.requests,
            "resources": cap.resources,
            "browser_signals": cap.browser_signals,
            "local_storage": cap.local_storage,
            "session_storage": cap.session_storage,
        }
        s1, n1 = cli_module.classify_cookies(page_signals, cfg.target_audience)
        findings.append(CheckFinding(criterion="RDS-CUC-371", status=cast(Status, s1), note=n1))
        findings.append(CheckFinding(criterion="RDS-CUC-372", status=cast(Status, s1), note=n1))
        s2, n2 = cli_module.classify_tracking_pixel(page_signals, cfg.target_audience)
        findings.append(CheckFinding(criterion="RDS-CUC-373", status=cast(Status, s2), note=n2))
        s3, n3 = cli_module.classify_local_storage(page_signals, cfg.target_audience)
        findings.append(CheckFinding(criterion="RDS-CUC-374", status=cast(Status, s3), note=n3))
        s377, n377 = cli_module.classify_tracking_mechanisms(page_signals, cfg.target_audience)
        findings.append(CheckFinding(criterion="RDS-CUC-377", status=cast(Status, s377), note=n377))
        findings.append(CheckFinding(criterion="RDS-CUC-453", status="MANUELL", note="Datenschutzerklärung vs. Cookies abgleichen"))

    if cfg.code_path:
        code_findings, code_capture = cli_module.inspect_code_path(cfg.code_path, cfg.target_audience)
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in code_findings:
            by_criterion[finding.criterion] = finding
        findings = list(by_criterion.values())

    document_inputs = build_document_inputs(
        request.document_paths,
        agb_url=str(request.agb_url) if request.agb_url else None,
        privacy_url=str(request.privacy_url) if request.privacy_url else None,
        avv_url=str(request.avv_url) if request.avv_url else None,
    )
    if document_inputs:
        document_findings, document_capture = cli_module.analyze_documents(document_inputs)
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in document_findings:
            by_criterion[finding.criterion] = finding
        if raw_capture is not None:
            raw_capture["document_capture"] = document_capture
            page_signals = {
                "cookies": raw_capture.get("cookies") or [],
                "scripts": raw_capture.get("scripts") or [],
                "requests": raw_capture.get("requests") or [],
                "resources": raw_capture.get("resources") or [],
                "browser_signals": raw_capture.get("browser_signals") or {},
                "local_storage": raw_capture.get("local_storage") or {},
                "session_storage": raw_capture.get("session_storage") or {},
                "document_capture": document_capture,
            }
            s377, n377 = cli_module.classify_tracking_mechanisms(page_signals, cfg.target_audience)
            by_criterion["RDS-CUC-377"] = CheckFinding(criterion="RDS-CUC-377", status=cast(Status, s377), note=n377)
        findings = list(by_criterion.values())

    if request.agentic:
        task_types = cli_module.normalize_agent_tasks(list(request.agent_tasks))
        username = cli_module.resolve_secret(request.agent_username, "VIDIS_AGENT_USERNAME")
        password = cli_module.resolve_secret(request.agent_password, "VIDIS_AGENT_PASSWORD")
        agent_result = cli_module.DefaultAgenticRunner().run(
            base_url=cfg.target_url or "",
            task_types=task_types,
            username=username,
            password=password,
            output_dir=_job_dir(job_id) / "agent",
            persona=cfg.target_audience,
            pages=cfg.pages,
        )
        agent_capture = cli_module.write_agentic_artifacts(agent_result, _job_dir(job_id) / "agent", [username, password])

    wired = {finding.criterion for finding in findings}
    for code in crit.items.keys():
        if code not in wired:
            findings.append(CheckFinding(criterion=code, status="MANUELL", note="Not yet implemented"))
    return JobResult(job_id=job_id, findings=findings), raw_capture, code_capture, document_capture, agent_capture


def _results_root() -> Path:
    return Path(os.environ.get("VIDIS_RESULTS_DIR", "results")).resolve()


def _api_key() -> str:
    return os.environ.get("VIDIS_API_KEY") or os.environ.get("API_KEY", "")


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
        if item.get("local_only"):
            continue
        source = Path(str(item.get("path") or ""))
        filename = str(item.get("filename") or source.name)
        if not filename or not source.exists():
            continue
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / filename
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)


def _capture_to_dict(capture) -> dict:
    try:
        return cli_module.asdict(capture)
    except TypeError:
        keys = (
            "url",
            "cookies",
            "local_storage",
            "session_storage",
            "scripts",
            "requests",
            "resources",
            "links",
            "visible_text",
            "browser_signals",
            "visited_urls",
            "screenshots",
            "vision_reviews",
        )
        return {key: getattr(capture, key) for key in keys if hasattr(capture, key)}


def _load_optional_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
