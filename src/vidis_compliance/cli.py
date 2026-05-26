from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
import typer
from .models import JobConfig, JobResult, CheckFinding, CriteriaIndex, VidisCriterion
from .checks.site.cookies import classify_cookies, classify_tracking_pixel, classify_local_storage
from .sources.site.crawl import crawl
from .sources.code.inspect import inspect_code_path
from .report.markdown import generate_markdown
from .report.pdf import generate_pdf
import yaml

app = typer.Typer(add_completion=False)

HERE = Path(__file__).resolve().parent
CRITERIA_PATH = HERE / "criteria" / "vidis_v0_2.yaml"


def load_criteria() -> CriteriaIndex:
    data = yaml.safe_load(CRITERIA_PATH.read_text(encoding="utf-8"))
    items = {}
    for code, spec in data.items():
        items[code] = VidisCriterion(code=code, **spec)
    return CriteriaIndex(items=items)


@app.command()
def check(
    url: str = typer.Option(None, "--url"),
    code_path: str = typer.Option(None, "--code-path"),
    output: str = typer.Option("job", "--output"),
    pages: int = typer.Option(8, "--pages"),
    audience: str = typer.Option("beide", "--audience"),
    output_pdf: str | None = typer.Option(None, "--pdf", help="Optionaler Pfad für den PDF-Report."),
    output_md: str | None = typer.Option(None, "--md", help="Optionaler Pfad für den Markdown-Report."),
):
    """Run unified VIDIS checks (site and/or code)."""
    crit = load_criteria()
    cfg = JobConfig(job_id=output, target_url=url, code_path=code_path, pages=pages, target_audience=audience)  # noqa: E501

    findings = []
    raw_capture = None
    code_capture = None
    # Browser capture for cookie/storage-related VIDIS criteria.
    if url:
        cap = crawl(url, pages=pages, headless=True)
        raw_capture = asdict(cap)
        page_signals = {
            "cookies": cap.cookies,
            "scripts": cap.scripts,
            "requests": cap.requests,
            "local_storage": cap.local_storage,
            "session_storage": cap.session_storage,
        }
        s1, n1 = classify_cookies(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-371", status=s1, note=n1))
        findings.append(CheckFinding(criterion="RDS-CUC-372", status=s1, note=n1))
        s2, n2 = classify_tracking_pixel(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-373", status=s2, note=n2))
        s3, n3 = classify_local_storage(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-374", status=s3, note=n3))
        findings.append(CheckFinding(criterion="RDS-CUC-453", status="MANUELL", note="Datenschutzerklärung vs. Cookies abgleichen"))
    if code_path:
        code_findings, code_capture = inspect_code_path(code_path, audience)
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in code_findings:
            by_criterion[finding.criterion] = finding
        findings = list(by_criterion.values())
    wired = {f.criterion for f in findings}
    for k in crit.items.keys():
        if k not in wired:
            findings.append(CheckFinding(criterion=k, status="MANUELL", note="Not yet implemented"))
    res = JobResult(job_id=cfg.job_id, findings=findings)

    outdir = Path("results") / cfg.job_id
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "result.json").write_text(res.model_dump_json(indent=2), encoding="utf-8")
    if raw_capture is not None:
        (outdir / "capture.json").write_text(json.dumps(raw_capture, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if code_capture is not None:
        (outdir / "code_capture.json").write_text(json.dumps(code_capture, ensure_ascii=False, indent=2), encoding="utf-8")
    if output_pdf:
        pdf_path = Path(output_pdf)
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        generate_pdf(res, pdf_path, raw_capture=raw_capture)
    if output_md:
        md_path = Path(output_md)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        generate_markdown(res, md_path, raw_capture=raw_capture)
    typer.echo(str(outdir / "result.json"))


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8645):
    """Start FastAPI server."""
    import uvicorn

    uvicorn.run("vidis_compliance.server:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
