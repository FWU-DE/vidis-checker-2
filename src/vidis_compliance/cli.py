import json
from pathlib import Path
import typer
from .models import JobConfig, JobResult, CheckFinding, CriteriaIndex, VidisCriterion
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
):
    """Run unified VIDIS checks (site and/or code)."""
    crit = load_criteria()
    cfg = JobConfig(job_id=output, target_url=url, code_path=code_path, pages=pages, target_audience=audience)  # noqa: E501

    # Placeholder: return MANUELL for all criteria until wired
    findings = [
        CheckFinding(criterion=k, status="MANUELL", note="Not yet implemented")
        for k in crit.items.keys()
    ]
    res = JobResult(job_id=cfg.job_id, findings=findings)

    outdir = Path("results") / cfg.job_id
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "result.json").write_text(res.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(str(outdir / "result.json"))


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8645):
    """Start FastAPI server."""
    import uvicorn

    uvicorn.run("vidis_compliance.server:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
