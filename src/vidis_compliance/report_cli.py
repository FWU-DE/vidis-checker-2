from __future__ import annotations

import json
from pathlib import Path

import typer

from .coverage_matrix import (
    DEFAULT_COVERAGE_HTML,
    DEFAULT_COVERAGE_JSON,
    write_coverage_matrix,
)
from .models import JobResult
from .report.markdown import generate_markdown
from .report.pdf import generate_pdf

app = typer.Typer(add_completion=False)


def _resolve_result_path(input_name: str) -> Path:
    path = Path(input_name)
    if path.exists():
        return path
    return Path("results") / input_name / "result.json"


def _resolve_capture_path(result_path: Path, capture: str | None) -> Path | None:
    if capture:
        path = Path(capture)
        return path if path.exists() else None
    candidate = result_path.parent / "capture.json"
    return candidate if candidate.exists() else None


def _load_capture(path: Path | None) -> dict | None:
    if not path:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@app.command()
def report(
    input_name: str = typer.Option(..., "--input", help="Job-ID oder Pfad zu result.json."),
    output_pdf: str | None = typer.Option(None, "--pdf", help="Pfad für den PDF-Report."),
    output_md: str | None = typer.Option(None, "--md", help="Pfad für den Markdown-Report."),
    capture: str | None = typer.Option(None, "--capture", help="Optionaler Pfad zu capture.json."),
):
    """Generate German VIDIS reports from an existing result.json."""
    result_path = _resolve_result_path(input_name)
    data = json.loads(result_path.read_text(encoding="utf-8"))
    res = JobResult(**data)
    raw_capture = _load_capture(_resolve_capture_path(result_path, capture))

    written: list[Path] = []
    if output_pdf is None and output_md is None:
        output_pdf = "report.pdf"

    if output_pdf:
        out = Path(output_pdf)
        out.parent.mkdir(parents=True, exist_ok=True)
        generate_pdf(res, out, raw_capture=raw_capture)
        written.append(out)
    if output_md:
        out = Path(output_md)
        out.parent.mkdir(parents=True, exist_ok=True)
        generate_markdown(res, out, raw_capture=raw_capture)
        written.append(out)

    for path in written:
        typer.echo(str(path))


@app.command()
def coverage(
    output_json: Path = typer.Option(DEFAULT_COVERAGE_JSON, "--json", help="Pfad für die maschinenlesbare Coverage-Matrix."),
    output_html: Path = typer.Option(DEFAULT_COVERAGE_HTML, "--html", help="Pfad für die statische HTML-Coverage-Matrix."),
):
    """Generate the VIDIS coverage and automation matrix."""
    written = write_coverage_matrix(json_path=output_json, html_path=output_html)
    for path in written:
        typer.echo(str(path))


if __name__ == "__main__":
    app()
