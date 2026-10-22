"""Command line interface: ingest, ask, reset, doctor."""

from dataclasses import fields
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rag_attack_lab.attacks.cases import CASES_BY_ID
from rag_attack_lab.attacks.runner import run_all, run_attack, write_findings
from rag_attack_lab.config import load_settings
from rag_attack_lab.doctor import FAIL, PASS, run_checks
from rag_attack_lab.ingest import ingest as ingest_path
from rag_attack_lab.providers import describe_model
from rag_attack_lab.rag import answer_question
from rag_attack_lab.vectorstore import reset_vector_store

app = typer.Typer(help="RAG Attack Lab: a deliberately vulnerable RAG app. Local only, fake data only.")
console = Console()


@app.command()
def ingest(
    path: Path | None = typer.Argument(None, help="File or folder to ingest. Defaults to DATA_DIR."),
) -> None:
    """Load TXT/PDF files, split them into chunks, and store them in Chroma."""
    settings = load_settings()
    target = path or settings.data_dir
    chunks = ingest_path(target, settings)
    sources = sorted({chunk.metadata["source"] for chunk in chunks})
    console.print(f"Stored {len(chunks)} chunks from {len(sources)} files: {', '.join(sources)}")


@app.command()
def ask(
    question: str = typer.Argument(..., help="The question to ask."),
    show_prompt: bool = typer.Option(False, "--show-prompt", help="Print the full prompt sent to the model."),
) -> None:
    """Answer a question using the ingested documents."""
    settings = load_settings()
    result = answer_question(question, settings)

    if show_prompt:
        console.print(Panel(result.prompt, title="Prompt", expand=False))

    console.print(Panel(result.answer, title=f"Answer ({describe_model(settings)})", expand=False))

    table = Table(title="Retrieved sources")
    table.add_column("#")
    table.add_column("Source")
    table.add_column("Chunk")
    table.add_column("Distance")
    for rank, chunk in enumerate(result.chunks, start=1):
        table.add_row(str(rank), chunk.source, str(chunk.metadata.get("chunk", "")), f"{chunk.score:.4f}")
    console.print(table)


@app.command()
def attack(
    case_id: str | None = typer.Option(None, "--case", help="Run one case by id. Default: all."),
    out_dir: Path = typer.Option(Path("findings"), "--out", help="Folder for findings.json and findings.md."),
    reingest: bool = typer.Option(False, "--reingest", help="Reset the store and re-ingest DATA_DIR first."),
) -> None:
    """Run the planted-weakness attacks against the configured model and write findings."""
    settings = load_settings()

    if reingest:
        reset_vector_store(settings)
        ingest_path(settings.data_dir, settings)

    if case_id is not None:
        case = CASES_BY_ID.get(case_id)
        if case is None:
            console.print(f"[red]Unknown case:[/red] {case_id}. Known: {', '.join(CASES_BY_ID)}")
            raise typer.Exit(code=2)
        findings = [run_attack(case, settings)]
    else:
        findings = run_all(settings)

    table = Table(title=f"Attack results ({describe_model(settings)})")
    table.add_column("Case")
    table.add_column("OWASP")
    table.add_column("Severity")
    table.add_column("Result")
    table.add_column("Evidence")
    for finding in findings:
        verdict = "[red]VULNERABLE[/red]" if finding.triggered else "[green]not triggered[/green]"
        evidence = "; ".join(finding.detection.evidence)
        table.add_row(finding.case.id, finding.case.owasp_id.split(":")[0], finding.case.severity, verdict, evidence)
    console.print(table)

    paths = write_findings(findings, out_dir)
    console.print(f"Wrote {', '.join(str(path) for path in paths)}")
    triggered = sum(1 for finding in findings if finding.triggered)
    console.print(f"{triggered}/{len(findings)} attack(s) triggered.")


@app.command()
def reset() -> None:
    """Delete all stored chunks."""
    reset_vector_store(load_settings())
    console.print("Vector store cleared.")


@app.command()
def doctor() -> None:
    """Check the setup: providers, Ollama and its models, and the Chroma store."""
    settings = load_settings()

    # Settings holds no secrets (API keys are read straight from the environment), so all of it is safe to print.
    settings_table = Table(title="Active settings")
    settings_table.add_column("Setting")
    settings_table.add_column("Value")
    for field in fields(settings):
        settings_table.add_row(field.name, str(getattr(settings, field.name)))
    console.print(settings_table)

    results = run_checks(settings)
    colors = {PASS: "green", FAIL: "red"}
    checks_table = Table(title="Checks")
    checks_table.add_column("Check")
    checks_table.add_column("Result")
    checks_table.add_column("Detail")
    for result in results:
        color = colors.get(result.status, "yellow")
        checks_table.add_row(result.name, f"[{color}]{result.status}[/{color}]", result.detail)
    console.print(checks_table)

    failed = [result for result in results if result.status == FAIL]
    if failed:
        console.print(f"[red]{len(failed)} check(s) failed.[/red]")
        raise typer.Exit(code=1)
    console.print("[green]All checks passed.[/green]")


if __name__ == "__main__":
    app()
