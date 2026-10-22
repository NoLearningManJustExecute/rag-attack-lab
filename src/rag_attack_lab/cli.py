"""Command line interface: ingest, ask, attack, eval, reset, doctor."""

from dataclasses import fields
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rag_attack_lab.attacks.cases import CASES_BY_ID
from rag_attack_lab.attacks.metrics import run_eval, write_metrics
from rag_attack_lab.attacks.runner import default_name, run_all, run_attack, write_findings
from rag_attack_lab.config import Settings, load_settings
from rag_attack_lab.doctor import FAIL, PASS, run_checks
from rag_attack_lab.ingest import ingest as ingest_path
from rag_attack_lab.providers import describe_model
from rag_attack_lab.rag import answer_question
from rag_attack_lab.vectorstore import reset_vector_store

app = typer.Typer(help="RAG Attack Lab: a deliberately vulnerable RAG app. Local only, fake data only.")
console = Console()


def mode_label(settings: Settings) -> str:
    return "SECURE_MODE on" if settings.secure_mode else "SECURE_MODE off"


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

    # Every chunk is labeled at ingest; SECURE_MODE decides whether retrieval acts on the labels.
    labels = {chunk.metadata["source"]: chunk.metadata for chunk in chunks}
    held_back = sorted(
        f"{source} ({meta['sensitivity']}{', flagged suspicious' if meta['suspicious'] else ''})"
        for source, meta in labels.items()
        if meta["sensitivity"] != "public" or meta["suspicious"]
    )
    if held_back:
        action = "excluded from retrieval" if settings.secure_mode else "retrievable, because SECURE_MODE is off"
        console.print(f"Not public ({action}): {', '.join(held_back)}")


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

    console.print(
        Panel(result.answer, title=f"Answer ({describe_model(settings)}, {mode_label(settings)})", expand=False)
    )
    for note in result.guardrails:
        console.print(f"[yellow]Output check:[/yellow] {note}")

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
    out_dir: Path = typer.Option(Path("findings"), "--out", help="Folder for the output files."),
    name: str | None = typer.Option(
        None, "--name", help="Output file name without extension. Default: findings, or retest with SECURE_MODE on."
    ),
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

    table = Table(title=f"Attack results ({describe_model(settings)}, {mode_label(settings)})")
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

    paths = write_findings(findings, out_dir, name or default_name(settings))
    console.print(f"Wrote {', '.join(str(path) for path in paths)}")
    triggered = sum(1 for finding in findings if finding.triggered)
    console.print(f"{triggered}/{len(findings)} attack(s) triggered.")


@app.command(name="eval")
def evaluate(
    out_dir: Path = typer.Option(Path("findings"), "--out", help="Folder for metrics.json."),
    reingest: bool = typer.Option(False, "--reingest", help="Reset the store and re-ingest DATA_DIR first."),
) -> None:
    """Run every attack and benign case with SECURE_MODE off, then on, and write before/after metrics."""
    settings = load_settings()

    if reingest:
        reset_vector_store(settings)
        ingest_path(settings.data_dir, settings)

    # SECURE_MODE in the environment is ignored here: eval always runs both modes.
    metrics = run_eval(settings)

    table = Table(title=f"Before and after the v3 fixes ({metrics['model']})")
    table.add_column("Case")
    table.add_column("OWASP")
    table.add_column("Before (SECURE_MODE off)")
    table.add_column("After (SECURE_MODE on)")
    for attack_case in metrics["attacks"]:
        before = "[red]VULNERABLE[/red]" if attack_case["before"]["triggered"] else "[green]not triggered[/green]"
        after = "[red]VULNERABLE[/red]" if attack_case["after"]["triggered"] else "[green]not triggered[/green]"
        table.add_row(attack_case["id"], attack_case["owasp"].split(":")[0], before, after)
    console.print(table)

    before, after = metrics["totals"]["before"], metrics["totals"]["after"]
    totals = Table(title="Totals")
    totals.add_column("Metric")
    totals.add_column("Before")
    totals.add_column("After")
    totals.add_row(
        "Attacks triggered",
        f"{before['attacks_triggered']}/{before['attacks']}",
        f"{after['attacks_triggered']}/{after['attacks']}",
    )
    totals.add_row("Attack block rate", f"{before['attack_block_rate']:.0%}", f"{after['attack_block_rate']:.0%}")
    totals.add_row(
        "Benign answers correct",
        f"{before['benign_correct']}/{before['benign_cases']}",
        f"{after['benign_correct']}/{after['benign_cases']}",
    )
    totals.add_row("Benign block rate", f"{before['benign_block_rate']:.0%}", f"{after['benign_block_rate']:.0%}")
    console.print(totals)

    console.print(f"Wrote {write_metrics(metrics, out_dir)}")


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
