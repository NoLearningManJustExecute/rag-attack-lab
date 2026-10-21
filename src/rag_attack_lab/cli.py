"""Command line interface: ingest, ask, reset."""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rag_attack_lab.config import load_settings
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
def reset() -> None:
    """Delete all stored chunks."""
    reset_vector_store(load_settings())
    console.print("Vector store cleared.")


if __name__ == "__main__":
    app()
