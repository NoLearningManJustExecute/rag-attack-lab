"""Load TXT and PDF files, split them into chunks, and store the chunks in Chroma."""

import hashlib
from collections import Counter
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from rag_attack_lab.canaries import fill_canaries
from rag_attack_lab.config import Settings
from rag_attack_lab.defenses import classify_sensitivity, find_suspicious_lines
from rag_attack_lab.vectorstore import get_vector_store

SUPPORTED_EXTENSIONS = {".txt", ".pdf"}


def load_file(path: Path) -> list[Document]:
    """Read one file into Documents. A PDF gives one Document per page."""
    extension = path.suffix.lower()

    if extension == ".txt":
        text = path.read_text(encoding="utf-8")
        return [Document(page_content=text, metadata={"source": path.name})]

    if extension == ".pdf":
        reader = PdfReader(str(path))
        return [
            Document(page_content=page.extract_text() or "", metadata={"source": path.name, "page": number})
            for number, page in enumerate(reader.pages, start=1)
        ]

    raise ValueError(f"Unsupported file type: {path.name}. Supported: {sorted(SUPPORTED_EXTENSIONS)}")


def find_files(path: Path) -> list[Path]:
    """Return the supported files at `path` (a single file, or a folder and all its subfolders)."""
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS)


def split_documents(documents: list[Document], settings: Settings) -> list[Document]:
    """Split documents into overlapping chunks. Each chunk keeps its source metadata."""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
    )
    chunks = splitter.split_documents(documents)

    # Number each file's chunks from 0, so a chunk's number does not depend on
    # which other files were ingested in the same run.
    next_number: Counter[str] = Counter()
    for chunk in chunks:
        source = chunk.metadata["source"]
        chunk.metadata["chunk"] = next_number[source]
        next_number[source] += 1
    return chunks


def chunk_id(chunk: Document) -> str:
    """A stable ID for a chunk: source file, chunk number, and a short hash of the text.

    Ingesting the same file again gives the same IDs, so Chroma overwrites the
    stored chunks instead of adding duplicates.
    """
    content_hash = hashlib.sha256(chunk.page_content.encode("utf-8")).hexdigest()[:12]
    return f"{chunk.metadata['source']}:{chunk.metadata['chunk']}:{content_hash}"


def ingest(path: Path, settings: Settings) -> list[Document]:
    """Load, split, and store everything at `path`. Returns the chunks that were stored."""
    # LLM09: every file found is stored in the same index, whatever its source, and poisoned
    # documents go straight in. LLM02: internal documents (with their canaries) are stored next to
    # the public ones. The labels below are recorded in every mode, but only SECURE_MODE acts on
    # them (see retriever.py), so with it off they change nothing.
    documents: list[Document] = []
    for file in find_files(path):
        file_documents = load_file(file)
        # LLM02/LLM09 fix (labels): where the file sits decides its sensitivity, and the
        # suspicious-content screen (issue #12) flags text that addresses an AI system.
        sensitivity = classify_sensitivity(file, settings.data_dir)
        suspicious = any(find_suspicious_lines(document.page_content) for document in file_documents)
        for document in file_documents:
            document.metadata["sensitivity"] = sensitivity
            document.metadata["suspicious"] = suspicious
        documents.extend(file_documents)

    # Swap canary placeholders for their generated values before the text is chunked and stored.
    for document in documents:
        document.page_content = fill_canaries(document.page_content, settings)

    chunks = split_documents(documents, settings)
    if chunks:
        ids = [chunk_id(chunk) for chunk in chunks]
        get_vector_store(settings).add_documents(chunks, ids=ids)
    return chunks
