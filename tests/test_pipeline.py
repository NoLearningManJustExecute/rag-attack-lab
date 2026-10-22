"""Offline tests for ingestion, retrieval, and the RAG pipeline."""

from rag_attack_lab.ingest import ingest, load_file
from rag_attack_lab.providers import FAKE_ANSWER
from rag_attack_lab.rag import answer_question
from rag_attack_lab.retriever import retrieve
from rag_attack_lab.vectorstore import get_vector_store, reset_vector_store


def make_minimal_pdf(text: str) -> bytes:
    """Build a valid one-page PDF showing `text`, so the test needs no PDF-writing library."""
    stream = f"BT /F1 18 Tf 20 70 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R"
            b" /Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    pdf = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n" % number + body + b"\nendobj\n"

    # The cross-reference table lists the byte offset of every object.
    xref_position = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        pdf += b"%010d 00000 n \n" % offset
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref_position)
    return pdf


def test_ingestion_creates_chunks(settings):
    chunks = ingest(settings.data_dir, settings)

    assert len(chunks) > 3
    sources = {chunk.metadata["source"] for chunk in chunks}
    # Subfolders are ingested too: data/internal/ and data/untrusted/ land in the same index.
    assert sources == {
        "employee_handbook.txt",
        "product_overview.txt",
        "customer_faq.txt",
        "ops_runbook.txt",
        "leadership_memo.txt",
        "vendor_newsletter.txt",
        "return_policy_update.txt",
    }
    assert len(get_vector_store(settings).get()["ids"]) == len(chunks)


def test_ingesting_the_same_file_twice_does_not_duplicate_chunks(settings):
    handbook = settings.data_dir / "employee_handbook.txt"

    first = ingest(handbook, settings)
    second = ingest(handbook, settings)

    assert [chunk.metadata["chunk"] for chunk in first] == [chunk.metadata["chunk"] for chunk in second]
    assert len(get_vector_store(settings).get()["ids"]) == len(first)


def test_ingesting_a_file_after_its_folder_does_not_duplicate_chunks(settings):
    all_chunks = ingest(settings.data_dir, settings)
    ingest(settings.data_dir / "customer_faq.txt", settings)

    assert len(get_vector_store(settings).get()["ids"]) == len(all_chunks)


def test_pdf_loading(tmp_path):
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(make_minimal_pdf("Northwind PDF test"))

    documents = load_file(pdf_path)

    assert len(documents) == 1
    assert "Northwind PDF test" in documents[0].page_content
    assert documents[0].metadata == {"source": "sample.pdf", "page": 1}


def test_retrieval_returns_expected_source(settings):
    ingest(settings.data_dir, settings)

    results = retrieve("How many days of paid vacation do full-time employees get?", settings)

    assert len(results) == settings.top_k
    assert results[0].source == "employee_handbook.txt"
    assert "vacation" in results[0].text.lower()


def test_rag_returns_an_answer(settings):
    ingest(settings.data_dir, settings)

    result = answer_question("What is the return policy?", settings)

    assert result.answer == FAKE_ANSWER
    assert result.chunks
    assert "What is the return policy?" in result.prompt
    assert "[Source: customer_faq.txt]" in result.prompt


def test_reset_clears_the_store(settings):
    ingest(settings.data_dir, settings)
    reset_vector_store(settings)

    assert get_vector_store(settings).get()["ids"] == []
