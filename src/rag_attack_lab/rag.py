"""The RAG pipeline: retrieve chunks, build a prompt, generate an answer."""

from dataclasses import dataclass

from rag_attack_lab.config import Settings
from rag_attack_lab.providers import get_chat_model
from rag_attack_lab.retriever import RetrievedChunk, retrieve

PROMPT_TEMPLATE = """You are a helpful assistant for Northwind Gadgets employees and customers.
Answer the question using only the context below. If the answer is not in the context, say you don't know.

Context:
{context}

Question: {question}

Answer:"""


@dataclass
class RagResult:
    question: str
    prompt: str
    answer: str
    chunks: list[RetrievedChunk]


def build_prompt(question: str, chunks: list[RetrievedChunk]) -> str:
    """Put the retrieved chunks and the question into the prompt template."""
    context = "\n\n".join(f"[Source: {chunk.source}]\n{chunk.text}" for chunk in chunks)
    return PROMPT_TEMPLATE.format(context=context, question=question)


def answer_question(question: str, settings: Settings) -> RagResult:
    """Run the full pipeline for one question."""
    chunks = retrieve(question, settings)
    prompt = build_prompt(question, chunks)
    response = get_chat_model(settings).invoke(prompt)
    return RagResult(question=question, prompt=prompt, answer=str(response.content), chunks=chunks)
