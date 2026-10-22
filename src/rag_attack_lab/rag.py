"""The RAG pipeline: retrieve chunks, build a prompt, generate an answer."""

from dataclasses import dataclass

from rag_attack_lab.config import Settings
from rag_attack_lab.providers import get_chat_model
from rag_attack_lab.retriever import RetrievedChunk, retrieve

# LLM08: the system instructions are plain text in the same prompt as the context and the question.
# Nothing marks them as hidden or stops the model from repeating them in an answer.
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
    # LLM01 (indirect): retrieved document text is pasted in verbatim, with no separation of instructions from data.
    # LLM09: every chunk gets the same [Source: ...] label, whether it came from a trusted or an untrusted file.
    context = "\n\n".join(f"[Source: {chunk.source}]\n{chunk.text}" for chunk in chunks)
    # LLM01 (direct): user input concatenated into the prompt with no sanitization.
    return PROMPT_TEMPLATE.format(context=context, question=question)


def answer_question(question: str, settings: Settings) -> RagResult:
    """Run the full pipeline for one question."""
    chunks = retrieve(question, settings)
    prompt = build_prompt(question, chunks)
    # LLM08: one plain string, no separate system message, and no check that the answer leaks the instructions.
    response = get_chat_model(settings).invoke(prompt)
    return RagResult(question=question, prompt=prompt, answer=str(response.content), chunks=chunks)
