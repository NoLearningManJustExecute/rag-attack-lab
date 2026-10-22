"""The RAG pipeline: retrieve chunks, build a prompt, generate an answer.

With SECURE_MODE off this is the vulnerable v1 pipeline. With it on, answer_question() takes the
secure path: fenced context, a separate system message, and an output check. See defenses.py.
"""

from dataclasses import dataclass, field

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from rag_attack_lab.config import Settings
from rag_attack_lab.defenses import (
    INSTRUCTIONS_REFUSAL,
    SECURE_SYSTEM_PROMPT,
    fence_document,
    injection_payloads,
    leaks_instructions,
    strip_payloads,
)
from rag_attack_lab.providers import get_chat_model
from rag_attack_lab.retriever import RetrievedChunk, flagged_texts, retrieve

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
    prompt: str  # what the model was sent, as readable text
    answer: str  # what the user gets back
    chunks: list[RetrievedChunk]
    secure_mode: bool = False
    raw_answer: str = ""  # the model's own answer, before any output check
    guardrails: list[str] = field(default_factory=list)  # output checks that changed the answer


def build_prompt(question: str, chunks: list[RetrievedChunk]) -> str:
    """Put the retrieved chunks and the question into the prompt template."""
    # LLM01 (indirect): retrieved document text is pasted in verbatim, with no separation of instructions from data.
    # LLM09: every chunk gets the same [Source: ...] label, whether it came from a trusted or an untrusted file.
    context = "\n\n".join(f"[Source: {chunk.source}]\n{chunk.text}" for chunk in chunks)
    # LLM01 (direct): user input concatenated into the prompt with no sanitization.
    return PROMPT_TEMPLATE.format(context=context, question=question)


def build_messages(question: str, chunks: list[RetrievedChunk]) -> list[BaseMessage]:
    """The secure prompt: instructions in a system message, fenced documents and the question in a user message."""
    # LLM01 fix: every chunk sits inside <document> tags, and the system message says text in the
    # tags is data, never instructions. LLM08 fix: the instructions travel in their own system-role
    # message instead of in the same string as the user's text.
    documents = "\n\n".join(fence_document(chunk.source, chunk.text) for chunk in chunks)
    user_message = f"Context:\n{documents}\n\nQuestion: {question}"
    return [SystemMessage(content=SECURE_SYSTEM_PROMPT), HumanMessage(content=user_message)]


def render_messages(messages: list[BaseMessage]) -> str:
    """Messages as readable text, for --show-prompt and the findings."""
    return "\n\n".join(f"[{message.type}]\n{message.content}" for message in messages)


def answer_question(question: str, settings: Settings) -> RagResult:
    """Run the full pipeline for one question."""
    chunks = retrieve(question, settings)
    if settings.secure_mode:
        return _answer_securely(question, chunks, settings)

    prompt = build_prompt(question, chunks)
    # LLM08: one plain string, no separate system message, and no check that the answer leaks the instructions.
    response = get_chat_model(settings).invoke(prompt)
    answer = str(response.content)
    return RagResult(question=question, prompt=prompt, answer=answer, chunks=chunks, raw_answer=answer)


def _answer_securely(question: str, chunks: list[RetrievedChunk], settings: Settings) -> RagResult:
    """The SECURE_MODE path. `chunks` are already filtered to public, unflagged documents (LLM02/LLM09 fix)."""
    messages = build_messages(question, chunks)
    response = get_chat_model(settings).invoke(messages)
    raw_answer = str(response.content)

    answer = raw_answer
    guardrails = []
    # LLM01 fix (output check): remove any payload that a flagged document asked the model to say.
    answer, removed = strip_payloads(answer, injection_payloads(flagged_texts(settings)))
    for payload in removed:
        guardrails.append(f'LLM01: removed injected text "{payload}" from the answer.')
    # LLM08 fix (output check): never return an answer that repeats the system instructions.
    if leaks_instructions(raw_answer):
        answer = INSTRUCTIONS_REFUSAL
        guardrails.append("LLM08: answer repeated the system instructions, so it was replaced with a refusal.")

    return RagResult(
        question=question,
        prompt=render_messages(messages),
        answer=answer,
        chunks=chunks,
        secure_mode=True,
        raw_answer=raw_answer,
        guardrails=guardrails,
    )
