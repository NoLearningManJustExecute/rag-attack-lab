"""Chat model providers.

- ollama: a local model served by Ollama (the default).
- anthropic: optional; needs `pip install langchain-anthropic` and ANTHROPIC_API_KEY.
- fake: a deterministic offline model for tests.
"""

from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from rag_attack_lab.config import Settings

FAKE_ANSWER = "This is a fake answer from the offline test provider."


def get_chat_model(settings: Settings) -> BaseChatModel:
    """Return the chat model selected by settings.llm_provider."""
    provider = settings.llm_provider

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=settings.ollama_chat_model,
            base_url=settings.ollama_base_url,
            temperature=settings.llm_temperature,
        )

    if provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as error:
            raise RuntimeError(
                "LLM_PROVIDER=anthropic needs the optional package: pip install langchain-anthropic"
            ) from error
        # ChatAnthropic reads ANTHROPIC_API_KEY from the environment.
        return ChatAnthropic(model=settings.anthropic_model, temperature=settings.llm_temperature)

    if provider == "fake":
        return FakeListChatModel(responses=[FAKE_ANSWER])

    raise ValueError(f"Unknown LLM_PROVIDER: {provider!r}. Use ollama, anthropic, or fake.")


def describe_model(settings: Settings) -> str:
    """A short label for the active model, for display in the CLI."""
    labels = {
        "ollama": f"ollama/{settings.ollama_chat_model}",
        "anthropic": f"anthropic/{settings.anthropic_model}",
        "fake": "fake/offline",
    }
    return labels.get(settings.llm_provider, settings.llm_provider)
