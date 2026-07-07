from config import MAX_TOKENS, MODEL_NAME, TEMPERATURE
from langchain_ollama import ChatOllama


def create_llm(
    model: str = MODEL_NAME,
    temperature: float = TEMPERATURE,
    num_predict: int = MAX_TOKENS,
):
    """Return a configured Ollama chat model."""

    return ChatOllama(
        model=model,
        temperature=temperature,
        num_predict=num_predict,
    )