from config import *
from langchain_ollama import ChatOllama


def create_llm(
    model: str = "mistral",
    temperature: float = 0.0,
    num_predict: int = 512,
):
    """
    Returns a configured Ollama LLM.
    """

return ChatOllama(
    model=MODEL_NAME,
    temperature=TEMPERATURE,
    num_predict=MAX_TOKENS,
)