from langchain_ollama import ChatOllama
from config import *

def create_llm():
    return ChatOllama(
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE,
        num_predict=MAX_TOKENS,
    )