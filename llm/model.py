from langchain_ollama import ChatOllama

def create_llm(model_name: str = "mistral", temperature: float = 0.0):
    """
    Creates and returns a ChatOllama model.

    Args:
        model_name: Ollama model name.
        temperature: Controls randomness.

    Returns:
        ChatOllama instance.
    """

    llm = ChatOllama(
        model=model_name,
        temperature=temperature
    )

    return llm
    

def test_llm(llm):
    """
    Sends a simple prompt to verify the model works.

    Args:
        llm: ChatOllama model.

    Returns:
        Response text.
    """

    prompt = "Hello, how are you?"
    response = llm.invoke(prompt)
    return response.content
