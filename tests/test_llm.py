from llm.chain import create_chain


def test_create_chain_is_callable():
    assert callable(create_chain)