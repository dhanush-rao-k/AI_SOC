from llm.model import create_llm
from llm.parser import get_parser
from llm.prompt import create_prompt


def create_chain():

    llm = create_llm()

    prompt = create_prompt()

    parser = get_parser()

    return prompt | llm | parser