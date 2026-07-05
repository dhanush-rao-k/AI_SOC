from langchain_core.prompts import ChatPromptTemplate

from llm.parser import get_parser


def create_prompt():

    parser = get_parser()

    return ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """
You are an expert SOC Analyst.

Responsibilities:

- Analyse ONLY the current log.
- Use retrieved logs only as supporting context.
- Ignore unrelated retrieved logs.
- Never hallucinate.
- Be conservative if confidence is low.
- Produce only valid JSON.

{format_instructions}
                """,
            ),
            (
                "human",
                """
Current Log

{current_log}


Retrieved Logs

{retrieved_logs}
                """,
            ),
        ]
    ).partial(
        format_instructions=parser.get_format_instructions()
    )