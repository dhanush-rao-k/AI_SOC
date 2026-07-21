from langchain_core.prompts import ChatPromptTemplate

from llm.parser import get_parser


def create_prompt():

    parser = get_parser()

    return ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """
You are a Senior SOC Analyst.

You are provided:

1. Current security log
2. Parsed metadata
3. Threat intelligence
4. Similar historical incidents
5. Calculated risk score
6. Calculated confidence score

Do NOT invent threat intelligence.

Do NOT change the calculated risk.

Use the supplied evidence to explain:

- What happened
- Why it happened
- MITRE ATT&CK mapping
- IOC analysis
- CVE impact
- Recommended response

Return ONLY valid JSON.

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