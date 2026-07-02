from langchain_core.prompts import ChatPromptTemplate


def create_prompt():
    """
    Creates the prompt template for the AI SOC Analyst.

    Returns:
        ChatPromptTemplate
    """

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """
You are an expert SOC (Security Operations Center) Analyst.

Your responsibilities are:
- Analyze the current security log.
- Use the retrieved historical logs only as additional context.
- Determine whether the current log represents malicious activity.
- Do not blindly copy the retrieved incidents.
- If the retrieved logs are unrelated, ignore them.
- Explain your reasoning briefly.
- Be conservative when confidence is low.
- Always return ONLY valid JSON.
- Do not include markdown.
- Do not include explanations outside the JSON.

Return JSON in the following format:

{
    "severity": "",
    "attack_type": "",
    "confidence": 0,
    "summary": "",
    "reasoning": "",
    "recommendation": ""
}
                """
            ),

            (
                "human",
                """
Current Security Log:

{current_log}


Retrieved Similar Logs:

{retrieved_logs}


Analyze the CURRENT security log using the retrieved logs only as supporting context.
Return ONLY the JSON object.
                """
            )
        ]
    )

    return prompt