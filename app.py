from llm.chain import create_chain


def main():

    chain = create_chain()

    report = chain.invoke(
        {
            "current_log": """
Failed password for root from 192.168.1.25 port 22
""",
            "retrieved_logs": """
SSH brute force from same IP yesterday.

Repeated login failures.

Known attack pattern.
""",
        }
    )

    print(report.model_dump_json(indent=4))


if __name__ == "__main__":
    main()