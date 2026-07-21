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

            "Large outbound transfer: 192.168.10.20 sent 2.1GB to 185.220.101.99 port 443",

            "Failed password for root from 203.0.113.45 port 22 ssh2",

            "Accepted password for ubuntu from 10.0.0.15 port 22 ssh2",

            "POST /api/export HTTP/1.1 200 from 192.168.10.20 Python/3.11",

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
    # Test Log — Data Exfiltration via HTTPS
    # -------------------------------------------------

    log = (
        "Jul 22 09:55:44 dlp-sensor snort[5005]: "
        "Data exfiltration alert: 192.168.10.20 "
        "transmitted 2.3GB to external host 185.220.101.99 port 443 "
        "over 4 minutes via HTTPS. "
        "User-Agent: Python/3.11 requests/2.31.0. "
        "Matched DLP rule: PII-CREDIT-CARD-BULK-EXPORT."
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
