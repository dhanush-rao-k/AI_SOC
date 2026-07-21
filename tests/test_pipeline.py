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

            "Failed password for root from 192.168.1.10 port 22 ssh2",

            "Accepted password for ubuntu from 10.0.0.15 port 52144 ssh2",

            "Invalid user admin from 172.16.1.25 port 22",

            "Failed password for admin from 192.168.1.10 port 22 ssh2"

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
    # Test Log
    # -------------------------------------------------

    log = (
        "Failed password for root "
        "from 192.168.1.10 "
        "port 22 ssh2 "
        "OpenSSH_8.2p1"
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
    # Retrieval
    # -------------------------------------------------

    print_section("Retrieved Logs")

    for result in context.similar_logs:

        print(f"Similarity: {result.similarity:.3f}")
        print(result.document.log)
        print()

    # -------------------------------------------------
    # Threat Intel
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