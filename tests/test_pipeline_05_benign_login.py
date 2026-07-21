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

            "Accepted password for alice from 192.168.0.50 port 22 ssh2",

            "Accepted password for bob from 192.168.0.51 port 22 ssh2",

            "Failed password for root from 203.0.113.45 port 22 ssh2",

            "Invalid user guest from 198.51.100.7 port 22",

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
    # Test Log — Benign Login from known internal IP
    # -------------------------------------------------

    log = (
        "Jul 22 08:01:05 corp-server sshd[4410]: "
        "Accepted password for alice "
        "from 192.168.0.50 port 55210 ssh2 "
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
