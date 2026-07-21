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

            "File encrypted: C:\\Users\\Public\\Documents\\report.docx -> report.docx.locked",

            "Failed password for root from 203.0.113.45 port 22 ssh2",

            "Accepted password for ubuntu from 10.0.0.15 port 22 ssh2",

            "Shadow copy deletion detected: vssadmin delete shadows /all",

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
    # Test Log — Ransomware File Encryption Activity
    # -------------------------------------------------

    log = (
        "Jul 22 05:48:02 workstation-07 WinDefend[1812]: "
        "Ransomware behavior detected: process vssadmin.exe "
        "deleted all volume shadow copies. "
        "400 files encrypted with extension .locky "
        "by PID 3944 (payload.exe) connecting to 185.220.101.55 port 443 "
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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
