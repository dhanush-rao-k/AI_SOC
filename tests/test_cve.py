from enrichment.cve import CVELookup
from ingestion.software import Software


def print_results(title, vulnerabilities):

    print("=" * 60)
    print(title)
    print("=" * 60)

    if not vulnerabilities:
        print("No CVEs Found")
        print()
        return

    for cve in vulnerabilities:
        print(cve)
        print()


def main():

    lookup = CVELookup()

    software = [

        Software(
            name="OpenSSH",
            version="8.2"
        ),

        Software(
            name="Log4j",
            version="2.17.1"
        ),

        Software(
            name="Apache",
            version="2.4.57"
        ),

        Software(
            name="UnknownSoftware",
            version="1.0"
        )

    ]

    vulnerabilities = lookup.lookup_all(
        software
    )

    print_results(
        "Detected CVEs",
        vulnerabilities
    )


if __name__ == "__main__":
    main()