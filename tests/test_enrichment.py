from enrichment.engine import EnrichmentEngine
from enrichment.ioc import IOC
from ingestion.software import Software


def main():

    engine = EnrichmentEngine()

    ioc = IOC(

        ip_addresses=[
            "8.8.8.8"
        ],

        domains=[
            "google.com"
        ],

        urls=[
            "https://google.com"
        ],

        file_hashes=[
            "44d88612fea8a8f36de82e1278abb02f"
        ],

        emails=[]

    )

    software = [

        Software(
            name="OpenSSH",
            version="8.2p1"
        ),

        Software(
            name="Apache",
            version="2.4.57"
        ),

        Software(
            name="Log4j",
            version="2.17.1"
        )

    ]

    intel = engine.enrich(

        ioc,

        software,

        "FAILED_LOGIN"

    )

    # --------------------------------------------------

    print("=" * 60)
    print("Threat Indicators")
    print("=" * 60)

    for indicator in intel.indicators:

        print(indicator)

        print()

    # --------------------------------------------------

    print("=" * 60)
    print("MITRE")
    print("=" * 60)

    for technique in intel.mitre_results:

        print(technique)

        print()

    # --------------------------------------------------

    print("=" * 60)
    print("GeoIP")
    print("=" * 60)

    for geo in intel.geo_locations:

        print(geo)

        print()

    # --------------------------------------------------

    print("=" * 60)
    print("CVEs")
    print("=" * 60)

    for cve in intel.cve_results:

        print(cve)

        print()


if __name__ == "__main__":
    main()