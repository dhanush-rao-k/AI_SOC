from ingestion.metadata import MetadataExtractor


def main():

    extractor = MetadataExtractor()

    logs = [

        "Failed password for root from 192.168.1.10 port 22 ssh2",

        "Accepted password for ubuntu from 10.0.0.15 port 52144 ssh2",

        "Invalid user admin from 172.16.1.25 port 22",

        "Connection refused from 8.8.8.8 port 443"

    ]

    for i, log in enumerate(logs, start=1):

        print("=" * 60)

        print(f"Test Case {i}")

        print("=" * 60)

        print(log)

        metadata = extractor.extract_metadata(log)

        print()

        print(metadata)

        print()


if __name__ == "__main__":
    main()