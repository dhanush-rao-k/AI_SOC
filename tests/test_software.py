from ingestion.software import SoftwareExtractor


def main():

    extractor = SoftwareExtractor()

    log = """
OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

Apache/2.4.57

nginx/1.22.0

OpenSSL 3.0.2

Log4j 2.17.1

MySQL 8.0.36

PostgreSQL 15.4
"""

    software = extractor.extract(log)

    print("=" * 60)
    print("Detected Software")
    print("=" * 60)

    for s in software:
        print(s)


if __name__ == "__main__":
    main()