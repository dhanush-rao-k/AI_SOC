from enrichment.ioc import IOCExtractor


def main():

    extractor = IOCExtractor()

    log = """
Failed password for root from 192.168.1.10 port 22 ssh2

Downloaded malware from https://malicious-site.com/payload.exe

Connected to evil.example.com

SHA256:
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

MD5:
44d88612fea8a8f36de82e1278abb02f

SHA1:
da39a3ee5e6b4b0d3255bfef95601890afd80709
"""

    ioc = extractor.extract_iocs(log)

    print("=" * 60)
    print("IP Addresses")
    print("=" * 60)

    for ip in ioc.ip_addresses:
        print(ip)

    print()

    print("=" * 60)
    print("Domains")
    print("=" * 60)

    for domain in ioc.domains:
        print(domain)

    print()

    print("=" * 60)
    print("URLs")
    print("=" * 60)

    for url in ioc.urls:
        print(url)

    print()

    print("=" * 60)
    print("Hashes")
    print("=" * 60)

    for h in ioc.file_hashes:
        print(h)


if __name__ == "__main__":
    main()