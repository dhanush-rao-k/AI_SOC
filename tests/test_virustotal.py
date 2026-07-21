from enrichment.virustotal import VirusTotalClient


def print_result(title, result):

    print("=" * 60)
    print(title)
    print("=" * 60)

    print(result)
    print()


def main():

    vt = VirusTotalClient()

    # -------------------------------------------------

    ip = vt.lookup_ip("8.8.8.8")

    print_result("IP", ip)

    # -------------------------------------------------

    domain = vt.lookup_domain("google.com")

    print_result("DOMAIN", domain)

    # -------------------------------------------------

    hash_result = vt.lookup_hash(
        "44d88612fea8a8f36de82e1278abb02f"
    )

    print_result("HASH", hash_result)


if __name__ == "__main__":
    main()