from enrichment.mitre import MitreLookup


def print_result(title, result):

    print("=" * 60)
    print(title)
    print("=" * 60)

    print(result)
    print()


def main():

    mitre = MitreLookup()

    events = [

        "FAILED_LOGIN",

        "SUCCESSFUL_LOGIN",

        "INVALID_USER",

        "CONNECTION_REFUSED",

        "UNKNOWN_EVENT"

    ]

    for event in events:

        result = mitre.lookup(event)

        print_result(event, result)


if __name__ == "__main__":
    main()