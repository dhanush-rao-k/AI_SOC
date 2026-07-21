from vectorstore.faiss_store import FAISSStore

from ingestion.metadata import Metadata


store = FAISSStore()


print("=" * 60)
print("Initial Count")
print("=" * 60)

print(store.count())


store.add_document(

    "Failed password for root from 192.168.1.10 port 22 ssh2",

    Metadata(

        src_ip="192.168.1.10",

        dst_ip=None,

        src_port=None,

        dst_port=22,

        username="root",

        protocol="SSH",

        timestamp=None,

        hostname=None,

        process=None,

        event_type="FAILED_LOGIN"

    )

)

store.add_document(

    "Accepted password for ubuntu from 10.0.0.15 port 22 ssh2",

    Metadata(

        src_ip="10.0.0.15",

        dst_ip=None,

        src_port=None,

        dst_port=22,

        username="ubuntu",

        protocol="SSH",

        timestamp=None,

        hostname=None,

        process=None,

        event_type="SUCCESSFUL_LOGIN"

    )

)

store.add_document(

    "Invalid user admin from 172.16.1.25 port 22",

    Metadata(

        src_ip="172.16.1.25",

        dst_ip=None,

        src_port=None,

        dst_port=22,

        username="admin",

        protocol="SSH",

        timestamp=None,

        hostname=None,

        process=None,

        event_type="INVALID_USER"

    )

)

print()

print("=" * 60)
print("After Insert")
print("=" * 60)

print(store.count())

print()

print("=" * 60)
print("Search")
print("=" * 60)

results = store.search(

    "Failed password from root",

    k=3

)

for result in results:

    print(result.similarity)

    print(result.document.log)

    print()

store.save()


print("=" * 60)
print("Reload")
print("=" * 60)

new_store = FAISSStore()

new_store.load()

print(new_store.count())

print()

results = new_store.search(

    "Failed password from root",

    k=3

)

for result in results:

    print(result.similarity)

    print(result.document.log)

    print()