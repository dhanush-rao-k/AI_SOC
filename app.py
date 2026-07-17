from pipeline import AISOCPipeline
from vectorstore.faiss_store import FAISSStore


store = FAISSStore()

store.load()

pipeline = AISOCPipeline(store)


log = input("Enter log: ")


context = pipeline.analyze(log)


print(context.incident_report)