from embeddings.embedding import EmbeddingGenerator

model = EmbeddingGenerator()

vector = model.embed_document(
    "Failed password for root from 192.168.1.10 port 22 ssh2"
)

print(type(vector))
print(len(vector))
print(vector[:10])