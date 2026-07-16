from vectorstore.faiss_store import SecurityDocument


class CorrelationScorer:

    def __init__(self):

        self.weights = {

            "src_ip": 30,

            "dst_ip": 20,

            "dst_port": 15,

            "protocol": 10,

            "username": 10,

            "event_type": 15

        }

    def score(

        self,

        query: SecurityDocument,

        candidate: SecurityDocument,

        vector_similarity: float

    ) -> float:

        score = vector_similarity * 100

        q = query.metadata

        c = candidate.metadata

        if q.src_ip == c.src_ip:

            score += self.weights["src_ip"]

        if q.dst_ip == c.dst_ip:

            score += self.weights["dst_ip"]

        if q.dst_port == c.dst_port:

            score += self.weights["dst_port"]

        if q.protocol == c.protocol:

            score += self.weights["protocol"]

        if q.username == c.username:

            score += self.weights["username"]

        if q.event_type == c.event_type:

            score += self.weights["event_type"]

        return score