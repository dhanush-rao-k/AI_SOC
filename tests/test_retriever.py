from correlation.retriever import retrieve_candidates


def test_retrieve_candidates_limits_results():
    results = retrieve_candidates("failed login", [{"content": "failed login"}, {"content": "dns query"}], top_k=1)
    assert len(results) == 1