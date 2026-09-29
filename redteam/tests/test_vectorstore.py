"""
Vector store backend tests: the local FAISS/numpy store (default) and the
Qdrant-backed store (VECTOR_BACKEND=qdrant) must behave identically from
the caller's point of view -- same duck-typed interface, same ranking
behavior given the same embeddings.
"""
import importlib

from target_agent.vectorstore import Document, LocalVectorStore


def test_local_vector_store_ranks_relevant_doc_first():
    store = LocalVectorStore()
    store.add_many([
        Document(doc_id="d1", title="PTO Policy", content="Employees accrue paid time off. Submit PTO requests through HR."),
        Document(doc_id="d2", title="Pricing", content="Standard tier is 49 dollars per month, pro tier is 199."),
    ])
    hits = store.search("what is the PTO policy for requesting time off", k=2)
    assert hits[0][0].title == "PTO Policy"


def test_qdrant_backend_in_memory_matches_local_ranking(monkeypatch):
    try:
        import qdrant_client  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("qdrant-client not installed")

    monkeypatch.setenv("VECTOR_BACKEND", "qdrant")
    monkeypatch.setenv("QDRANT_URL", ":memory:")
    import target_agent.config as config_mod
    importlib.reload(config_mod)
    import target_agent.vectorstore as vs_mod
    importlib.reload(vs_mod)

    try:
        store = vs_mod.create_vector_store()
        assert type(store).__name__ == "QdrantVectorStore"

        store.add_many([
            vs_mod.Document(doc_id="d1", title="PTO Policy", content="Employees accrue paid time off. Submit PTO requests through HR."),
            vs_mod.Document(doc_id="d2", title="Pricing", content="Standard tier is 49 dollars per month, pro tier is 199."),
        ])
        assert len(store.docs) == 2

        hits = store.search("what is the PTO policy for requesting time off", k=2)
        assert hits[0][0].title == "PTO Policy"

        store.clear()
        assert len(store.docs) == 0
    finally:
        monkeypatch.delenv("VECTOR_BACKEND", raising=False)
        monkeypatch.delenv("QDRANT_URL", raising=False)
        importlib.reload(config_mod)
        importlib.reload(vs_mod)


def test_qdrant_unreachable_falls_back_to_local(monkeypatch):
    monkeypatch.setenv("VECTOR_BACKEND", "qdrant")
    monkeypatch.setenv("QDRANT_URL", "http://localhost:1/nonexistent")
    import target_agent.config as config_mod
    importlib.reload(config_mod)
    import target_agent.vectorstore as vs_mod
    importlib.reload(vs_mod)

    try:
        store = vs_mod.create_vector_store()
        assert type(store).__name__ == "LocalVectorStore"
    finally:
        monkeypatch.delenv("VECTOR_BACKEND", raising=False)
        monkeypatch.delenv("QDRANT_URL", raising=False)
        importlib.reload(config_mod)
        importlib.reload(vs_mod)
