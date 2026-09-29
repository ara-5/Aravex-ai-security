"""
RAG vector store for the target agent.

Two backends (VECTOR_BACKEND):
  - "local" (default): FAISS when importable (Linux/Docker installs),
    otherwise a small numpy cosine-similarity index -- zero extra
    services, runs unmodified on Windows without a FAISS wheel.
  - "qdrant": a real Qdrant collection. Works against a real server
    (QDRANT_URL, e.g. the `qdrant` docker-compose profile) or, with
    QDRANT_URL=":memory:", an embedded in-process instance -- same
    client code path as production, zero extra services, which is what
    tests/CI use.

Both implement the same duck-typed interface (`docs`, `add`, `add_many`,
`clear`, `search`), so nothing elsewhere in the codebase (agents.py,
seed_data.py, main.py) needs to know which one is active. If Qdrant is
configured but unreachable at startup, `create_vector_store()` falls
back to the local backend rather than crashing RAG entirely.

Embeddings are pluggable separately (EmbeddingProvider): a deterministic
hashing embedding by default (zero dependencies, works fully offline), or
a real Ollama embedding model (EMBEDDING_PROVIDER=ollama) for
production-quality retrieval. If the Ollama embedding endpoint is
unreachable, the store probes it once at construction time and
permanently falls back to the hash provider for that process (mixing
embedding spaces mid-index would silently break cosine similarity, so
the fallback is all-or-nothing).
"""
from __future__ import annotations

import abc
import dataclasses
import hashlib
import re
import threading

import httpx
import numpy as np

from target_agent import config

try:
    import faiss  # type: ignore

    _HAS_FAISS = True
except Exception:
    _HAS_FAISS = False

HASH_EMBED_DIM = 256


class EmbeddingProvider(abc.ABC):
    name: str
    dim: int

    @abc.abstractmethod
    def embed(self, text: str) -> np.ndarray: ...


class HashEmbeddingProvider(EmbeddingProvider):
    """Deterministic bag-of-hashed-tokens embedding — no external model
    required. Good enough for nearest-neighbour retrieval demos."""

    name = "hash"
    dim = HASH_EMBED_DIM

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype="float32")
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        for tok in tokens:
            h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
            vec[h % self.dim] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec


class OllamaEmbeddingProvider(EmbeddingProvider):
    name = "ollama"

    def __init__(self, host: str = config.OLLAMA_HOST, model: str = config.OLLAMA_EMBEDDING_MODEL):
        self.host = host
        self.model = model
        self.dim = 0  # probed lazily

    def _call(self, text: str) -> np.ndarray | None:
        try:
            resp = httpx.post(f"{self.host}/api/embeddings", json={"model": self.model, "prompt": text}, timeout=15.0)
            resp.raise_for_status()
            vec = np.array(resp.json()["embedding"], dtype="float32")
            norm = np.linalg.norm(vec)
            return vec / norm if norm > 0 else vec
        except Exception:
            return None

    def probe(self) -> bool:
        vec = self._call("connectivity probe")
        if vec is None:
            return False
        self.dim = len(vec)
        return True

    def embed(self, text: str) -> np.ndarray:
        vec = self._call(text)
        if vec is None:
            raise RuntimeError("Ollama embedding endpoint became unreachable mid-session")
        return vec


def _select_embedding_provider() -> EmbeddingProvider:
    if config.EMBEDDING_PROVIDER == "ollama":
        provider = OllamaEmbeddingProvider()
        if provider.probe():
            return provider
        # Unreachable at startup: stay on hash embeddings for this process
        # rather than mixing embedding spaces or crashing RAG entirely.
    return HashEmbeddingProvider()


@dataclasses.dataclass
class Document:
    doc_id: str
    title: str
    content: str
    trust: str = "external"  # "internal" | "external" — provenance label, NOT enforced (that's the vuln)


class QdrantVectorStore:
    """Real Qdrant-backed store, behind the exact same duck-typed
    interface as LocalVectorStore. `QDRANT_URL=":memory:"` runs Qdrant's
    embedded engine in-process (same client/API calls as a real server,
    zero extra services) -- what tests and the default "local" fallback
    check use; point it at a real server (docker-compose's `qdrant`
    profile) for a genuinely multi-worker deployment."""

    def __init__(self, embedding_provider: EmbeddingProvider):
        from qdrant_client import QdrantClient  # optional dependency

        self.embedding_provider = embedding_provider
        self.collection = config.QDRANT_COLLECTION
        self._lock = threading.RLock()
        self._docs_by_id: dict[int, Document] = {}
        url = config.QDRANT_URL
        self.client = QdrantClient(location=url) if url == ":memory:" else QdrantClient(url=url)
        self._ensure_collection()

    def _ensure_collection(self):
        from qdrant_client.models import Distance, VectorParams

        existing = [c.name for c in self.client.get_collections().collections]
        if self.collection not in existing:
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(size=self.embedding_provider.dim, distance=Distance.COSINE),
            )

    def health_check(self):
        self.client.get_collections()  # raises if unreachable

    @property
    def docs(self) -> list[Document]:
        with self._lock:
            return list(self._docs_by_id.values())

    def add(self, doc: Document):
        self.add_many([doc])

    def add_many(self, docs: list[Document]):
        from qdrant_client.models import PointStruct

        with self._lock:
            points = []
            next_id = len(self._docs_by_id)
            for i, doc in enumerate(docs):
                point_id = next_id + i
                self._docs_by_id[point_id] = doc
                vec = self.embedding_provider.embed(doc.content)
                points.append(PointStruct(id=point_id, vector=vec.tolist(), payload={"doc_id": doc.doc_id}))
            if points:
                self.client.upsert(collection_name=self.collection, points=points)

    def clear(self):
        with self._lock:
            self._docs_by_id.clear()
            self.client.delete_collection(self.collection)
            self._ensure_collection()

    def search(self, query: str, k: int = 3) -> list[tuple[Document, float]]:
        with self._lock:
            if not self._docs_by_id:
                return []
            qvec = self.embedding_provider.embed(query)
            hits = self.client.query_points(
                collection_name=self.collection, query=qvec.tolist(), limit=min(k, len(self._docs_by_id))
            ).points
            return [(self._docs_by_id[h.id], float(h.score)) for h in hits if h.id in self._docs_by_id]


class LocalVectorStore:
    """FastAPI runs sync `def` route handlers in a thread pool, so with
    the red-team engine's planner firing concurrent chat requests
    (planner.py, MAX_WORKERS), this process-wide singleton IS accessed
    from multiple threads at once. A doc ingested by one request's
    _rebuild() racing against another request's search() would otherwise
    intermittently read a torn `docs`/`_matrix` pair (wrong-length
    embeddings, or index-out-of-range) and 500 -- silently dropping
    unrelated in-flight attack attempts. One lock around every mutation
    and read keeps it simple and correct; the store is small enough that
    this is not a real bottleneck."""

    def __init__(self, embedding_provider: EmbeddingProvider | None = None):
        self.embedding_provider = embedding_provider or _select_embedding_provider()
        self.docs: list[Document] = []
        self._matrix: np.ndarray | None = None
        self._faiss_index = None
        self._lock = threading.RLock()

    def add(self, doc: Document):
        with self._lock:
            self.docs.append(doc)
            self._rebuild()

    def add_many(self, docs: list[Document]):
        with self._lock:
            self.docs.extend(docs)
            self._rebuild()

    def clear(self):
        with self._lock:
            self.docs = []
            self._matrix = None
            self._faiss_index = None

    def _rebuild(self):
        # Caller holds self._lock.
        if not self.docs:
            self._matrix = None
            self._faiss_index = None
            return
        embs = np.stack([self.embedding_provider.embed(d.content) for d in self.docs])
        if _HAS_FAISS:
            index = faiss.IndexFlatIP(self.embedding_provider.dim)
            index.add(embs)
            self._faiss_index = index
            self._matrix = embs
        else:
            self._matrix = embs
            self._faiss_index = None

    def search(self, query: str, k: int = 3) -> list[tuple[Document, float]]:
        with self._lock:
            if not self.docs:
                return []
            q = self.embedding_provider.embed(query).reshape(1, -1)
            if _HAS_FAISS and self._faiss_index is not None:
                scores, idxs = self._faiss_index.search(q, min(k, len(self.docs)))
                return [(self.docs[i], float(scores[0][n])) for n, i in enumerate(idxs[0]) if i != -1]
            sims = (self._matrix @ q.T).flatten()
            top = np.argsort(-sims)[:k]
            return [(self.docs[i], float(sims[i])) for i in top]


def create_vector_store():
    """Picks the vector store backend from config.VECTOR_BACKEND. Falls
    back to the local backend if Qdrant is configured but unreachable at
    startup, so a misconfigured/down Qdrant degrades RAG quality-wise
    rather than crashing the whole agent."""
    embedding_provider = _select_embedding_provider()
    if config.VECTOR_BACKEND == "qdrant":
        try:
            store = QdrantVectorStore(embedding_provider)
            store.health_check()
            return store
        except Exception:
            pass  # unreachable/not installed -- fall back below
    return LocalVectorStore(embedding_provider)


# Process-wide singleton (per target_agent process). Backed by FAISS/numpy
# by default, or a real Qdrant collection (VECTOR_BACKEND=qdrant) for a
# genuinely multi-worker deployment.
STORE = create_vector_store()
