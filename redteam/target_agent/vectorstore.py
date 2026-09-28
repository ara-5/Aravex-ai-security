"""
RAG vector store for the target agent.

Uses FAISS when it's importable (Linux/Docker installs), otherwise falls
back to a small numpy cosine-similarity index so the platform runs
unmodified on Windows without a FAISS wheel.

Embeddings are pluggable (EmbeddingProvider): a deterministic hashing
embedding by default (zero dependencies, works fully offline), or a real
Ollama embedding model (EMBEDDING_PROVIDER=ollama) for production-quality
retrieval. If the Ollama embedding endpoint is unreachable, the store
probes it once at construction time and permanently falls back to the
hash provider for that process (mixing embedding spaces mid-index would
silently break cosine similarity, so the fallback is all-or-nothing).
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


class VectorStore:
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


# Process-wide singleton (per target_agent process). A real deployment
# would use Qdrant/pgvector for multi-worker sharing; kept in-process here
# so the platform needs no extra services to run.
STORE = VectorStore()
