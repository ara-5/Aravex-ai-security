"""
RAG vector store for the target agent.

Uses FAISS when it's importable (Linux/Docker installs), otherwise falls
back to a small numpy cosine-similarity index so the platform runs
unmodified on Windows without a FAISS wheel. Embeddings are a simple
deterministic hashing embedding when no Ollama embedding model is
reachable, so RAG works fully offline.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re

import numpy as np

try:
    import faiss  # type: ignore

    _HAS_FAISS = True
except Exception:
    _HAS_FAISS = False

EMBED_DIM = 256


def _hash_embed(text: str) -> np.ndarray:
    """Deterministic bag-of-hashed-tokens embedding — no external model
    required. Good enough for nearest-neighbour retrieval demos; swap in
    real embeddings (Ollama /api/embeddings, sentence-transformers) for
    production-quality RAG."""
    vec = np.zeros(EMBED_DIM, dtype="float32")
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    for tok in tokens:
        h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
        vec[h % EMBED_DIM] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


@dataclasses.dataclass
class Document:
    doc_id: str
    title: str
    content: str
    trust: str = "external"  # "internal" | "external" — provenance label, NOT enforced (that's the vuln)


class VectorStore:
    def __init__(self):
        self.docs: list[Document] = []
        self._matrix: np.ndarray | None = None
        self._faiss_index = None

    def add(self, doc: Document):
        self.docs.append(doc)
        self._rebuild()

    def add_many(self, docs: list[Document]):
        self.docs.extend(docs)
        self._rebuild()

    def clear(self):
        self.docs = []
        self._matrix = None
        self._faiss_index = None

    def _rebuild(self):
        if not self.docs:
            self._matrix = None
            self._faiss_index = None
            return
        embs = np.stack([_hash_embed(d.content) for d in self.docs])
        if _HAS_FAISS:
            index = faiss.IndexFlatIP(EMBED_DIM)
            index.add(embs)
            self._faiss_index = index
            self._matrix = embs
        else:
            self._matrix = embs
            self._faiss_index = None

    def search(self, query: str, k: int = 3) -> list[tuple[Document, float]]:
        if not self.docs:
            return []
        q = _hash_embed(query).reshape(1, -1)
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
