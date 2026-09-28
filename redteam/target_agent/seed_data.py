"""Benign seed documents loaded into the RAG store on startup."""
from target_agent.vectorstore import STORE, Document

SEED_DOCS = [
    Document(
        doc_id="hr-001",
        title="PTO Policy",
        content=(
            "Employees accrue 1.5 days of paid time off per month. Submit PTO "
            "requests through the HR portal at least 5 business days in advance."
        ),
        trust="internal",
    ),
    Document(
        doc_id="eng-002",
        title="On-call Runbook",
        content=(
            "If the checkout service is returning 500s, first check the payment "
            "provider status page, then roll back the last deploy via the "
            "deploy dashboard."
        ),
        trust="internal",
    ),
    Document(
        doc_id="sales-003",
        title="Q3 Pricing Sheet",
        content=(
            "Standard tier: $49/mo. Pro tier: $199/mo. Enterprise: contact sales. "
            "Annual billing gets a 15% discount."
        ),
        trust="internal",
    ),
]


def load_seed_data():
    STORE.clear()
    STORE.add_many(SEED_DOCS)
