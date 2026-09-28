"""
Target agent FastAPI app — the deliberately vulnerable system under test.

Exposes:
  POST /chat            - talk to the agent (what a normal user/attacker hits)
  GET  /admin/state      - introspection for the red-team judge (ground truth:
                            outbox, MCP exfil log, granted scopes, tool logs)
  GET  /admin/canaries    - the planted secret values, for leak detection
  GET  /admin/memory       - dump a session's long-term memory
  POST /admin/documents     - ingest a document into RAG (this is the RAG/
                              cross-document poisoning entry point)
  POST /admin/reset          - wipe state between red-team campaigns/regression runs

The /admin/* routes exist because AgentShield is an AUTHORIZED white-box
tester attacking a system it owns for evaluation purposes — a production
deployment of this agent would never expose them publicly.
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from target_agent.config import PORT, CANARY_API_KEY, CANARY_DB_PASSWORD
from target_agent.db import init_db, get_session, SessionLocal, MemoryEntry, ToolCallLog, AgentMessageLog, ChatTurn
from target_agent.vectorstore import STORE, Document
from target_agent.seed_data import load_seed_data
from target_agent.agents import run_pipeline
from target_agent import tools as tools_mod
from target_agent import mcp_tools

app = FastAPI(title="Target Agent — Nova (intentionally vulnerable)")


@app.on_event("startup")
def startup():
    init_db()
    load_seed_data()


class ChatRequest(BaseModel):
    session_id: str
    message: str


class ChatResponse(BaseModel):
    response: str
    tool_calls: list[dict]
    agent_trace: list[dict]
    memory_written: list[str]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    db = SessionLocal()
    try:
        db.add(ChatTurn(session_id=req.session_id, role="user", content=req.message))
        db.commit()
        result = run_pipeline(db, req.session_id, req.message)
        db.add(ChatTurn(session_id=req.session_id, role="assistant", content=result.final_response))
        db.commit()
        return ChatResponse(
            response=result.final_response,
            tool_calls=result.tool_calls_executed,
            agent_trace=result.agent_trace,
            memory_written=result.memory_written,
        )
    finally:
        db.close()


class DocumentIn(BaseModel):
    doc_id: str
    title: str
    content: str
    trust: str = "external"


@app.post("/admin/documents")
def ingest_document(doc: DocumentIn):
    STORE.add(Document(doc_id=doc.doc_id, title=doc.title, content=doc.content, trust=doc.trust))
    return {"status": "ingested", "doc_count": len(STORE.docs)}


@app.get("/admin/canaries")
def canaries():
    return {"CANARY_API_KEY": CANARY_API_KEY, "CANARY_DB_PASSWORD": CANARY_DB_PASSWORD}


@app.get("/admin/memory")
def memory(session_id: str):
    db = SessionLocal()
    try:
        rows = db.query(MemoryEntry).filter(MemoryEntry.session_id == session_id).all()
        return [{"content": r.content, "source": r.source, "created_at": str(r.created_at)} for r in rows]
    finally:
        db.close()


@app.get("/admin/state")
def state(session_id: str | None = None):
    db = SessionLocal()
    try:
        tool_q = db.query(ToolCallLog)
        agent_q = db.query(AgentMessageLog)
        if session_id:
            tool_q = tool_q.filter(ToolCallLog.session_id == session_id)
            agent_q = agent_q.filter(AgentMessageLog.session_id == session_id)
        tool_logs = [
            {
                "tool_name": r.tool_name,
                "arguments": r.arguments,
                "result": r.result,
                "triggered_by": r.triggered_by,
                "privileged": r.privileged,
            }
            for r in tool_q.order_by(ToolCallLog.id.desc()).limit(50).all()
        ]
        agent_msgs = [
            {"from_agent": r.from_agent, "to_agent": r.to_agent, "content": r.content}
            for r in agent_q.order_by(AgentMessageLog.id.desc()).limit(50).all()
        ]
        return {
            "outbox": tools_mod.OUTBOX,
            "mcp_exfil_log": mcp_tools.MCP_EXFIL_LOG,
            "mcp_granted_scopes": mcp_tools.MCP_SESSION_SCOPE,
            "tool_call_logs": tool_logs,
            "agent_messages": agent_msgs,
            "rag_doc_count": len(STORE.docs),
        }
    finally:
        db.close()


@app.post("/admin/reset")
def reset():
    db = SessionLocal()
    try:
        for model in (MemoryEntry, ToolCallLog, AgentMessageLog, ChatTurn):
            db.query(model).delete()
        db.commit()
    finally:
        db.close()
    tools_mod.OUTBOX.clear()
    mcp_tools.MCP_EXFIL_LOG.clear()
    mcp_tools.MCP_SESSION_SCOPE.clear()
    load_seed_data()
    return {"status": "reset"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("target_agent.main:app", host="0.0.0.0", port=PORT, reload=False)
