"""SQLAlchemy models + session for the target agent."""
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

from target_agent.config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {},
)

if DATABASE_URL.startswith("sqlite"):
    # The red-team engine's planner now fires concurrent chat requests
    # from multiple worker threads (planner.py) -- WAL lets those
    # requests' independent DB sessions proceed without serializing on a
    # single file lock.
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def now():
    return datetime.now(timezone.utc)


class MemoryEntry(Base):
    """Long-term memory. Deliberately weak: any 'remember this' style
    instruction from a user message, a retrieved document, or a tool
    output gets written here verbatim and is re-injected into every
    future conversation for that session — a classic memory-poisoning
    surface."""

    __tablename__ = "memory_entries"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    content = Column(Text)
    source = Column(String)  # "user" | "document" | "tool_output" | "agent"
    created_at = Column(DateTime, default=now)


class ToolCallLog(Base):
    __tablename__ = "tool_call_logs"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    tool_name = Column(String)
    arguments = Column(Text)
    result = Column(Text)
    triggered_by = Column(String)  # "user" | "document" | "tool_output" | "agent"
    privileged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=now)


class AgentMessageLog(Base):
    """Inter-agent messages, for detecting agent-to-agent propagation attacks."""

    __tablename__ = "agent_message_logs"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    from_agent = Column(String)
    to_agent = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=now)


class ChatTurn(Base):
    __tablename__ = "chat_turns"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    role = Column(String)  # "user" | "assistant"
    content = Column(Text)
    created_at = Column(DateTime, default=now)


def init_db():
    Base.metadata.create_all(engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
