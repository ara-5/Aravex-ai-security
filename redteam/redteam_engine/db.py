"""SQLAlchemy models + session for the red-team engine (AgentShield)."""
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, Column, Integer, String, Text, DateTime, Boolean, Float
from sqlalchemy.orm import declarative_base, sessionmaker

from redteam_engine.config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {},
)

if DATABASE_URL.startswith("sqlite"):
    # WAL lets readers and writers proceed concurrently instead of
    # serializing on a single file lock -- needed now that the planner
    # (planner.py) runs multiple techniques' attempts from worker threads,
    # each with its own session/connection.
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


class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    status = Column(String, default="running")  # running | completed
    started_at = Column(DateTime, default=now)
    finished_at = Column(DateTime, nullable=True)
    categories = Column(Text)  # JSON list


class AttackAttempt(Base):
    __tablename__ = "attack_attempts"
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, index=True)
    session_id = Column(String)
    category = Column(String)
    technique = Column(String)
    generation = Column(Integer, default=0)  # mutation round
    payload = Column(Text)
    metadata_json = Column(Text, default="{}")
    response_text = Column(Text)
    tool_calls_json = Column(Text)
    success = Column(Boolean, default=False)
    severity = Column(String, default="low")
    confidence = Column(Float, default=0.0)
    evidence = Column(Text)
    llm_judge_verdict = Column(String, nullable=True)  # optional second opinion; never authoritative
    llm_judge_rationale = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, index=True)
    attempt_id = Column(Integer, index=True)
    category = Column(String)
    technique = Column(String)
    severity = Column(String)
    title = Column(String)
    attack_payload = Column(Text)
    attack_metadata_json = Column(Text, default="{}")
    evidence = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    status = Column(String, default="open")  # open | fixed_pending_regression | resolved | regressed
    last_regression_result = Column(String, nullable=True)  # PASS | FAIL
    last_regression_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now)


class ScoreSnapshot(Base):
    """One row per scorecard computation (after every campaign completes,
    and after every regression run) -- lets the dashboard show security
    posture *over time*, not just the current instant."""

    __tablename__ = "score_snapshots"
    id = Column(Integer, primary_key=True)
    overall_score = Column(Float)
    rows_json = Column(Text)  # per-category rows, same shape scorecard.py returns
    severity_counts_json = Column(Text)
    trigger = Column(String)  # "campaign" | "regression"
    trigger_ref = Column(String, nullable=True)  # campaign id or finding id, for context
    created_at = Column(DateTime, default=now)


def init_db():
    Base.metadata.create_all(engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
