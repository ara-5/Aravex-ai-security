"""SQLAlchemy models + session for the red-team engine (AgentShield)."""
from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float
from sqlalchemy.orm import declarative_base, sessionmaker

from redteam_engine.config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
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


def init_db():
    Base.metadata.create_all(engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
