"""Database engine setup, base class, and session provider."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger("db.database")

# Ensure SQLite handles thread sharing for FastAPI
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Create all database tables on application initialization."""
    # Import all models to ensure registration with Base.metadata
    from app.models.telemetry import TelemetryRecord
    from app.models.security_event import SecurityEventRecord
    
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully.")


def get_db():
    """FastAPI dependency for yielding database sessions with automatic closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
