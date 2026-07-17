"""Database connection — single source, driven by config."""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate():
    """Add new columns to existing SQLite DBs without a migration framework."""
    from sqlalchemy import text
    adds = {
        "entities": [("lat", "FLOAT"), ("lng", "FLOAT"),
                     ("first_seen", "DATETIME"), ("last_seen", "DATETIME")],
    }
    try:
        with engine.connect() as c:
            for table, cols in adds.items():
                have = {r[1] for r in c.execute(text(f"PRAGMA table_info({table})")).fetchall()}
                for name, ddl in cols:
                    if name not in have:
                        c.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
            c.commit()
    except Exception:
        pass
