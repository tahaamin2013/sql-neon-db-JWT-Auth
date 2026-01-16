from sqlmodel import SQLModel, create_engine, Session
from config import get_settings

settings = get_settings()

engine = create_engine(settings.database_url, echo=True)


def create_db_and_tables():
    """Create all tables in the database."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """Dependency that provides database sessions."""
    with Session(engine) as session:
        yield session