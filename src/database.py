"""Async database engine and session management.

Uses aiosqlite for prototype (Windows ARM64 compatible).
Switch to asyncpg + PostgreSQL for production deployment.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.config import get_settings

settings = get_settings()

# Use SQLite for prototype (no asyncpg compile needed on Windows ARM64)
# For production: switch to settings.database_url (PostgreSQL + asyncpg)
SQLITE_URL = "sqlite+aiosqlite:///soc_database.db"

engine = create_async_engine(
    SQLITE_URL,
    echo=settings.log_level == "DEBUG",
    pool_pre_ping=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables."""
    from src.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Dispose the engine connection pool."""
    await engine.dispose()