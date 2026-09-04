"""Shared asynchronous PostgreSQL database access."""

from collections.abc import AsyncIterator
from functools import lru_cache

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from intelgenz_api.core.config import settings


@lru_cache
def get_database_engine() -> AsyncEngine:
    """Create one pooled engine for the configured shared database."""
    database_url = settings.resolved_database_url
    if database_url is None:
        raise RuntimeError("Database connection settings are not configured.")
    return create_async_engine(database_url, pool_pre_ping=True)


@lru_cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the shared async session factory."""
    return async_sessionmaker(get_database_engine(), expire_on_commit=False)


async def get_database_session() -> AsyncIterator[AsyncSession]:
    """Provide a database session to an API request."""
    try:
        session_factory = get_session_factory()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not configured.",
        ) from error

    async with session_factory() as session:
        yield session


async def close_database_engine() -> None:
    """Close the connection pool during application shutdown."""
    if get_database_engine.cache_info().currsize:
        await get_database_engine().dispose()
        get_database_engine.cache_clear()
        get_session_factory.cache_clear()
