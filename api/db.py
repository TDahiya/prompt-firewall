"""
Thin async Postgres layer. Falls back to a no-op if DATABASE_URL is unset
so the service works without a DB during development.
"""
import os
from typing import Any
from api.firewall.models import CheckResponse

_pool = None


async def _get_pool():
    global _pool
    if _pool is None:
        url = os.environ.get("DATABASE_URL")
        if not url:
            return None
        import asyncpg
        _pool = await asyncpg.create_pool(url, min_size=1, max_size=10)
    return _pool


async def log_check(text: str, result: CheckResponse) -> None:
    pool = await _get_pool()
    if pool is None:
        return
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO checks (text, verdict, category, confidence, matched_pattern, layer, latency_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            text,
            result.verdict.value,
            result.category.value,
            result.confidence,
            result.matched_pattern,
            result.layer,
            result.latency_ms,
        )


async def get_stats() -> dict[str, Any]:
    pool = await _get_pool()
    if pool is None:
        return {"error": "database not configured"}
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM checks")
        blocked = await conn.fetchval("SELECT COUNT(*) FROM checks WHERE verdict = 'BLOCK'")
        by_category = await conn.fetch(
            "SELECT category, COUNT(*) as count FROM checks WHERE verdict = 'BLOCK' GROUP BY category ORDER BY count DESC"
        )
        hourly = await conn.fetch(
            """
            SELECT date_trunc('hour', created_at) as hour, COUNT(*) as total,
                   SUM(CASE WHEN verdict = 'BLOCK' THEN 1 ELSE 0 END) as blocked
            FROM checks
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY hour ORDER BY hour
            """
        )
    return {
        "total": total,
        "blocked": blocked,
        "passed": total - blocked,
        "block_rate": round(blocked / total, 4) if total else 0,
        "by_category": [dict(r) for r in by_category],
        "hourly_24h": [dict(r) for r in hourly],
    }


async def get_log(limit: int = 100, offset: int = 0) -> list[dict]:
    pool = await _get_pool()
    if pool is None:
        return []
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM checks ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            limit, offset,
        )
    return [dict(r) for r in rows]
