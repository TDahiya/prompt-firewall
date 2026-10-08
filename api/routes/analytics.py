from fastapi import APIRouter
from api.db import get_stats, get_log

router = APIRouter()


@router.get("/stats")
async def stats():
    return await get_stats()


@router.get("/log")
async def log(limit: int = 100, offset: int = 0):
    return await get_log(limit=limit, offset=offset)
