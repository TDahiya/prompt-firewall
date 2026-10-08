import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv

load_dotenv()

from api.routes.firewall import router as firewall_router
from api.routes.analytics import router as analytics_router
from api.firewall import sessions


_RATE_PATHS = {"/check", "/chat", "/proxy"}
_RPM = 30


class _RateLimit(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _RATE_PATHS or request.url.path.startswith("/proxy/"):
            ip = request.client.host if request.client else "0"
            now = time.time()
            bucket = [t for t in self._hits[ip] if now - t < 60]
            if len(bucket) >= _RPM:
                return JSONResponse({"error": "Rate limit exceeded. Try again in a minute."}, status_code=429)
            bucket.append(now)
            self._hits[ip] = bucket
            if len(self._hits) > 10_000:
                self._hits.clear()
        return await call_next(request)


async def _prune_sessions():
    while True:
        await asyncio.sleep(300)
        sessions.prune()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_prune_sessions())
    yield
    task.cancel()


app = FastAPI(title="Prompt Firewall", version="0.2.0", lifespan=lifespan)

app.add_middleware(_RateLimit)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(firewall_router)
app.include_router(analytics_router)

_frontend = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/")
async def root():
    return FileResponse(_frontend / "index.html")


app.mount("/static", StaticFiles(directory=_frontend), name="static")
