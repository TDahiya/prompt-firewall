import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from api.routes.firewall import router as firewall_router
from api.routes.analytics import router as analytics_router
from api.firewall import sessions


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
