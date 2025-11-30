from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.routers import peers, metrics, config
from app.database import db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.init_db()
    yield
    # Shutdown (if needed)


app = FastAPI(
    title="WireGuard Management API",
    description="Simple REST API for managing WireGuard peers",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(peers.router, prefix="/api/peers", tags=["peers"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["metrics"])
app.include_router(config.router, prefix="/api/config", tags=["config"])


@app.get("/")
async def root():
    return {"message": "WireGuard Management API", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "ok"}

