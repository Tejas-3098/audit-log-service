from fastapi import FastAPI

from app.db import init_db

app = FastAPI(
    title="Audit Log Service",
    description="Tamper-evident, append-only audit log service.",
    version="0.1.0",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
