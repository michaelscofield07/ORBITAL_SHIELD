"""
Audit Service — FastAPI Entrypoint

Thin file: just creates the app, initializes the DB, and registers routes.
"""
from verify import router as verify_router
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from storage import init_db
from event_reciever import router as event_router
from review import router as review_router
from report_generatior import router as report_router

app = FastAPI(title="Orbital Shield — Audit Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

app.include_router(event_router)
app.include_router(verify_router)
app.include_router(review_router)
app.include_router(report_router)

@app.get("/")
def root():
    return {"status": "Audit service running"}


@app.get("/health")
def health():
    return {"status": "healthy", "service": "audit-service"}


if __name__ == "__main__":
    import os
    import uvicorn
    from pathlib import Path
    try:
        from dotenv import load_dotenv
        _env = Path(__file__).resolve().parent.parent / ".env"
        if _env.exists():
            load_dotenv(dotenv_path=_env, override=False)
    except ImportError:
        pass
    port = int(os.getenv("AUDIT_PORT", "8006"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
