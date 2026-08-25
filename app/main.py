"""FastAPI Application Entrypoint for ORBITAL SHIELD Downlink Security Engine."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.logging_config import setup_logging, get_logger
from app.db.database import init_db
from app.api.routes_health import router as health_router
from app.api.routes_downlink import router as downlink_router
from app.services.anomaly_detector import AnomalyDetector

# Initialize logging on load
setup_logging()
logger = get_logger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info("=" * 60)
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    logger.info("=" * 60)

    # Initialize SQLite tables
    init_db()

    # Inspect ML model presence
    detector = AnomalyDetector(auto_load=False)
    if settings.MODEL_PATH.exists():
        detector.load_model()
        logger.info(f"Isolation Forest model loaded from '{settings.MODEL_PATH}'")
    else:
        logger.warning(
            f"WARNING: Isolation Forest model artifact missing at '{settings.MODEL_PATH}'. "
            "Please run 'python scripts/train_model.py' to generate baseline and train model."
        )

    yield

    logger.info("Shutting down Downlink Security Engine...")


app = FastAPI(
    title="ORBITAL SHIELD — Downlink Security Engine (Person 2)",
    description=(
        "Production-grade cybersecurity microservice responsible for real-time "
        "satellite telemetry integrity verification and Isolation Forest behavioral anomaly detection. "
        "Emits standardized SecurityEvents for downstream correlation and audit engines."
    ),
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for cross-module integration / local dashboard consumption
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router)
app.include_router(downlink_router)


# Global Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle schema validation errors with clean structured JSON response."""
    errors = []
    for error in exc.errors():
        field = " -> ".join([str(loc) for loc in error.get("loc", [])])
        msg = error.get("msg", "Invalid value")
        errors.append({"field": field, "message": msg})

    logger.warning(f"Validation failure on {request.url.path}: {errors}")
    return JSONResponse(
        status_code=422,
        content={
            "status": "VALIDATION_ERROR",
            "message": "Telemetry input does not conform to required contract schema.",
            "errors": errors
        }
    )


@app.get("/", include_in_schema=False)
def root():
    """Root redirect / information endpoint."""
    return {
        "module": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
        "status": f"{settings.API_V1_PREFIX}/status"
    }
