"""API route routers for Downlink Security Engine."""

from app.api.routes_health import router as health_router
from app.api.routes_downlink import router as downlink_router

__all__ = ["health_router", "downlink_router"]
