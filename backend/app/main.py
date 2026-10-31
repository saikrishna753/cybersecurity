"""FastAPI application entrypoint — AI-IDS."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.core.config import get_settings
from app.core.rate_limit import RateLimitMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("aiids")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.db.init_db import init_db
    from app.ml.predict import registry

    init_db()
    # Load active models from DB registry (falls back to newest artifacts).
    try:
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        from app.db.session import SessionLocal
        from app.models import MlModel

        registered_any = False
        with SessionLocal() as db:
            for task in ("binary", "multiclass", "anomaly"):
                row = db.scalar(
                    select(MlModel)
                    .where(MlModel.task == task, MlModel.is_active.is_(True))
                    .order_by(MlModel.created_at.desc())
                    .limit(1)
                )
                if row is None:
                    row = db.scalar(
                        select(MlModel)
                        .where(MlModel.task == task)
                        .order_by(MlModel.created_at.desc())
                        .limit(1)
                    )
                if row is not None:
                    registry.register(
                        algorithm=row.algorithm, task=row.task, version=row.version,
                        artifact_path=row.artifact_path,
                        feature_columns=row.feature_columns or [],
                    )
                    registered_any = True
        if not registered_any:
            registry.load()
    except Exception:
        logger.exception("model registry load failed")
        registry.load()

    # Ensure at least the newest artifacts are active in DB for visibility.
    try:
        from app.ml.registry_bootstrap import ensure_models_registered

        ensure_models_registered()
    except Exception:
        logger.debug("registry bootstrap skipped", exc_info=True)

    # Wire capture service to authorized interfaces persisted in DB.
    try:
        from sqlalchemy import select

        from app.db.session import SessionLocal
        from app.models import NetworkInterface
        from app.network.capture import capture_service

        with SessionLocal() as db:
            for iface in db.scalars(
                select(NetworkInterface).where(NetworkInterface.is_authorized.is_(True))
            ).all():
                capture_service.authorize(iface.name)
    except Exception:
        logger.debug("interface authorization restore failed", exc_info=True)

    from app.ws.manager import ws_manager

    ws_manager.bind_loop()
    logger.info("AI-IDS %s ready (env=%s)", __version__, get_settings().app_env)
    yield
    # graceful shutdown: stop capture thread
    try:
        from app.network.capture import capture_service

        if capture_service.running:
            capture_service.stop()
    except Exception:
        pass


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI-IDS — AI-Powered Network Intrusion Detection Platform",
        version=__version__,
        description=(
            "Monitor authorized network traffic, extract flow features, classify "
            "attacks with ML, generate alerts, explain decisions and export reports."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RateLimitMiddleware)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    # ------------------------------------------------------------------ routes
    from app.api import (
        alerts,
        auth,
        dashboard,
        datasets,
        explain,
        incidents,
        models,
        monitoring,
        predict,
    )
    from app.api.ws import router as ws_router

    app.include_router(auth.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api")
    app.include_router(alerts.router, prefix="/api")
    app.include_router(incidents.router, prefix="/api")
    app.include_router(monitoring.router, prefix="/api")
    app.include_router(datasets.router, prefix="/api")
    app.include_router(models.router, prefix="/api")
    app.include_router(predict.router, prefix="/api")
    app.include_router(explain.router, prefix="/api")
    app.include_router(ws_router, prefix="/api")

    return app


app = create_app()
