#!/usr/bin/env python3
"""
Secure Terminal Execution Server

Main application entry point with FastAPI server setup,
security middleware, and monitoring integration.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from src.core.config import get_settings
from src.core.database import create_tables, get_database
from src.core.exceptions import (
    CommandExecutionError,
    SecurityViolationError,
    ValidationError,
)
from src.core.logging import setup_logging
from src.core.redis import get_redis_client
from src.routers import auth, audit, commands, execution, health

# Configure structured logging
setup_logging()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown operations including:
    - Database connection initialization
    - Redis connection setup
    - Background task startup
    - Graceful shutdown
    """
    settings = get_settings()
    
    # Startup
    logger.info("Starting Secure Terminal Execution Server")
    
    try:
        # Initialize database
        await create_tables()
        logger.info("Database tables created/verified")
        
        # Test Redis connection
        redis_client = await get_redis_client()
        await redis_client.ping()
        logger.info("Redis connection established")
        
        # Start background monitoring
        logger.info("Server startup completed successfully")
        
        yield
        
    except Exception as e:
        logger.error("Failed to start server", error=str(e))
        raise
    
    finally:
        # Shutdown
        logger.info("Shutting down server")
        
        # Close Redis connections
        redis_client = await get_redis_client()
        await redis_client.close()
        
        # Close database connections
        # Database connections are handled by SQLAlchemy pool
        
        logger.info("Server shutdown completed")


def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance
    """
    settings = get_settings()
    
    app = FastAPI(
        title="Secure Terminal Execution Server",
        description="Production-ready terminal command execution with security and audit",
        version="1.0.0",
        docs_url="/docs" if settings.server_debug else None,
        redoc_url="/redoc" if settings.server_debug else None,
        lifespan=lifespan,
        openapi_tags=[
            {
                "name": "authentication",
                "description": "OAuth2 authentication and token management",
            },
            {
                "name": "commands",
                "description": "Command template management and discovery",
            },
            {
                "name": "execution",
                "description": "Command execution and job management",
            },
            {
                "name": "audit",
                "description": "Audit logging and compliance reporting",
            },
            {
                "name": "monitoring",
                "description": "Health checks and system metrics",
            },
        ],
    )
    
    # Security middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )
    
    # Request correlation middleware
    @app.middleware("http")
    async def add_correlation_id(request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", "")
        if not correlation_id:
            import uuid
            correlation_id = str(uuid.uuid4())
        
        # Add to structured logging context
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
        
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
    
    # Exception handlers
    @app.exception_handler(ValidationError)
    async def validation_exception_handler(request: Request, exc: ValidationError):
        logger.warning("Validation error", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=400,
            content={
                "error": "validation_error",
                "message": str(exc),
                "correlation_id": request.headers.get("X-Correlation-ID"),
            },
        )
    
    @app.exception_handler(SecurityViolationError)
    async def security_violation_handler(request: Request, exc: SecurityViolationError):
        logger.error("Security violation", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=403,
            content={
                "error": "security_violation",
                "message": "Access denied",
                "correlation_id": request.headers.get("X-Correlation-ID"),
            },
        )
    
    @app.exception_handler(CommandExecutionError)
    async def command_execution_handler(request: Request, exc: CommandExecutionError):
        logger.error("Command execution error", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "execution_error",
                "message": "Command execution failed",
                "correlation_id": request.headers.get("X-Correlation-ID"),
            },
        )
    
    # Include routers
    app.include_router(health.router, prefix="/health", tags=["monitoring"])
    app.include_router(auth.router, prefix="/auth", tags=["authentication"])
    app.include_router(commands.router, prefix="/commands", tags=["commands"])
    app.include_router(execution.router, prefix="/execute", tags=["execution"])
    app.include_router(audit.router, prefix="/audit", tags=["audit"])
    
    # Mount Prometheus metrics
    if settings.prometheus_enabled:
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)
    
    return app


def main():
    """
    Main entry point for the application.
    """
    settings = get_settings()
    
    logger.info(
        "Starting server",
        host=settings.server_host,
        port=settings.server_port,
        debug=settings.server_debug,
    )
    
    uvicorn.run(
        "src.main:create_application",
        factory=True,
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.server_reload,
        log_config=None,  # We handle logging ourselves
        access_log=False,  # We log requests via middleware
    )


if __name__ == "__main__":
    main()
