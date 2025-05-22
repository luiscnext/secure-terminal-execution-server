"""
Configuration management using Pydantic settings.

Handles environment variables, validation, and provides
type-safe configuration access throughout the application.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings have sensible defaults for development and
    can be overridden via environment variables.
    """
    
    # Server Configuration
    server_host: str = Field(default="0.0.0.0", description="Server bind address")
    server_port: int = Field(default=8000, description="Server port")
    server_debug: bool = Field(default=False, description="Enable debug mode")
    server_reload: bool = Field(default=False, description="Enable auto-reload")
    
    # Security Configuration
    allowed_hosts: List[str] = Field(
        default=["localhost", "127.0.0.1"],
        description="Allowed host headers"
    )
    cors_origins: List[str] = Field(
        default=["http://localhost:3000"],
        description="CORS allowed origins"
    )
    
    # Database Configuration
    database_url: str = Field(
        default="postgresql://user:password@localhost:5432/terminal_server",
        description="Database connection URL"
    )
    database_pool_size: int = Field(default=20, description="Database pool size")
    database_max_overflow: int = Field(default=10, description="Database max overflow")
    
    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    redis_max_connections: int = Field(
        default=100,
        description="Redis connection pool size"
    )
    
    # JWT Configuration
    jwt_secret_key: str = Field(
        default="dev-secret-key-change-in-production",
        description="JWT signing secret"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration time in minutes"
    )
    jwt_refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration time in days"
    )
    
    # OAuth2 Configuration
    oauth2_issuer_url: Optional[str] = Field(
        default=None,
        description="OAuth2 issuer URL"
    )
    oauth2_client_id: Optional[str] = Field(
        default=None,
        description="OAuth2 client ID"
    )
    oauth2_client_secret: Optional[str] = Field(
        default=None,
        description="OAuth2 client secret"
    )
    
    # Execution Configuration
    max_concurrent_jobs: int = Field(
        default=100,
        description="Maximum concurrent job executions"
    )
    default_command_timeout: int = Field(
        default=300,
        description="Default command timeout in seconds"
    )
    max_output_size: int = Field(
        default=1024 * 1024,  # 1MB
        description="Maximum command output size in bytes"
    )
    execution_sandbox_image: str = Field(
        default="ubuntu:22.04",
        description="Docker image for sandbox execution"
    )
    
    # Docker Configuration
    docker_socket_path: str = Field(
        default="/var/run/docker.sock",
        description="Docker socket path"
    )
    sandbox_memory_limit: str = Field(
        default="512m",
        description="Sandbox memory limit"
    )
    sandbox_cpu_limit: float = Field(
        default=0.5,
        description="Sandbox CPU limit"
    )
    sandbox_network_mode: str = Field(
        default="none",
        description="Sandbox network mode"
    )
    
    # Monitoring Configuration
    prometheus_enabled: bool = Field(
        default=True,
        description="Enable Prometheus metrics"
    )
    opentelemetry_enabled: bool = Field(
        default=True,
        description="Enable OpenTelemetry tracing"
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )
    log_format: str = Field(
        default="json",
        description="Log format (json or text)"
    )
    
    @validator("jwt_secret_key")
    def validate_jwt_secret(cls, v):
        if v == "dev-secret-key-change-in-production":
            import os
            if os.getenv("ENVIRONMENT") == "production":
                raise ValueError("JWT secret key must be changed in production")
        return v
    
    @validator("log_level")
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()
    
    @validator("cors_origins")
    def validate_cors_origins(cls, v):
        # In production, CORS origins should be more restrictive
        import os
        if os.getenv("ENVIRONMENT") == "production" and "*" in v:
            raise ValueError("Wildcard CORS origins not allowed in production")
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Returns:
        Settings instance loaded from environment
    """
    return Settings()
