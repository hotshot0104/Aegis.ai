"""
Application Configuration and Settings for Project AEGIS-AI.
Uses Pydantic Settings for type-safe environment variable management.
"""

import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings and operational parameters."""

    # Project Information
    PROJECT_NAME: str = "Project AEGIS-AI"
    API_V1_STR: str = "/api/v1"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Autonomous Agentic SOC & Non-IoC Network Compromise Defense Engine"

    # Security & Authentication
    OFFICER_AUTH_TOKEN: str = "SOC-OFFICER-AUTH-TOKEN-DEMO"

    # ML Perception Thresholds
    ANOMALY_BDI_THRESHOLD: float = 0.80
    ROLLING_WINDOW_SIZE: int = 3
    ROLLING_TIME_WINDOW_SECONDS: float = 5.0

    # CORS Configuration
    CORS_ORIGINS: List[str] = ["*"]

    # File Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATA_DIR: str = os.path.join(BASE_DIR, "data")
    MODELS_DIR: str = os.path.join(BASE_DIR, "models_saved")
    MODEL_PATH: str = os.path.join(MODELS_DIR, "isolation_forest_benign.joblib")

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="allow",
    )


settings = Settings()
