import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "三员管理系统"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # 服务配置
    HOST: str = "0.0.0.0"
    PORT: int = 3001

    # 数据库配置
    DATABASE_URL: str = os.getenv(
        "ADMIN_DB_URL",
        "sqlite:///./admin_management.db"
    )

    # JWT配置
    JWT_SECRET: str = os.getenv("ADMIN_JWT_SECRET", "your-secret-key-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24  # 24小时

    # Open WebUI集成配置
    OPENWEBUI_URL: str = os.getenv("OPENWEBUI_URL", "http://localhost:3000")
    OPENWEBUI_API_KEY: Optional[str] = os.getenv("OPENWEBUI_API_KEY")
    # OpenWebUI数据库配置（用于读取审计日志）
    OPENWEBUI_DB_URL: str = os.getenv(
        "OPENWEBUI_DB_URL",
        "sqlite:///../../../data/webui.db"  # 默认相对路径
    )

    # 安全配置
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_EXPIRY_DAYS: int = 90
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION: int = 1800  # 30分钟

    # 内置管理员账户配置
    BUILTIN_ADMINS: Dict[str, Dict[str, Any]] = {
        "sys_admin": {
            "username": "sys_admin",
            "email": "sys_admin@admin.com",
            "display_name": "系统管理员",
            "role": "sys_admin",
            "initial_password": "SysAdmin123!"
        },
        "auth_admin": {
            "username": "auth_admin",
            "email": "auth_admin@admin.com",
            "display_name": "安全管理员",
            "role": "auth_admin",
            "initial_password": "AuthAdmin123!"
        },
        "audit_admin": {
            "username": "audit_admin",
            "email": "audit_admin@admin.com",
            "display_name": "审计管理员",
            "role": "audit_admin",
            "initial_password": "AuditAdmin123!"
        }
    }

    class Config:
        env_file = ".env"
        extra = "allow"  # 允许额外的环境变量


settings = Settings()