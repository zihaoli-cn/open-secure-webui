from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from typing import Generator
import logging

from config import settings

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建数据库引擎（三员管理系统自己的数据库）
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=settings.DEBUG
)

# 创建 OpenWebUI 数据库引擎（只读，用于读取审计日志）
openwebui_engine = create_engine(
    settings.OPENWEBUI_DB_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=settings.DEBUG
)

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
OpenWebUISessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=openwebui_engine)

# 创建基类
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    获取数据库会话（三员管理系统自己的数据库）
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_openwebui_db() -> Generator[Session, None, None]:
    """
    获取 OpenWebUI 数据库会话（只读，用于查询审计日志）
    """
    db = OpenWebUISessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database():
    """
    初始化数据库表结构
    """
    try:
        # 检查数据库连接
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("数据库连接成功")

        # 创建扩展表
        create_extension_tables()

    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        raise


def create_extension_tables():
    """
    创建三员管理系统扩展表
    """
    try:
        with engine.connect() as conn:
            # 对于SQLite，我们直接创建独立的管理员表，不依赖OpenWebUI的users表
            # 创建管理配置表
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS admin_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key VARCHAR(100) UNIQUE NOT NULL,
                    config_value TEXT NOT NULL,
                    description TEXT,
                    created_by VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))

            # 创建API Key管理表
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS admin_api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL,
                    api_key VARCHAR(100) UNIQUE NOT NULL,
                    created_by VARCHAR(100) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    permissions TEXT
                );
            """))

            # 创建独立的管理员用户表
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    display_name VARCHAR(100) NOT NULL,
                    admin_role VARCHAR(20) NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_builtin_admin BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    last_login TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))

            # 创建审计日志表（与 OpenWebUI 的 audit_logs 表结构一致）
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id VARCHAR(255) PRIMARY KEY,
                    timestamp BIGINT NOT NULL,
                    user_id VARCHAR(255),
                    user_name VARCHAR(255),
                    user_email VARCHAR(255),
                    user_role VARCHAR(100),
                    verb VARCHAR(100) NOT NULL,
                    request_uri TEXT NOT NULL,
                    response_status_code INTEGER,
                    source_ip VARCHAR(45),
                    user_agent TEXT,
                    request_object TEXT,
                    response_object TEXT,
                    created_at BIGINT,
                    processing_time INTEGER
                );
            """))
            
            # 创建索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
            """))

            logger.info("数据库扩展表创建成功")

    except Exception as e:
        logger.error(f"创建扩展表失败: {e}")
        raise


def execute_sql(sql: str, params: dict = None) -> list:
    """
    执行SQL查询
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(text(sql), params or {})
            return [dict(row._mapping) for row in result]
    except Exception as e:
        logger.error(f"SQL执行失败: {e}")
        raise