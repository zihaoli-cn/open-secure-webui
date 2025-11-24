from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import logging

from config import settings
from utils.database import init_database, get_db
from models.admin_users import AdminUser
from routers import auth, sys_admin, auth_admin, audit_admin

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建FastAPI应用
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Open WebUI 三员管理系统",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该限制具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """
    应用启动时执行
    """
    try:
        # 初始化数据库
        init_database()

        # 创建内置管理员账户
        with next(get_db()) as db:
            AdminUser.create_builtin_admins(db)

        logger.info("三员管理系统启动完成")

    except Exception as e:
        logger.error(f"应用启动失败: {e}")
        raise


@app.on_event("shutdown")
def shutdown_event():
    """
    应用关闭时执行
    """
    logger.info("三员管理系统正在关闭...")


@app.get("/")
async def root():
    """
    根路径
    """
    return {
        "message": "欢迎使用三员管理系统",
        "version": settings.APP_VERSION,
        "docs": "/docs"
    }


@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    健康检查
    """
    try:
        # 检查数据库连接
        db.execute("SELECT 1")

        return {
            "status": "healthy",
            "database": "connected",
            "version": settings.APP_VERSION
        }
    except Exception as e:
        logger.error(f"健康检查失败: {e}")
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }


# 注册路由
app.include_router(auth.router)
app.include_router(sys_admin.router)
app.include_router(auth_admin.router)
app.include_router(audit_admin.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )