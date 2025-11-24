from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import logging

from config import settings
from utils.database import get_db
from models.admin_users import AdminUser

logger = logging.getLogger(__name__)
security = HTTPBearer()


class AuthManager:
    """
    认证管理器
    """

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        """
        创建JWT Token
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """
        验证JWT Token
        """
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            return payload
        except JWTError as e:
            logger.error(f"Token验证失败: {e}")
            return None

    @staticmethod
    def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
    ):
        """
        获取当前用户
        """
        token = credentials.credentials
        payload = AuthManager.verify_token(token)

        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证令牌",
                headers={"WWW-Authenticate": "Bearer"},
            )

        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证令牌",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = AdminUser.get_by_username(db, username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户不存在",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    @staticmethod
    def get_current_sys_admin(
        current_user: dict = Depends(get_current_user)
    ):
        """
        获取当前系统管理员
        """
        if current_user.get("admin_role") != "sys_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="需要系统管理员权限"
            )
        return current_user

    @staticmethod
    def get_current_auth_admin(
        current_user: dict = Depends(get_current_user)
    ):
        """
        获取当前安全管理员
        """
        if current_user.get("admin_role") != "auth_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="需要安全管理员权限"
            )
        return current_user

    @staticmethod
    def get_current_audit_admin(
        current_user: dict = Depends(get_current_user)
    ):
        """
        获取当前审计管理员
        """
        if current_user.get("admin_role") != "audit_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="需要审计管理员权限"
            )
        return current_user


class LoginManager:
    """
    登录管理器
    """

    @staticmethod
    def login_user(db: Session, username: str, password: str):
        """
        用户登录
        """
        try:
            # 验证用户凭据
            user = AdminUser.authenticate_user(db, username, password)
            if not user:
                return None

            # 检查用户是否为管理员
            if not user.get("admin_role"):
                return None

            # 检查密码是否过期
            password_expiry = AdminUser.check_password_expiry(db, username)
            if password_expiry["is_expired"]:
                return {
                    "success": False,
                    "error": "password_expired",
                    "message": "密码已过期，请修改密码"
                }

            # 创建访问令牌
            access_token = AuthManager.create_access_token(
                data={"sub": user["username"]}
            )

            return {
                "success": True,
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "username": user["username"],
                    "role": user["admin_role"],
                    "display_name": user["display_name"],
                    "email": user["email"]
                },
                "password_expiry": password_expiry
            }

        except Exception as e:
            logger.error(f"用户登录失败: {e}")
            return None

    @staticmethod
    def logout_user(token: str):
        """
        用户登出
        """
        # 在实际应用中，可以将token加入黑名单
        # 这里简单返回成功
        return {"success": True, "message": "登出成功"}


class PermissionManager:
    """
    权限管理器
    """

    @staticmethod
    def has_permission(user: dict, required_role: str) -> bool:
        """
        检查用户权限
        """
        user_role = user.get("admin_role")
        return user_role == required_role

    @staticmethod
    def can_view_audit_logs(user: dict) -> bool:
        """
        检查是否可以查看审计日志
        """
        user_role = user.get("admin_role")
        return user_role in ["audit_admin", "sys_admin"]

    @staticmethod
    def can_manage_security(user: dict) -> bool:
        """
        检查是否可以管理安全配置
        """
        user_role = user.get("admin_role")
        return user_role in ["auth_admin", "sys_admin"]

    @staticmethod
    def can_manage_api_keys(user: dict) -> bool:
        """
        检查是否可以管理API Key
        """
        user_role = user.get("admin_role")
        return user_role == "sys_admin"