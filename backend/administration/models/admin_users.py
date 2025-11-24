from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import bcrypt
import logging

from config import settings
from utils.database import get_db

Base = declarative_base()
logger = logging.getLogger(__name__)


class AdminUser:
    """
    三员用户模型 - 基于独立管理员表的实现
    """

    @staticmethod
    def get_by_username(db: Session, username: str):
        """
        根据用户名获取管理员用户
        """
        try:
            result = db.execute(
                text("""
                    SELECT id, username, email, display_name, admin_role,
                           password_hash, is_builtin_admin, is_active,
                           last_login, created_at, updated_at
                    FROM admin_users
                    WHERE username = :username AND is_active = true
                """),
                {"username": username}
            ).fetchone()

            if result:
                return dict(result._mapping) if result else None
            return None

        except Exception as e:
            logger.error(f"获取管理员用户失败: {e}")
            raise

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        验证密码
        """
        try:
            return bcrypt.checkpw(
                plain_password.encode('utf-8'),
                hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password
            )
        except Exception as e:
            logger.error(f"密码验证失败: {e}")
            return False

    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        生成密码哈希
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @staticmethod
    def create_builtin_admins(db: Session):
        """
        创建内置管理员账户
        """
        try:
            for admin_key, admin_info in settings.BUILTIN_ADMINS.items():
                # 检查用户是否已存在
                existing_user = AdminUser.get_by_username(db, admin_info["username"])

                if not existing_user:
                    # 创建新用户 - 直接插入到独立的管理员表
                    hashed_password = AdminUser.get_password_hash(admin_info["initial_password"])

                    db.execute(
                        text("""
                            INSERT INTO admin_users (
                                username, email, display_name, admin_role,
                                password_hash, is_builtin_admin, created_at, updated_at
                            ) VALUES (
                                :username, :email, :display_name, :admin_role,
                                :password_hash, :is_builtin_admin, :created_at, :updated_at
                            )
                        """),
                        {
                            "username": admin_info["username"],
                            "email": admin_info["email"],
                            "display_name": admin_info["display_name"],
                            "admin_role": admin_info["role"],
                            "password_hash": hashed_password,
                            "is_builtin_admin": True,
                            "created_at": datetime.now(),
                            "updated_at": datetime.now()
                        }
                    )

                    logger.info(f"创建内置管理员: {admin_info['display_name']}")

            db.commit()
            logger.info("内置管理员账户初始化完成")

        except Exception as e:
            db.rollback()
            logger.error(f"创建内置管理员失败: {e}")
            raise

    @staticmethod
    def authenticate_user(db: Session, username: str, password: str):
        """
        用户认证
        """
        try:
            user = AdminUser.get_by_username(db, username)
            if not user:
                return None

            # 验证密码 - 直接从查询结果中获取密码哈希
            if not AdminUser.verify_password(password, user["password_hash"]):
                return None

            # 更新最后登录时间
            db.execute(
                text("""
                    UPDATE admin_users
                    SET last_login = :last_login
                    WHERE username = :username
                """),
                {
                    "last_login": datetime.now(),
                    "username": username
                }
            )
            db.commit()

            return user

        except Exception as e:
            logger.error(f"用户认证失败: {e}")
            return None

    @staticmethod
    def check_password_expiry(db: Session, username: str):
        """
        检查密码是否过期
        """
        try:
            result = db.execute(
                text("""
                    SELECT updated_at FROM admin_users
                    WHERE username = :username
                """),
                {"username": username}
            ).fetchone()

            if not result:
                return {"is_expired": True, "days_remaining": 0, "last_change": None}

            last_change = result.updated_at
            if not last_change:
                return {"is_expired": True, "days_remaining": 0, "last_change": None}

            # Handle SQLite string timestamps
            if isinstance(last_change, str):
                last_change = datetime.fromisoformat(last_change.replace('Z', '+00:00'))

            expiry_date = last_change + timedelta(days=settings.PASSWORD_EXPIRY_DAYS)
            days_remaining = (expiry_date - datetime.now()).days

            return {
                "is_expired": days_remaining <= 0,
                "days_remaining": max(0, days_remaining),
                "last_change": last_change
            }

        except Exception as e:
            logger.error(f"检查密码过期失败: {e}")
            return {"is_expired": True, "days_remaining": 0, "last_change": None}

    @staticmethod
    def change_password(db: Session, username: str, current_password: str, new_password: str) -> bool:
        """
        修改密码
        """
        try:
            # 验证当前密码
            user = AdminUser.authenticate_user(db, username, current_password)
            if not user:
                return False

            # 验证新密码复杂度
            if len(new_password) < settings.PASSWORD_MIN_LENGTH:
                return False

            # 更新密码
            hashed_password = AdminUser.get_password_hash(new_password)
            db.execute(
                text("""
                    UPDATE admin_users
                    SET password_hash = :password_hash, updated_at = :updated_at
                    WHERE username = :username
                """),
                {
                    "password_hash": hashed_password,
                    "updated_at": datetime.now(),
                    "username": username
                }
            )

            db.commit()
            logger.info(f"用户 {username} 密码修改成功")
            return True

        except Exception as e:
            db.rollback()
            logger.error(f"修改密码失败: {e}")
            return False

    @staticmethod
    def get_all_admin_users(db: Session):
        """
        获取所有管理员用户
        """
        try:
            result = db.execute(
                text("""
                    SELECT id, username, email, display_name, admin_role,
                           is_builtin_admin, is_active, last_login, created_at, updated_at
                    FROM admin_users
                    ORDER BY created_at DESC
                """)
            ).fetchall()

            return [dict(row._mapping) for row in result]

        except Exception as e:
            logger.error(f"获取管理员用户失败: {e}")
            return []