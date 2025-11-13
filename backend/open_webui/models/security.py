from sqlalchemy import Column, Integer, String, BigInteger, Boolean, Text  
from open_webui.internal.db import Base  
import time  
  
class UserIPWhitelist(Base):  
    """用户IP白名单表"""  
    __tablename__ = "user_ip_whitelist"  
      
    id = Column(String, primary_key=True)  
    user_id = Column(String, nullable=False, index=True)  
    ip_address = Column(String, nullable=False)  
    created_at = Column(BigInteger, default=lambda: int(time.time()))  
    created_by = Column(String)  # 管理员ID  
    is_active = Column(Boolean, default=True)  
  
  
class LoginAttempt(Base):  
    """登录尝试记录表"""  
    __tablename__ = "login_attempts"  
      
    id = Column(String, primary_key=True)  
    user_email = Column(String, nullable=False, index=True)  
    ip_address = Column(String)  
    success = Column(Boolean, nullable=False)  
    failure_reason = Column(String)  # 'invalid_credentials', 'ip_blocked', 'account_locked'  
    timestamp = Column(BigInteger, nullable=False, index=True)  
    user_agent = Column(Text)  
  
  
class UserLockStatus(Base):  
    """用户锁定状态表"""  
    __tablename__ = "user_lock_status"  
      
    user_email = Column(String, primary_key=True)  
    is_locked = Column(Boolean, default=False)  
    lock_reason = Column(String)  # 'too_many_failures', 'inactive_too_long'  
    locked_at = Column(BigInteger)  
    locked_until = Column(BigInteger)  # 自动解锁时间，None表示需要管理员解锁  
    failed_attempts = Column(Integer, default=0)  
    last_failed_at = Column(BigInteger)  
    last_success_at = Column(BigInteger)  
  
  
class PasswordPolicy(Base):  
    """密码策略表"""  
    __tablename__ = "password_policy"  
      
    id = Column(String, primary_key=True)  
    user_email = Column(String, nullable=False, index=True)  
    # 密码设置时间  
    password_set_at = Column(BigInteger, default=lambda: int(time.time()))  
    # 密码过期时间（秒），例如 7776000 表示 90 天  
    password_expiry_interval = Column(BigInteger, default=7776000)  
    # 是否强制用户定期更换密码  
    force_password_change = Column(Boolean, default=True)  
    # 上次提醒更改密码的时间  
    last_reminder_at = Column(BigInteger, nullable=True)  
  
  
class SecurityConfig(Base):  
    """安全配置表"""  
    __tablename__ = "security_config"  
      
    id = Column(String, primary_key=True)  
    # 配置键名  
    key = Column(String, unique=True, nullable=False)  
    # 配置值  
    value = Column(String, nullable=False)  
    # 配置描述  
    description = Column(Text)  
    # 是否启用  
    is_active = Column(Boolean, default=True)  
    # 创建时间  
    created_at = Column(BigInteger, default=lambda: int(time.time()))  
    # 更新时间  
    updated_at = Column(BigInteger, default=lambda: int(time.time()))