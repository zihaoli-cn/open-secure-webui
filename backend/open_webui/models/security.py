from sqlalchemy import Column, Integer, String, BigInteger, Boolean, Text  
from open_webui.internal.db import Base, get_db
import time  
import uuid
import logging
from typing import Optional, List

log = logging.getLogger(__name__)

####################
# DB MODELS
####################

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


####################
# TABLE CLASSES
####################

class SecurityConfigTable:
    """安全配置表操作类"""
    
    def get_config_by_key(self, key: str) -> Optional[SecurityConfig]:
        """根据键获取配置"""
        try:
            with get_db() as db:
                config = db.query(SecurityConfig).filter_by(key=key, is_active=True).first()
                return config
        except Exception as e:
            log.error(f"获取安全配置失败: {e}")
            return None
    
    def get_all_configs(self) -> List[SecurityConfig]:
        """获取所有配置"""
        try:
            with get_db() as db:
                configs = db.query(SecurityConfig).filter_by(is_active=True).all()
                return configs
        except Exception as e:
            log.error(f"获取所有安全配置失败: {e}")
            return []
    
    def create_config(self, key: str, value: str, description: str = None) -> Optional[SecurityConfig]:
        """创建配置"""
        try:
            with get_db() as db:
                config = SecurityConfig(
                    id=str(uuid.uuid4()),
                    key=key,
                    value=value,
                    description=description,
                    is_active=True,
                    created_at=int(time.time()),
                    updated_at=int(time.time())
                )
                db.add(config)
                db.commit()
                db.refresh(config)
                return config
        except Exception as e:
            log.error(f"创建安全配置失败: {e}")
            return None
    
    def update_config(self, key: str, value: str, description: str = None) -> bool:
        """更新配置"""
        try:
            with get_db() as db:
                config = db.query(SecurityConfig).filter_by(key=key).first()
                if config:
                    config.value = value
                    if description:
                        config.description = description
                    config.updated_at = int(time.time())
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"更新安全配置失败: {e}")
            return False
    
    def delete_config(self, key: str) -> bool:
        """删除配置（软删除）"""
        try:
            with get_db() as db:
                config = db.query(SecurityConfig).filter_by(key=key).first()
                if config:
                    config.is_active = False
                    config.updated_at = int(time.time())
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"删除安全配置失败: {e}")
            return False


class UserIPWhitelistTable:
    """IP白名单表操作类"""
    
    def get_by_id(self, whitelist_id: str) -> Optional[UserIPWhitelist]:
        """根据ID获取白名单记录"""
        try:
            with get_db() as db:
                record = db.query(UserIPWhitelist).filter_by(id=whitelist_id, is_active=True).first()
                return record
        except Exception as e:
            log.error(f"获取IP白名单记录失败: {e}")
            return None
    
    def get_by_user_id(self, user_id: str) -> List[UserIPWhitelist]:
        """根据用户ID获取白名单列表"""
        try:
            with get_db() as db:
                records = db.query(UserIPWhitelist).filter_by(user_id=user_id, is_active=True).all()
                return records
        except Exception as e:
            log.error(f"获取用户IP白名单失败: {e}")
            return []
    
    def get_all(self) -> List[UserIPWhitelist]:
        """获取所有白名单记录"""
        try:
            with get_db() as db:
                records = db.query(UserIPWhitelist).filter_by(is_active=True).all()
                return records
        except Exception as e:
            log.error(f"获取所有IP白名单失败: {e}")
            return []
    
    def create(self, user_id: str, ip_address: str, created_by: str = None) -> Optional[UserIPWhitelist]:
        """创建白名单记录"""
        try:
            with get_db() as db:
                record = UserIPWhitelist(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    ip_address=ip_address,
                    created_by=created_by,
                    created_at=int(time.time()),
                    is_active=True
                )
                db.add(record)
                db.commit()
                db.refresh(record)
                return record
        except Exception as e:
            log.error(f"创建IP白名单失败: {e}")
            return None
    
    def update(self, whitelist_id: str, ip_address: str = None) -> bool:
        """更新白名单记录"""
        try:
            with get_db() as db:
                record = db.query(UserIPWhitelist).filter_by(id=whitelist_id).first()
                if record:
                    if ip_address:
                        record.ip_address = ip_address
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"更新IP白名单失败: {e}")
            return False
    
    def delete(self, whitelist_id: str) -> bool:
        """删除白名单记录（软删除）"""
        try:
            with get_db() as db:
                record = db.query(UserIPWhitelist).filter_by(id=whitelist_id).first()
                if record:
                    record.is_active = False
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"删除IP白名单失败: {e}")
            return False
    
    def check_ip_in_whitelist(self, user_id: str, ip_address: str) -> bool:
        """检查IP是否在白名单中"""
        try:
            with get_db() as db:
                record = db.query(UserIPWhitelist).filter_by(
                    user_id=user_id,
                    ip_address=ip_address,
                    is_active=True
                ).first()
                return record is not None
        except Exception as e:
            log.error(f"检查IP白名单失败: {e}")
            return False


class LoginAttemptTable:
    """登录尝试记录表操作类"""
    
    def create(self, user_email: str, ip_address: str, success: bool, 
               failure_reason: str = None, user_agent: str = None) -> Optional[LoginAttempt]:
        """创建登录尝试记录"""
        try:
            with get_db() as db:
                attempt = LoginAttempt(
                    id=str(uuid.uuid4()),
                    user_email=user_email,
                    ip_address=ip_address,
                    success=success,
                    failure_reason=failure_reason,
                    timestamp=int(time.time()),
                    user_agent=user_agent
                )
                db.add(attempt)
                db.commit()
                db.refresh(attempt)
                return attempt
        except Exception as e:
            log.error(f"创建登录尝试记录失败: {e}")
            return None
    
    def get_recent_attempts(self, user_email: str, minutes: int = 30) -> List[LoginAttempt]:
        """获取最近的登录尝试记录"""
        try:
            with get_db() as db:
                cutoff_time = int(time.time()) - (minutes * 60)
                attempts = db.query(LoginAttempt).filter(
                    LoginAttempt.user_email == user_email,
                    LoginAttempt.timestamp >= cutoff_time
                ).order_by(LoginAttempt.timestamp.desc()).all()
                return attempts
        except Exception as e:
            log.error(f"获取登录尝试记录失败: {e}")
            return []
    
    def get_failed_attempts_count(self, user_email: str, minutes: int = 30) -> int:
        """获取失败的登录尝试次数"""
        try:
            with get_db() as db:
                cutoff_time = int(time.time()) - (minutes * 60)
                count = db.query(LoginAttempt).filter(
                    LoginAttempt.user_email == user_email,
                    LoginAttempt.success == False,
                    LoginAttempt.timestamp >= cutoff_time
                ).count()
                return count
        except Exception as e:
            log.error(f"获取失败登录次数失败: {e}")
            return 0


class UserLockStatusTable:
    """用户锁定状态表操作类"""
    
    def get_by_email(self, user_email: str) -> Optional[UserLockStatus]:
        """根据邮箱获取锁定状态"""
        try:
            with get_db() as db:
                status = db.query(UserLockStatus).filter_by(user_email=user_email).first()
                return status
        except Exception as e:
            log.error(f"获取用户锁定状态失败: {e}")
            return None
    
    def is_locked(self, user_email: str) -> bool:
        """检查用户是否被锁定"""
        try:
            status = self.get_by_email(user_email)
            if not status or not status.is_locked:
                return False
            
            # 检查是否到了自动解锁时间
            if status.locked_until and status.locked_until < int(time.time()):
                self.unlock(user_email)
                return False
            
            return True
        except Exception as e:
            log.error(f"检查用户锁定状态失败: {e}")
            return False
    
    def lock(self, user_email: str, reason: str, duration_seconds: int = None) -> bool:
        """锁定用户"""
        try:
            with get_db() as db:
                status = db.query(UserLockStatus).filter_by(user_email=user_email).first()
                
                locked_until = None
                if duration_seconds:
                    locked_until = int(time.time()) + duration_seconds
                
                if status:
                    status.is_locked = True
                    status.lock_reason = reason
                    status.locked_at = int(time.time())
                    status.locked_until = locked_until
                else:
                    status = UserLockStatus(
                        user_email=user_email,
                        is_locked=True,
                        lock_reason=reason,
                        locked_at=int(time.time()),
                        locked_until=locked_until,
                        failed_attempts=0
                    )
                    db.add(status)
                
                db.commit()
                return True
        except Exception as e:
            log.error(f"锁定用户失败: {e}")
            return False
    
    def unlock(self, user_email: str) -> bool:
        """解锁用户"""
        try:
            with get_db() as db:
                status = db.query(UserLockStatus).filter_by(user_email=user_email).first()
                if status:
                    status.is_locked = False
                    status.lock_reason = None
                    status.locked_at = None
                    status.locked_until = None
                    status.failed_attempts = 0
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"解锁用户失败: {e}")
            return False
    
    def increment_failed_attempts(self, user_email: str) -> int:
        """增加失败尝试次数"""
        try:
            with get_db() as db:
                status = db.query(UserLockStatus).filter_by(user_email=user_email).first()
                
                if status:
                    status.failed_attempts += 1
                    status.last_failed_at = int(time.time())
                else:
                    status = UserLockStatus(
                        user_email=user_email,
                        is_locked=False,
                        failed_attempts=1,
                        last_failed_at=int(time.time())
                    )
                    db.add(status)
                
                db.commit()
                return status.failed_attempts
        except Exception as e:
            log.error(f"增加失败尝试次数失败: {e}")
            return 0
    
    def reset_failed_attempts(self, user_email: str) -> bool:
        """重置失败尝试次数"""
        try:
            with get_db() as db:
                status = db.query(UserLockStatus).filter_by(user_email=user_email).first()
                if status:
                    status.failed_attempts = 0
                    status.last_success_at = int(time.time())
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"重置失败尝试次数失败: {e}")
            return False


class PasswordPolicyTable:
    """密码策略表操作类"""
    
    def get_by_email(self, user_email: str) -> Optional[PasswordPolicy]:
        """根据邮箱获取密码策略"""
        try:
            with get_db() as db:
                policy = db.query(PasswordPolicy).filter_by(user_email=user_email).first()
                return policy
        except Exception as e:
            log.error(f"获取密码策略失败: {e}")
            return None
    
    def create_or_update(self, user_email: str, password_expiry_interval: int = 7776000,
                        force_password_change: bool = True) -> Optional[PasswordPolicy]:
        """创建或更新密码策略"""
        try:
            with get_db() as db:
                policy = db.query(PasswordPolicy).filter_by(user_email=user_email).first()
                
                if policy:
                    policy.password_set_at = int(time.time())
                    policy.password_expiry_interval = password_expiry_interval
                    policy.force_password_change = force_password_change
                else:
                    policy = PasswordPolicy(
                        id=str(uuid.uuid4()),
                        user_email=user_email,
                        password_set_at=int(time.time()),
                        password_expiry_interval=password_expiry_interval,
                        force_password_change=force_password_change
                    )
                    db.add(policy)
                
                db.commit()
                db.refresh(policy)
                return policy
        except Exception as e:
            log.error(f"创建或更新密码策略失败: {e}")
            return None
    
    def is_password_expired(self, user_email: str) -> bool:
        """检查密码是否过期"""
        try:
            policy = self.get_by_email(user_email)
            if not policy or not policy.force_password_change:
                return False
            
            expiry_time = policy.password_set_at + policy.password_expiry_interval
            return int(time.time()) > expiry_time
        except Exception as e:
            log.error(f"检查密码过期失败: {e}")
            return False
    
    def update_reminder_time(self, user_email: str) -> bool:
        """更新提醒时间"""
        try:
            with get_db() as db:
                policy = db.query(PasswordPolicy).filter_by(user_email=user_email).first()
                if policy:
                    policy.last_reminder_at = int(time.time())
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"更新提醒时间失败: {e}")
            return False


# 创建全局实例
SecurityConfigs = SecurityConfigTable()
UserIPWhitelists = UserIPWhitelistTable()
LoginAttempts = LoginAttemptTable()
UserLockStatuses = UserLockStatusTable()
PasswordPolicies = PasswordPolicyTable()
