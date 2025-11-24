from open_webui.internal.db import Base, get_db
from sqlalchemy import Column, Integer, String, Text, BigInteger
import time  
import uuid
import logging
from typing import Optional, List, Dict, Any

log = logging.getLogger(__name__)

####################
# DB MODELS
####################

class AuditLog(Base):  
    __tablename__ = "audit_logs"  
      
    id = Column(String, primary_key=True)  
    timestamp = Column(BigInteger, nullable=False, index=True)  
    user_id = Column(String, index=True)  
    user_name = Column(String)  
    user_email = Column(String)  
    user_role = Column(String)  
    verb = Column(String, nullable=False)  
    request_uri = Column(Text, nullable=False)  
    response_status_code = Column(Integer)  
    source_ip = Column(String)  
    user_agent = Column(Text)  
    request_object = Column(Text)  
    response_object = Column(Text)  
    created_at = Column(BigInteger, default=lambda: int(time.time()))
    processing_time = Column(Integer)


class AuditConfig(Base):  
    """审计配置表"""  
    __tablename__ = "audit_config"
      
    id = Column(String, primary_key=True)  
    # 配置键名  
    key = Column(String, unique=True, nullable=False)  
    # 配置值  
    value = Column(String, nullable=False)  
    # 配置描述  
    description = Column(Text)  
    # 是否启用  
    is_active = Column(Integer, default=1)  
    # 创建时间  
    created_at = Column(BigInteger, default=lambda: int(time.time()))  
    # 更新时间  
    updated_at = Column(BigInteger, default=lambda: int(time.time()))


####################
# TABLE CLASSES
####################

class AuditLogTable:
    """审计日志表操作类"""
    
    def create(self, user_id: str = None, user_name: str = None, user_email: str = None,
               user_role: str = None, verb: str = "", request_uri: str = "",
               response_status_code: int = None, source_ip: str = None,
               user_agent: str = None, request_object: str = None,
               response_object: str = None, processing_time: int = None) -> Optional[AuditLog]:
        """创建审计日志"""
        try:
            with get_db() as db:
                log_entry = AuditLog(
                    id=str(uuid.uuid4()),
                    timestamp=int(time.time()),
                    user_id=user_id,
                    user_name=user_name,
                    user_email=user_email,
                    user_role=user_role,
                    verb=verb,
                    request_uri=request_uri,
                    response_status_code=response_status_code,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    request_object=request_object,
                    response_object=response_object,
                    created_at=int(time.time()),
                    processing_time=processing_time
                )
                db.add(log_entry)
                db.commit()
                db.refresh(log_entry)
                return log_entry
        except Exception as e:
            log.error(f"创建审计日志失败: {e}")
            return None
    
    def get_by_id(self, log_id: str) -> Optional[AuditLog]:
        """根据ID获取审计日志"""
        try:
            with get_db() as db:
                log_entry = db.query(AuditLog).filter_by(id=log_id).first()
                return log_entry
        except Exception as e:
            log.error(f"获取审计日志失败: {e}")
            return None
    
    def get_logs(self, limit: int = 100, offset: int = 0, 
                 user_id: str = None, user_role: str = None,
                 verb: str = None, start_time: int = None, 
                 end_time: int = None) -> List[AuditLog]:
        """获取审计日志列表"""
        try:
            with get_db() as db:
                query = db.query(AuditLog)
                
                # 应用过滤条件
                if user_id:
                    query = query.filter(AuditLog.user_id == user_id)
                if user_role:
                    query = query.filter(AuditLog.user_role == user_role)
                if verb:
                    query = query.filter(AuditLog.verb == verb)
                if start_time:
                    query = query.filter(AuditLog.timestamp >= start_time)
                if end_time:
                    query = query.filter(AuditLog.timestamp <= end_time)
                
                # 排序和分页
                logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()
                return logs
        except Exception as e:
            log.error(f"获取审计日志列表失败: {e}")
            return []
    
    def count_logs(self, user_id: str = None, user_role: str = None,
                   verb: str = None, start_time: int = None,
                   end_time: int = None) -> int:
        """统计审计日志数量"""
        try:
            with get_db() as db:
                query = db.query(AuditLog)
                
                # 应用过滤条件
                if user_id:
                    query = query.filter(AuditLog.user_id == user_id)
                if user_role:
                    query = query.filter(AuditLog.user_role == user_role)
                if verb:
                    query = query.filter(AuditLog.verb == verb)
                if start_time:
                    query = query.filter(AuditLog.timestamp >= start_time)
                if end_time:
                    query = query.filter(AuditLog.timestamp <= end_time)
                
                count = query.count()
                return count
        except Exception as e:
            log.error(f"统计审计日志失败: {e}")
            return 0
    
    def get_logs_by_user(self, user_id: str, limit: int = 100) -> List[AuditLog]:
        """获取指定用户的审计日志"""
        return self.get_logs(limit=limit, user_id=user_id)
    
    def get_logs_by_role(self, user_role: str, limit: int = 100) -> List[AuditLog]:
        """获取指定角色的审计日志"""
        return self.get_logs(limit=limit, user_role=user_role)
    
    def get_logs_by_action(self, verb: str, limit: int = 100) -> List[AuditLog]:
        """获取指定操作类型的审计日志"""
        return self.get_logs(limit=limit, verb=verb)
    
    def get_logs_by_time_range(self, start_time: int, end_time: int, limit: int = 100) -> List[AuditLog]:
        """获取指定时间范围的审计日志"""
        return self.get_logs(limit=limit, start_time=start_time, end_time=end_time)
    
    def get_recent_logs(self, hours: int = 24, limit: int = 100) -> List[AuditLog]:
        """获取最近的审计日志"""
        start_time = int(time.time()) - (hours * 3600)
        return self.get_logs(limit=limit, start_time=start_time)
    
    def get_statistics(self, start_time: int = None, end_time: int = None) -> Dict[str, Any]:
        """获取审计统计信息"""
        try:
            with get_db() as db:
                query = db.query(AuditLog)
                
                if start_time:
                    query = query.filter(AuditLog.timestamp >= start_time)
                if end_time:
                    query = query.filter(AuditLog.timestamp <= end_time)
                
                logs = query.all()
                
                # 统计各种维度
                stats = {
                    "total_count": len(logs),
                    "by_role": {},
                    "by_verb": {},
                    "by_status": {},
                    "by_user": {}
                }
                
                for log_entry in logs:
                    # 按角色统计
                    role = log_entry.user_role or "unknown"
                    stats["by_role"][role] = stats["by_role"].get(role, 0) + 1
                    
                    # 按操作类型统计
                    verb = log_entry.verb or "unknown"
                    stats["by_verb"][verb] = stats["by_verb"].get(verb, 0) + 1
                    
                    # 按状态码统计
                    status = str(log_entry.response_status_code) if log_entry.response_status_code else "unknown"
                    stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
                    
                    # 按用户统计
                    user = log_entry.user_name or log_entry.user_id or "unknown"
                    stats["by_user"][user] = stats["by_user"].get(user, 0) + 1
                
                return stats
        except Exception as e:
            log.error(f"获取审计统计失败: {e}")
            return {
                "total_count": 0,
                "by_role": {},
                "by_verb": {},
                "by_status": {},
                "by_user": {}
            }
    
    def delete_old_logs(self, days: int = 90) -> int:
        """删除旧的审计日志"""
        try:
            with get_db() as db:
                cutoff_time = int(time.time()) - (days * 24 * 3600)
                result = db.query(AuditLog).filter(AuditLog.timestamp < cutoff_time).delete()
                db.commit()
                return result
        except Exception as e:
            log.error(f"删除旧审计日志失败: {e}")
            return 0


class AuditConfigTable:
    """审计配置表操作类"""
    
    def get_config_by_key(self, key: str) -> Optional[AuditConfig]:
        """根据键获取配置"""
        try:
            with get_db() as db:
                config = db.query(AuditConfig).filter_by(key=key, is_active=1).first()
                return config
        except Exception as e:
            log.error(f"获取审计配置失败: {e}")
            return None
    
    def get_all_configs(self) -> List[AuditConfig]:
        """获取所有配置"""
        try:
            with get_db() as db:
                configs = db.query(AuditConfig).filter_by(is_active=1).all()
                return configs
        except Exception as e:
            log.error(f"获取所有审计配置失败: {e}")
            return []
    
    def create_config(self, key: str, value: str, description: str = None) -> Optional[AuditConfig]:
        """创建配置"""
        try:
            with get_db() as db:
                config = AuditConfig(
                    id=str(uuid.uuid4()),
                    key=key,
                    value=value,
                    description=description,
                    is_active=1,
                    created_at=int(time.time()),
                    updated_at=int(time.time())
                )
                db.add(config)
                db.commit()
                db.refresh(config)
                return config
        except Exception as e:
            log.error(f"创建审计配置失败: {e}")
            return None
    
    def update_config(self, key: str, value: str, description: str = None) -> bool:
        """更新配置"""
        try:
            with get_db() as db:
                config = db.query(AuditConfig).filter_by(key=key).first()
                if config:
                    config.value = value
                    if description:
                        config.description = description
                    config.updated_at = int(time.time())
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"更新审计配置失败: {e}")
            return False
    
    def delete_config(self, key: str) -> bool:
        """删除配置（软删除）"""
        try:
            with get_db() as db:
                config = db.query(AuditConfig).filter_by(key=key).first()
                if config:
                    config.is_active = 0
                    config.updated_at = int(time.time())
                    db.commit()
                    return True
                return False
        except Exception as e:
            log.error(f"删除审计配置失败: {e}")
            return False


# 创建全局实例
AuditLogs = AuditLogTable()
AuditConfigs = AuditConfigTable()
