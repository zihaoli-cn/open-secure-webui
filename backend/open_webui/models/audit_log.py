from open_webui.internal.db import Base
from sqlalchemy import Column, Integer, String, Text, BigInteger
import time  
  
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