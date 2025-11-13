from sqlalchemy import Column, Integer, String, Text, BigInteger  
from open_webui.internal.db import Base  
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
