"""
审计中间件
自动记录所有API请求和响应
"""
import time
import json
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Callable

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    审计中间件 - 记录所有API请求和响应
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        处理请求并记录审计日志
        """
        # 记录请求开始时间
        start_time = time.time()
        
        # 提取请求信息
        method = request.method
        url = str(request.url)
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        
        # 提取用户信息（如果有）
        user_info = {
            "user_id": None,
            "user_name": None,
            "user_email": None,
            "user_role": None
        }
        
        # 尝试从请求中获取用户信息
        if hasattr(request.state, "user"):
            user = request.state.user
            user_info["user_id"] = user.get("id")
            user_info["user_name"] = user.get("username")
            user_info["user_email"] = user.get("email")
            user_info["user_role"] = user.get("admin_role")
        
        # 读取请求体（如果有）
        request_body = None
        if method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    request_body = body_bytes.decode("utf-8")
                    # 重新设置请求体，以便后续处理可以读取
                    async def receive():
                        return {"type": "http.request", "body": body_bytes}
                    request._receive = receive
            except Exception as e:
                logger.warning(f"读取请求体失败: {e}")
        
        # 处理请求
        response = await call_next(request)
        
        # 计算处理时间
        processing_time = int((time.time() - start_time) * 1000)  # 毫秒
        
        # 记录审计日志
        try:
            # 这里可以将审计日志写入数据库
            # 为了避免循环依赖，我们使用异步任务或直接数据库连接
            self._log_audit(
                user_id=user_info["user_id"],
                user_name=user_info["user_name"],
                user_email=user_info["user_email"],
                user_role=user_info["user_role"],
                verb=method,
                request_uri=url,
                response_status_code=response.status_code,
                source_ip=client_ip,
                user_agent=user_agent,
                request_object=request_body,
                processing_time=processing_time
            )
        except Exception as e:
            logger.error(f"记录审计日志失败: {e}")
        
        return response
    
    def _log_audit(self, **kwargs):
        """
        记录审计日志到数据库
        """
        try:
            # 导入审计日志模型
            from utils.database import get_db
            from sqlalchemy import text
            import uuid
            
            # 使用原始SQL插入审计日志
            with next(get_db()) as db:
                timestamp = int(time.time())
                db.execute(
                    text("""
                        INSERT INTO audit_logs (
                            id, timestamp, user_id, user_name, user_email, user_role,
                            verb, request_uri, response_status_code, source_ip,
                            user_agent, request_object, processing_time, created_at
                        ) VALUES (
                            :id, :timestamp, :user_id, :user_name, :user_email, :user_role,
                            :verb, :request_uri, :response_status_code, :source_ip,
                            :user_agent, :request_object, :processing_time, :created_at
                        )
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "timestamp": timestamp,
                        "user_id": kwargs.get("user_id"),
                        "user_name": kwargs.get("user_name"),
                        "user_email": kwargs.get("user_email"),
                        "user_role": kwargs.get("user_role"),
                        "verb": kwargs.get("verb"),
                        "request_uri": kwargs.get("request_uri"),
                        "response_status_code": kwargs.get("response_status_code"),
                        "source_ip": kwargs.get("source_ip"),
                        "user_agent": kwargs.get("user_agent"),
                        "request_object": kwargs.get("request_object"),
                        "processing_time": kwargs.get("processing_time"),
                        "created_at": timestamp
                    }
                )
                db.commit()
        except Exception as e:
            logger.error(f"写入审计日志到数据库失败: {e}")


class AdminAuditLogger:
    """
    管理员操作审计日志记录器
    用于记录三员管理系统中的关键操作
    """
    
    @staticmethod
    def log_admin_action(user_id: str, username: str, user_role: str,
                        action: str, resource_type: str, resource_id: str = None,
                        details: str = None, ip_address: str = None):
        """
        记录管理员操作
        """
        try:
            from utils.database import get_db
            from sqlalchemy import text
            import uuid
            
            with next(get_db()) as db:
                timestamp = int(time.time())
                # 将resource_type和resource_id合并到request_uri
                request_uri = f"{resource_type}:{resource_id}" if resource_id else resource_type
                db.execute(
                    text("""
                        INSERT INTO audit_logs (
                            id, timestamp, user_id, user_name, user_role,
                            verb, request_uri, source_ip, request_object, created_at
                        ) VALUES (
                            :id, :timestamp, :user_id, :user_name, :user_role,
                            :verb, :request_uri, :source_ip, :request_object, :created_at
                        )
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "timestamp": timestamp,
                        "user_id": user_id,
                        "user_name": username,
                        "user_role": user_role,
                        "verb": action,
                        "request_uri": request_uri,
                        "source_ip": ip_address,
                        "request_object": details,
                        "created_at": timestamp
                    }
                )
                db.commit()
                logger.info(f"记录管理员操作: {username} - {action} - {resource_type}")
        except Exception as e:
            logger.error(f"记录管理员操作失败: {e}")
    
    @staticmethod
    def log_login(username: str, user_role: str, success: bool, ip_address: str = None, reason: str = None):
        """记录登录操作"""
        action = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"
        details = f"登录{'成功' if success else '失败'}"
        if reason:
            details += f": {reason}"
        
        AdminAuditLogger.log_admin_action(
            user_id=None,
            username=username,
            user_role=user_role,
            action=action,
            resource_type="auth",
            details=details,
            ip_address=ip_address
        )
    
    @staticmethod
    def log_password_change(user_id: str, username: str, user_role: str, ip_address: str = None):
        """记录密码修改操作"""
        AdminAuditLogger.log_admin_action(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action="CHANGE_PASSWORD",
            resource_type="auth",
            details="修改密码",
            ip_address=ip_address
        )
    
    @staticmethod
    def log_api_key_create(user_id: str, username: str, user_role: str, 
                          api_key_name: str, ip_address: str = None):
        """记录API Key创建操作"""
        AdminAuditLogger.log_admin_action(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action="CREATE_API_KEY",
            resource_type="api_key",
            resource_id=api_key_name,
            details=f"创建API Key: {api_key_name}",
            ip_address=ip_address
        )
    
    @staticmethod
    def log_api_key_delete(user_id: str, username: str, user_role: str,
                          api_key_id: str, ip_address: str = None):
        """记录API Key删除操作"""
        AdminAuditLogger.log_admin_action(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action="DELETE_API_KEY",
            resource_type="api_key",
            resource_id=api_key_id,
            details=f"删除API Key: {api_key_id}",
            ip_address=ip_address
        )
    
    @staticmethod
    def log_security_config_update(user_id: str, username: str, user_role: str,
                                   config_key: str, ip_address: str = None):
        """记录安全配置更新操作"""
        AdminAuditLogger.log_admin_action(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action="UPDATE_SECURITY_CONFIG",
            resource_type="security_config",
            resource_id=config_key,
            details=f"更新安全配置: {config_key}",
            ip_address=ip_address
        )
    
    @staticmethod
    def log_ip_whitelist_add(user_id: str, username: str, user_role: str,
                            ip_address_added: str, ip_address: str = None):
        """记录IP白名单添加操作"""
        AdminAuditLogger.log_admin_action(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action="ADD_IP_WHITELIST",
            resource_type="ip_whitelist",
            resource_id=ip_address_added,
            details=f"添加IP白名单: {ip_address_added}",
            ip_address=ip_address
        )
    
    @staticmethod
    def log_ip_whitelist_remove(user_id: str, username: str, user_role: str,
                                ip_address_removed: str, ip_address: str = None):
        """记录IP白名单移除操作"""
        AdminAuditLogger.log_admin_action(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action="REMOVE_IP_WHITELIST",
            resource_type="ip_whitelist",
            resource_id=ip_address_removed,
            details=f"移除IP白名单: {ip_address_removed}",
            ip_address=ip_address
        )
