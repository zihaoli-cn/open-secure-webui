import re
import uuid
import time
import json
from typing import Optional, Dict, Any, cast, MutableMapping
from contextlib import asynccontextmanager
import asyncio
from collections import defaultdict

from asgiref.typing import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGIReceiveEvent,
    ASGISendCallable,
    ASGISendEvent,
    Scope as ASGIScope,
)
import logging
from starlette.requests import Request

from open_webui.env import SRC_LOG_LEVELS

from open_webui.internal.db import get_db
from open_webui.models.audit_log import AuditLog, AuditConfig
from open_webui.models.users import UserModel
from open_webui.utils.auth import get_current_user, get_http_authorization_cred

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["MAIN"])



class AuditContext:
    """捕获请求和响应数据的上下文"""

    def __init__(self, max_body_size: int = 1048576):  # 默认1MB
        self.request_body = bytearray()
        self.response_body = bytearray()
        self.max_body_size = max_body_size
        self.metadata: Dict[str, Any] = {}
        self.start_time = time.time()
        self._request_size = 0
        self._response_size = 0

    def add_request_chunk(self, chunk: bytes):
        if self._request_size < self.max_body_size:
            remaining = self.max_body_size - self._request_size
            chunk_to_add = chunk[:remaining]
            self.request_body.extend(chunk_to_add)
            self._request_size += len(chunk_to_add)

    def add_response_chunk(self, chunk: bytes):
        if self._response_size < self.max_body_size:
            remaining = self.max_body_size - self._response_size
            chunk_to_add = chunk[:remaining]
            self.response_body.extend(chunk_to_add)
            self._response_size += len(chunk_to_add)

    def cleanup(self):
        """清理内存资源"""
        # 彻底清理字节数组，释放内存
        if self.request_body:
            self.request_body.clear()
        if self.response_body:
            self.response_body.clear()
        self._request_size = 0
        self._response_size = 0
        self.metadata.clear()


class DatabaseAuditMiddleware:
    """
    持久化Audit中间件 - 将所有请求信息保存到数据库
    不使用audit level分级，默认记录所有信息
    """

    # 需要审计的HTTP方法
    AUDITED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

    # 敏感字段列表
    SENSITIVE_FIELDS = [
        "password", "token", "api_key", "secret", "authorization",
        "access_token", "refresh_token", "api_secret", "private_key",
        "client_secret", "bearer", "credential", "auth"
    ]

    def __init__(
        self,
        app: ASGI3Application,
        *,
        excluded_paths: Optional[list[str]] = None,
        max_body_size: int = 1048576,
    ) -> None:
        self.app = app
        self.excluded_paths = excluded_paths or []
        self.max_body_size = max_body_size
        # 速率限制跟踪
        self._rate_limit_tracker = defaultdict(list)
        # 初始化安全配置
        self._init_config()
        
    def _init_config(self):
        """从数据库初始化配置参数，如果不存在则使用默认值"""
        config_defaults = {
            "AUDIT_RATE_LIMIT_WINDOW": ("60", "审计速率限制时间窗口（秒）"),
            "AUDIT_RATE_LIMIT_MAX_REQUESTS": ("100", "每个窗口最大请求数"),
            "AUDIT_RATE_LIMIT_BY_IP": ("true", "是否按IP进行速率限制"),
            "AUDIT_RATE_LIMIT_BY_USER": ("true", "是否按用户进行速率限制")
        }
        
        try:
            with get_db() as db:
                for key, (default_value, description) in config_defaults.items():
                    config = db.query(AuditConfig).filter(AuditConfig.key == key).first()
                    if not config:
                        # 如果配置不存在，创建默认配置
                        config = AuditConfig(
                            id=str(uuid.uuid4()),
                            key=key,
                            value=default_value,
                            description=description,
                            is_active=1  # 使用整数1表示激活状态
                        )
                        db.add(config)
                        db.commit()
        except Exception as e:
            logger.warning(f"Failed to initialize audit configs: {e}")
            
    def _get_security_config(self, key: str, default_value: Any) -> Any:
        """从数据库获取安全配置，如果没有则使用默认值"""
        try:
            with get_db() as db:
                config = db.query(AuditConfig).filter(AuditConfig.key == key).first()
                # 检查 is_active 是否为激活状态（兼容整数和布尔类型）
                is_active = config.is_active if isinstance(config.is_active, bool) else config.is_active == 1
                if config and is_active:
                    # 尝试转换为合适的类型
                    if isinstance(default_value, int):
                        try:
                            return int(config.value)
                        except ValueError:
                            # 如果转换失败，记录警告并返回默认值
                            logger.warning(f"Failed to convert config {key} value '{config.value}' to int, using default {default_value}")
                            return default_value
                    elif isinstance(default_value, bool):
                        # 对于布尔值，需要特殊处理
                        return str(config.value).lower() in ['true', '1', 'yes', 'on']
                    else:
                        return config.value
        except Exception as e:
            logger.warning(f"Failed to get security config for {key}: {e}")
            
        return default_value
      
    async def __call__(  
        self,  
        scope: ASGIScope,  
        receive: ASGIReceiveCallable,  
        send: ASGISendCallable,  
    ) -> None:  
        if scope["type"] != "http":  
            return await self.app(scope, receive, send)  
          
        request = Request(scope=cast(MutableMapping, scope))  
          
        if self._should_skip_auditing(request):  
            return await self.app(scope, receive, send)  
          
        async with self._audit_context(request) as context:  
            async def send_wrapper(message: ASGISendEvent) -> None:  
                await self._capture_response(message, context)  
                await send(message)  
              
            async def receive_wrapper() -> ASGIReceiveEvent:  
                message = await receive()  
                await self._capture_request(message, context)  
                return message  
              
            await self.app(scope, receive_wrapper, send_wrapper)  
      
    @asynccontextmanager  
    async def _audit_context(self, request: Request):  
        """审计上下文管理器"""  
        context = AuditContext(self.max_body_size)  
        try:  
            yield context  
        finally:  
            # 在后台任务中保存审计记录，避免阻塞主请求
            asyncio.create_task(self._save_audit_entry(request, context))
      
    def _should_skip_auditing(self, request: Request) -> bool:  
        """判断是否跳过审计"""  
        # 只审计配置的HTTP方法  
        if request.method not in self.AUDITED_METHODS:  
            return True  
          
        # 检查排除路径  
        path = request.url.path.lower()  
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path.lower()):
                return True
          
        return False  
      
    async def _get_authenticated_user(self, request: Request) -> Optional[UserModel]:
        """获取认证用户"""
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None

        try:
            # 使用正确的参数调用 get_current_user
            # 参考 audit.py 的实现，传递 None 作为 response 和 background_tasks
            cred = get_http_authorization_cred(auth_header)
            if cred is None:
                logger.debug("Invalid Authorization header")
                return None
            user = await get_current_user(request, None, None, cred)
            logger.debug(f"Authenticated user: {user}")
            return user
        except Exception as e:
            logger.debug(f"Failed to get authenticated user: {str(e)}")
        return None  
      
    async def _capture_request(self, message: ASGIReceiveEvent, context: AuditContext):  
        """捕获请求体"""  
        if message["type"] == "http.request":  
            body = message.get("body", b"")  
            context.add_request_chunk(body)  
      
    async def _capture_response(self, message: ASGISendEvent, context: AuditContext):  
        """捕获响应体"""  
        if message["type"] == "http.response.start":  
            context.metadata["response_status_code"] = message["status"]  
        elif message["type"] == "http.response.body":  
            body = message.get("body", b"")  
            context.add_response_chunk(body)  
      
    def _redact_sensitive_data(self, data: str) -> str:  
        """脱敏敏感信息"""  
        if not data:  
            return data  
          
        # 对于JSON数据，尝试解析并脱敏
        try:
            parsed_data = json.loads(data)
            if isinstance(parsed_data, dict):
                self._redact_dict(parsed_data)
                return json.dumps(parsed_data, ensure_ascii=False)
        except json.JSONDecodeError:
            pass  # 不是JSON数据，继续处理
            
        # 脱敏表单数据和其他文本数据
        for field in self.SENSITIVE_FIELDS:  
            # 脱敏JSON格式的字段  
            data = re.sub(  
                rf'("{field}"\s*:\s*")[^"]*(")',  
                r'\1********\2',  
                data,  
                flags=re.IGNORECASE  
            )  
            # 脱敏表单格式的字段  
            data = re.sub(  
                rf'(&?{field}=)[^&]*',  
                r'\1********',  
                data,  
                flags=re.IGNORECASE  
            )  
            # 脱敏Authorization header  
            data = re.sub(  
                rf'({field}:\s*)[^\n\r]*',  
                r'\1********',  
                data,  
                flags=re.IGNORECASE  
            )  
          
        return data  
        
    def _redact_dict(self, data: dict) -> None:
        """递归脱敏字典中的敏感字段"""
        for key, value in data.items():
            if isinstance(value, dict):
                self._redact_dict(value)
            elif any(sensitive_field in key.lower() for sensitive_field in self.SENSITIVE_FIELDS):
                data[key] = "********"
            elif isinstance(value, str) and any(sensitive_word in value.lower() for sensitive_word in ["bearer", "token"]):
                data[key] = "********"
      
    def _check_rate_limit(self, request: Request, user: Optional[UserModel]) -> bool:
        """检查速率限制，返回True如果超过限制"""
        current_time = time.time()

        # 获取速率限制配置
        rate_limit_window = self._get_security_config("AUDIT_RATE_LIMIT_WINDOW", 60)
        rate_limit_max_requests = self._get_security_config("AUDIT_RATE_LIMIT_MAX_REQUESTS", 100)
        rate_limit_by_ip = self._get_security_config("AUDIT_RATE_LIMIT_BY_IP", True)
        rate_limit_by_user = self._get_security_config("AUDIT_RATE_LIMIT_BY_USER", True)

        # 清理过期的请求记录
        self._cleanup_rate_limit_tracker(current_time, rate_limit_window)

        # 按IP进行速率限制
        if rate_limit_by_ip:
            client_ip = request.client.host if request.client else "unknown"
            ip_key = f"ip:{client_ip}"
            if self._is_rate_limited(ip_key, current_time, rate_limit_window, rate_limit_max_requests):
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return True

        # 按用户进行速率限制
        if rate_limit_by_user and user:
            user_key = f"user:{user.id}"
            if self._is_rate_limited(user_key, current_time, rate_limit_window, rate_limit_max_requests):
                logger.warning(f"Rate limit exceeded for user: {user.id}")
                return True

        return False

    def _is_rate_limited(self, key: str, current_time: float, window: int, max_requests: int) -> bool:
        """检查特定键是否超过速率限制"""
        # 清理当前键的过期记录
        self._rate_limit_tracker[key] = [
            timestamp for timestamp in self._rate_limit_tracker[key]
            if current_time - timestamp < window
        ]

        # 检查是否超过限制
        if len(self._rate_limit_tracker[key]) >= max_requests:
            return True

        # 添加当前请求时间戳
        self._rate_limit_tracker[key].append(current_time)
        return False

    def _cleanup_rate_limit_tracker(self, current_time: float, window: int):
        """清理速率限制跟踪器中过期的记录"""
        # 定期清理整个跟踪器（每100次请求清理一次，避免性能问题）
        cleanup_interval = 100
        if len(self._rate_limit_tracker) > cleanup_interval:
            expired_keys = []
            for key, timestamps in self._rate_limit_tracker.items():
                # 清理每个键的过期时间戳
                self._rate_limit_tracker[key] = [
                    ts for ts in timestamps
                    if current_time - ts < window
                ]
                # 如果键为空，标记为待删除
                if not self._rate_limit_tracker[key]:
                    expired_keys.append(key)

            # 删除空的键
            for key in expired_keys:
                del self._rate_limit_tracker[key]

    async def _save_audit_entry(self, request: Request, context: AuditContext):
        """保存审计记录到数据库"""
        max_retries = 3
        retry_delay = 1  # seconds

        for attempt in range(max_retries):
            try:
                user = await self._get_authenticated_user(request)

                # 检查速率限制
                if self._check_rate_limit(request, user):
                    logger.warning("Audit entry skipped due to rate limiting")
                    return

                # 解码请求和响应体
                request_body = context.request_body.decode("utf-8", errors="replace")
                response_body = context.response_body.decode("utf-8", errors="replace")

                # 脱敏处理
                request_body = self._redact_sensitive_data(request_body)
                response_body = self._redact_sensitive_data(response_body)

                # 计算处理时间
                duration = time.time() - context.start_time

                # 创建审计日志记录
                audit_log = AuditLog(
                    id=str(uuid.uuid4()),
                    timestamp=int(time.time() * 1000),  # 毫秒时间戳
                    user_id=user.id if user else None,
                    user_name=user.name if user else None,
                    user_email=user.email if user else None,
                    user_role=user.role if user else None,
                    verb=request.method,
                    request_uri=str(request.url),
                    response_status_code=context.metadata.get("response_status_code"),
                    source_ip=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    request_object=request_body[:self.max_body_size] if request_body else None,
                    response_object=response_body[:self.max_body_size] if response_body else None,
                    processing_time=int(duration * 1000)  # 处理时间（毫秒）
                )

                # 保存到数据库
                try:
                    with get_db() as db:
                        db.add(audit_log)
                        db.commit()
                    # 成功保存，退出重试循环
                    break
                except Exception as e:
                    logger.warning(f"Database commit attempt {attempt + 1} failed: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying in {retry_delay} seconds...")
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # 指数退避
                    else:
                        logger.error(f"Failed to commit audit entry after {max_retries} attempts: {str(e)}")
                        raise

            except Exception as e:
                logger.error(f"Failed to save audit entry to database on attempt {attempt + 1}: {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # 指数退避
                else:
                    logger.error(f"Failed to save audit entry after {max_retries} attempts: {str(e)}")