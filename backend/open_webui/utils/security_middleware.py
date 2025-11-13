import re  
import uuid  
import time  
from typing import Optional, cast, MutableMapping  
from contextlib import asynccontextmanager  
  
from asgiref.typing import (  
    ASGI3Application,  
    ASGIReceiveCallable,  
    ASGIReceiveEvent,  
    ASGISendCallable,  
    ASGISendEvent,  
    Scope as ASGIScope,  
)  
from loguru import logger  
from starlette.requests import Request  
from starlette.responses import JSONResponse  
import json  
  
from open_webui.internal.db import get_db  
from open_webui.models.security import UserIPWhitelist, LoginAttempt, UserLockStatus, PasswordPolicy, SecurityConfig  
from open_webui.models.users import Users  
  
  
class LoginSecurityMiddleware:  
    """  
    登录安全中间件  
    - IP白名单验证  
    - 登录失败次数限制  
    - 长期未登录账户锁定  
    - 密码过期检查  
    """  
      
    # 默认配置参数（防止静态检查错误）  
    MAX_FAILED_ATTEMPTS = 5  # 最大失败次数  
    FAILED_ATTEMPTS_WINDOW = 900  # 失败次数统计窗口（秒），15分钟  
    LOCKOUT_DURATION = 1800  # 锁定时长（秒），30分钟  
    INACTIVE_DAYS_THRESHOLD = 90  # 未登录天数阈值  
    PASSWORD_EXPIRY_DAYS = 90  # 密码过期天数  
      
    def __init__(  
        self,  
        app: ASGI3Application,  
        *,  
        enable_ip_whitelist: bool = True,  
        enable_failed_attempts_lock: bool = True,  
        enable_inactive_lock: bool = True,  
        enable_password_expiry: bool = True,  
    ) -> None:  
        self.app = app  
        self.enable_ip_whitelist = enable_ip_whitelist  
        self.enable_failed_attempts_lock = enable_failed_attempts_lock  
        self.enable_inactive_lock = enable_inactive_lock  
        self.enable_password_expiry = enable_password_expiry  
        # 初始化配置参数  
        self._init_config()  
      
    def _init_config(self):  
        """从数据库初始化配置参数，如果不存在则使用默认值"""  
        config_defaults = {  
            "MAX_FAILED_ATTEMPTS": ("5", "最大失败次数"),  
            "FAILED_ATTEMPTS_WINDOW": ("900", "失败次数统计窗口（秒），15分钟"),  
            "LOCKOUT_DURATION": ("1800", "锁定时长（秒），30分钟"),  
            "INACTIVE_DAYS_THRESHOLD": ("90", "未登录天数阈值"),  
            "PASSWORD_EXPIRY_DAYS": ("90", "密码过期天数")  
        }  
          
        with get_db() as db:  
            for key, (default_value, description) in config_defaults.items():  
                config = db.query(SecurityConfig).filter(SecurityConfig.key == key).first()  
                if not config:  
                    # 如果配置不存在，创建默认配置  
                    config = SecurityConfig(  
                        id=str(uuid.uuid4()),  
                        key=key,  
                        value=default_value,  
                        description=description  
                    )  
                    db.add(config)  
                    db.commit()  
                  
                # 设置实例属性  
                setattr(self, key, int(config.value))  
      
    async def __call__(  
        self,  
        scope: ASGIScope,  
        receive: ASGIReceiveCallable,  
        send: ASGISendCallable,  
    ) -> None:  
        if scope["type"] != "http":  
            return await self.app(scope, receive, send)  
          
        request = Request(scope=cast(MutableMapping, scope))  
          
        # 只拦截登录API  
        if not self._is_signin_request(request):  
            return await self.app(scope, receive, send)  
          
        # 读取请求体  
        body = await self._read_body(receive)  
          
        try:  
            credentials = json.loads(body.decode("utf-8"))  
            email = credentials.get("email", "").lower()  
              
            # 安全检查  
            security_check = await self._check_security(request, email)  
              
            if not security_check["allowed"]:  
                # 记录失败尝试  
                await self._log_attempt(  
                    email=email,  
                    ip_address=request.client.host if request.client else None,  
                    success=False,  
                    failure_reason=security_check["reason"],  
                    user_agent=request.headers.get("user-agent")  
                )  
                  
                # 返回错误响应  
                status_code = 403  
                # 如果是密码过期，使用特殊的响应码  
                if security_check["reason"] == "password_expired":  
                    status_code = 401  
                  
                response = JSONResponse(  
                    status_code=status_code,  
                    content={"detail": security_check["message"]}  
                )  
                await response(scope, receive, send)  
                return  
              
        except Exception as e:  
            logger.error(f"Security middleware error: {str(e)}")  
          
        # 继续处理请求，但需要包装receive以重新提供body  
        async def receive_wrapper():  
            return {"type": "http.request", "body": body}  
          
        # 包装send以捕获响应  
        response_status = None  
          
        async def send_wrapper(message: ASGISendEvent) -> None:  
            nonlocal response_status  
            if message["type"] == "http.response.start":  
                response_status = message["status"]  
            elif message["type"] == "http.response.body" and response_status:  
                # 登录完成后记录结果  
                try:  
                    credentials = json.loads(body.decode("utf-8"))  
                    email = credentials.get("email", "").lower()  
                    success = 200 <= response_status < 300  
                      
                    await self._log_attempt(  
                        email=email,  
                        ip_address=request.client.host if request.client else None,  
                        success=success,  
                        failure_reason="invalid_credentials" if not success else None,  
                        user_agent=request.headers.get("user-agent")  
                    )  
                      
                    if success:  
                        await self._update_success_login(email)  
                        # 如果启用了密码过期检查，更新密码策略  
                        if self.enable_password_expiry:  
                            await self._update_password_policy(email)  
                    else:  
                        await self._update_failed_login(email)  
                except Exception as e:  
                    logger.error(f"Failed to log login attempt: {str(e)}")  
              
            await send(message)  
          
        await self.app(scope, receive_wrapper, send_wrapper)  
      
    def _is_signin_request(self, request: Request) -> bool:  
        """判断是否为登录请求"""  
        path = request.url.path.lower()  
        return (  
            request.method == "POST" and  
            (path == "/api/v1/auths/signin" or path.endswith("/auths/signin"))  
        )  
      
    async def _read_body(self, receive: ASGIReceiveCallable) -> bytes:  
        """读取请求体"""  
        body = b""  
        while True:  
            message = await receive()  
            body += message.get("body", b"")  
            if not message.get("more_body", False):  
                break  
        return body  
      
    async def _check_security(self, request: Request, email: str) -> dict:  
        """执行安全检查"""  
        with get_db() as db:  
            # 1. 检查账户锁定状态  
            if self.enable_failed_attempts_lock or self.enable_inactive_lock:  
                lock_status = db.query(UserLockStatus).filter(  
                    UserLockStatus.user_email == email  
                ).first()  
                  
                if lock_status and lock_status.is_locked:  
                    # 检查是否到达自动解锁时间  
                    if lock_status.locked_until:  
                        current_time = int(time.time())  
                        if current_time < lock_status.locked_until:  
                            remaining = lock_status.locked_until - current_time  
                            return {  
                                "allowed": False,  
                                "reason": lock_status.lock_reason,  
                                "message": f"账户已被锁定，原因：{lock_status.lock_reason}。剩余锁定时间：{remaining // 60}分钟"  
                            }  
                        else:  
                            # 自动解锁  
                            lock_status.is_locked = False  
                            lock_status.locked_until = None  
                            lock_status.failed_attempts = 0  
                            db.commit()  
                    else:  
                        return {  
                            "allowed": False,  
                            "reason": lock_status.lock_reason,  
                            "message": f"账户已被永久锁定，原因：{lock_status.lock_reason}。请联系管理员解锁"  
                        }  
              
            # 2. 检查IP白名单  
            if self.enable_ip_whitelist:  
                user = Users.get_user_by_email(email)  
                if user:  
                    whitelisted_ips = db.query(UserIPWhitelist).filter(  
                        UserIPWhitelist.user_id == user.id,  
                        UserIPWhitelist.is_active == True  
                    ).all()  
                      
                    if whitelisted_ips:  
                        client_ip = request.client.host if request.client else None  
                        allowed_ips = [ip.ip_address for ip in whitelisted_ips]  
                          
                        if client_ip not in allowed_ips:  
                            return {  
                                "allowed": False,  
                                "reason": "ip_blocked",  
                                "message": f"您的IP地址 {client_ip} 不在允许的IP范围内。允许的IP：{', '.join(allowed_ips)}"  
                            }  
              
            # 3. 检查长期未登录  
            if self.enable_inactive_lock:  
                user = Users.get_user_by_email(email)  
                if user:  
                    lock_status = db.query(UserLockStatus).filter(  
                        UserLockStatus.user_email == email  
                    ).first()  
                      
                    if lock_status and lock_status.last_success_at:  
                        days_inactive = (int(time.time()) - lock_status.last_success_at) / 86400  
                        if days_inactive > self.INACTIVE_DAYS_THRESHOLD:  
                            # 锁定账户  
                            lock_status.is_locked = True  
                            lock_status.lock_reason = "inactive_too_long"  
                            lock_status.locked_at = int(time.time())  
                            lock_status.locked_until = None  # 需要管理员解锁  
                            db.commit()  
                              
                            return {  
                                "allowed": False,  
                                "reason": "inactive_too_long",  
                                "message": f"账户因超过{self.INACTIVE_DAYS_THRESHOLD}天未登录已被锁定，请联系管理员解锁"  
                            }  
              
            # 4. 检查密码是否过期  
            if self.enable_password_expiry:  
                password_policy = db.query(PasswordPolicy).filter(  
                    PasswordPolicy.user_email == email  
                ).first()  
                  
                if password_policy and password_policy.force_password_change:  
                    current_time = int(time.time())  
                    password_expiry_time = password_policy.password_set_at + (self.PASSWORD_EXPIRY_DAYS * 86400)  
                      
                    if current_time > password_expiry_time:  
                        return {  
                            "allowed": False,  
                            "reason": "password_expired",  
                            "message": "PASSWORD_EXPIRED"  
                        }
          
        return {"allowed": True}  
      
    async def _log_attempt(  
        self,  
        email: str,  
        ip_address: Optional[str],  
        success: bool,  
        failure_reason: Optional[str],  
        user_agent: Optional[str]  
    ):  
        """记录登录尝试"""  
        try:  
            with get_db() as db:  
                attempt = LoginAttempt(  
                    id=str(uuid.uuid4()),  
                    user_email=email,  
                    ip_address=ip_address,  
                    success=success,  
                    failure_reason=failure_reason,  
                    timestamp=int(time.time()),  
                    user_agent=user_agent  
                )  
                db.add(attempt)  
                db.commit()  
        except Exception as e:  
            logger.error(f"Failed to log login attempt: {str(e)}")  
      
    async def _update_success_login(self, email: str):  
        """更新成功登录状态"""  
        try:  
            with get_db() as db:  
                lock_status = db.query(UserLockStatus).filter(  
                    UserLockStatus.user_email == email  
                ).first()  
                  
                if not lock_status:  
                    lock_status = UserLockStatus(  
                        user_email=email,  
                        is_locked=False,  
                        failed_attempts=0  
                    )  
                    db.add(lock_status)  
                  
                lock_status.failed_attempts = 0  
                lock_status.last_success_at = int(time.time())  
                lock_status.last_failed_at = None  
                db.commit()  
        except Exception as e:  
            logger.error(f"Failed to update success login: {str(e)}")  
      
    async def _update_failed_login(self, email: str):  
        """更新失败登录状态"""  
        if not self.enable_failed_attempts_lock:  
            return  
          
        try:  
            with get_db() as db:  
                lock_status = db.query(UserLockStatus).filter(  
                    UserLockStatus.user_email == email  
                ).first()  
                  
                if not lock_status:  
                    lock_status = UserLockStatus(  
                        user_email=email,  
                        is_locked=False,  
                        failed_attempts=0  
                    )  
                    db.add(lock_status)  
                  
                current_time = int(time.time())  
                  
                # 检查是否在统计窗口内  
                if lock_status.last_failed_at:  
                    time_since_last_fail = current_time - lock_status.last_failed_at  
                    if time_since_last_fail > self.FAILED_ATTEMPTS_WINDOW:  
                        # 超出窗口，重置计数  
                        lock_status.failed_attempts = 1  
                    else:  
                        lock_status.failed_attempts += 1  
                else:  
                    lock_status.failed_attempts = 1  
                  
                lock_status.last_failed_at = current_time  
                  
                # 检查是否需要锁定  
                if lock_status.failed_attempts >= self.MAX_FAILED_ATTEMPTS:  
                    # 锁定账户  
                    lock_status.is_locked = True  
                    lock_status.lock_reason = "too_many_failures"  
                    lock_status.locked_at = current_time  
                    lock_status.locked_until = current_time + self.LOCKOUT_DURATION  
                    db.commit()  
        except Exception as e:  
            logger.error(f"Failed to update failed login: {str(e)}")  
      
    async def _update_password_policy(self, email: str):  
        """更新密码策略"""  
        try:  
            with get_db() as db:  
                password_policy = db.query(PasswordPolicy).filter(  
                    PasswordPolicy.user_email == email  
                ).first()  
                  
                if not password_policy:  
                    password_policy = PasswordPolicy(  
                        id=str(uuid.uuid4()),  
                        user_email=email,  
                        password_set_at=int(time.time()),  
                        force_password_change=True  
                    )  
                    db.add(password_policy)  
                else:  
                    # 更新密码设置时间  
                    password_policy.password_set_at = int(time.time())  
                  
                db.commit()  
        except Exception as e:  
            logger.error(f"Failed to update password policy: {str(e)}")