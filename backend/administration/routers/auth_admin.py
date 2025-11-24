from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from utils.database import get_db
from utils.auth import AuthManager
from config import settings

router = APIRouter(prefix="/api/auth-admin", tags=["安全管理员"])


# 安全配置相关模型
class SecurityConfigRequest(BaseModel):
    max_failed_attempts: Optional[int] = None
    lockout_duration: Optional[int] = None
    password_expiry_days: Optional[int] = None
    ip_whitelist_enabled: Optional[bool] = None


class SecurityConfigResponse(BaseModel):
    max_failed_attempts: int
    lockout_duration: int
    password_expiry_days: int
    ip_whitelist_enabled: bool
    updated_at: datetime


# IP白名单相关模型
class IpWhitelistRequest(BaseModel):
    ip_address: str
    description: Optional[str] = None


class IpWhitelistResponse(BaseModel):
    id: int
    ip_address: str
    description: Optional[str]
    created_at: datetime
    created_by: str
    is_active: bool = True


class IpWhitelistListResponse(BaseModel):
    ip_addresses: List[IpWhitelistResponse]
    total: int


class IpWhitelistUpdateRequest(BaseModel):
    ip_address: Optional[str] = None
    description: Optional[str] = None


class IpWhitelistToggleRequest(BaseModel):
    enabled: bool


class BatchToggleRequest(BaseModel):
    ip_ids: List[int]
    enabled: bool


class IpValidationRequest(BaseModel):
    ip_address: str


@router.get("/security-config", response_model=SecurityConfigResponse)
async def get_security_config(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取安全配置
    """
    try:
        # 从数据库获取配置，如果没有则使用默认值
        result = db.execute(
            """
            SELECT config_value
            FROM admin_config
            WHERE config_key = 'security_config'
            """
        ).fetchone()

        if result:
            config_data = result.config_value
        else:
            # 使用默认配置
            config_data = {
                "max_failed_attempts": settings.MAX_LOGIN_ATTEMPTS,
                "lockout_duration": settings.LOCKOUT_DURATION,
                "password_expiry_days": settings.PASSWORD_EXPIRY_DAYS,
                "ip_whitelist_enabled": False
            }

        return SecurityConfigResponse(
            max_failed_attempts=config_data.get("max_failed_attempts", settings.MAX_LOGIN_ATTEMPTS),
            lockout_duration=config_data.get("lockout_duration", settings.LOCKOUT_DURATION),
            password_expiry_days=config_data.get("password_expiry_days", settings.PASSWORD_EXPIRY_DAYS),
            ip_whitelist_enabled=config_data.get("ip_whitelist_enabled", False),
            updated_at=datetime.now()
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取安全配置失败: {str(e)}"
        )


@router.put("/security-config", response_model=SecurityConfigResponse)
async def update_security_config(
    request: SecurityConfigRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    更新安全配置
    """
    try:
        # 获取当前配置
        current_config = await get_security_config(current_user, db)

        # 构建更新数据
        update_data = {
            "max_failed_attempts": request.max_failed_attempts or current_config.max_failed_attempts,
            "lockout_duration": request.lockout_duration or current_config.lockout_duration,
            "password_expiry_days": request.password_expiry_days or current_config.password_expiry_days,
            "ip_whitelist_enabled": request.ip_whitelist_enabled if request.ip_whitelist_enabled is not None
                              else current_config.ip_whitelist_enabled
        }

        # 保存到数据库
        db.execute(
            """
            INSERT INTO admin_config (config_key, config_value, description, created_by)
            VALUES ('security_config', :config_value, '安全配置', :created_by)
            ON CONFLICT (config_key)
            DO UPDATE SET config_value = :config_value, updated_at = CURRENT_TIMESTAMP
            """,
            {
                "config_value": update_data,
                "created_by": current_user["username"]
            }
        )

        db.commit()

        return SecurityConfigResponse(
            max_failed_attempts=update_data["max_failed_attempts"],
            lockout_duration=update_data["lockout_duration"],
            password_expiry_days=update_data["password_expiry_days"],
            ip_whitelist_enabled=update_data["ip_whitelist_enabled"],
            updated_at=datetime.now()
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新安全配置失败: {str(e)}"
        )


@router.get("/ip-whitelist", response_model=IpWhitelistListResponse)
async def get_ip_whitelist(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取IP白名单列表
    """
    try:
        # 从现有系统的UserIPWhitelist表获取数据
        result = db.execute(
            """
            SELECT id, user_id, ip_address, created_at, created_by
            FROM user_ip_whitelist
            WHERE is_active = true
            ORDER BY created_at DESC
            """
        ).fetchall()

        ip_addresses = [
            IpWhitelistResponse(
                id=row.id,
                ip_address=row.ip_address,
                description=f"用户ID: {row.user_id}",
                created_at=row.created_at,
                created_by=row.created_by or "system"
            )
            for row in result
        ]

        return IpWhitelistListResponse(ip_addresses=ip_addresses, total=len(ip_addresses))

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取IP白名单失败: {str(e)}"
        )


@router.post("/ip-whitelist", response_model=IpWhitelistResponse)
async def add_ip_whitelist(
    request: IpWhitelistRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    添加IP白名单
    """
    try:
        # 验证IP地址格式
        import ipaddress
        try:
            ipaddress.ip_address(request.ip_address)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的IP地址格式"
            )

        # 检查是否已存在
        existing = db.execute(
            """
            SELECT id FROM user_ip_whitelist
            WHERE ip_address = :ip_address AND is_active = true
            """,
            {"ip_address": request.ip_address}
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该IP地址已在白名单中"
            )

        # 添加到现有系统的UserIPWhitelist表
        result = db.execute(
            """
            INSERT INTO user_ip_whitelist (user_id, ip_address, created_by, is_active)
            VALUES (:user_id, :ip_address, :created_by, true)
            RETURNING id, ip_address, created_at, created_by
            """,
            {
                "user_id": current_user["id"],  # 使用当前管理员ID
                "ip_address": request.ip_address,
                "created_by": current_user["username"]
            }
        ).fetchone()

        db.commit()

        return IpWhitelistResponse(
            id=result.id,
            ip_address=result.ip_address,
            description=request.description,
            created_at=result.created_at,
            created_by=result.created_by
        )

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"添加IP白名单失败: {str(e)}"
        )


@router.delete("/ip-whitelist/{ip_id}")
async def remove_ip_whitelist(
    ip_id: int,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    移除IP白名单
    """
    try:
        result = db.execute(
            """
            UPDATE user_ip_whitelist
            SET is_active = false
            WHERE id = :id
            RETURNING id
            """,
            {"id": ip_id}
        ).fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="IP白名单记录不存在"
            )

        db.commit()

        return {"success": True, "message": "IP白名单移除成功"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"移除IP白名单失败: {str(e)}"
        )


@router.put("/ip-whitelist/{ip_id}", response_model=IpWhitelistResponse)
async def update_ip_whitelist(
    ip_id: int,
    request: IpWhitelistUpdateRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    更新IP白名单
    """
    try:
        # 检查IP记录是否存在
        existing = db.execute(
            """
            SELECT id, ip_address, description, created_at, created_by, is_active
            FROM user_ip_whitelist
            WHERE id = :id
            """,
            {"id": ip_id}
        ).fetchone()

        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="IP白名单记录不存在"
            )

        # 如果更新IP地址，验证格式
        if request.ip_address:
            import ipaddress
            try:
                ipaddress.ip_address(request.ip_address)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="无效的IP地址格式"
                )

            # 检查新IP是否已存在
            duplicate = db.execute(
                """
                SELECT id FROM user_ip_whitelist
                WHERE ip_address = :ip_address AND id != :id AND is_active = true
                """,
                {"ip_address": request.ip_address, "id": ip_id}
            ).fetchone()

            if duplicate:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="该IP地址已在白名单中"
                )

        # 更新记录
        result = db.execute(
            """
            UPDATE user_ip_whitelist
            SET
                ip_address = COALESCE(:ip_address, ip_address),
                description = COALESCE(:description, description),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            RETURNING id, ip_address, description, created_at, created_by, is_active
            """,
            {
                "id": ip_id,
                "ip_address": request.ip_address,
                "description": request.description
            }
        ).fetchone()

        db.commit()

        return IpWhitelistResponse(
            id=result.id,
            ip_address=result.ip_address,
            description=result.description,
            created_at=result.created_at,
            created_by=result.created_by,
            is_active=result.is_active
        )

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新IP白名单失败: {str(e)}"
        )


@router.patch("/ip-whitelist/{ip_id}/enable")
async def enable_ip_address(
    ip_id: int,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    启用IP地址
    """
    try:
        result = db.execute(
            """
            UPDATE user_ip_whitelist
            SET is_active = true, updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            RETURNING id
            """,
            {"id": ip_id}
        ).fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="IP白名单记录不存在"
            )

        db.commit()

        return {"success": True, "message": "IP地址已启用"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"启用IP地址失败: {str(e)}"
        )


@router.patch("/ip-whitelist/{ip_id}/disable")
async def disable_ip_address(
    ip_id: int,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    禁用IP地址
    """
    try:
        result = db.execute(
            """
            UPDATE user_ip_whitelist
            SET is_active = false, updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
            RETURNING id
            """,
            {"id": ip_id}
        ).fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="IP白名单记录不存在"
            )

        db.commit()

        return {"success": True, "message": "IP地址已禁用"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"禁用IP地址失败: {str(e)}"
        )


@router.patch("/ip-whitelist/batch-toggle")
async def batch_toggle_ip_addresses(
    request: BatchToggleRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    批量启用/禁用IP地址
    """
    try:
        if not request.ip_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="IP ID列表不能为空"
            )

        # 更新所有指定的IP地址
        result = db.execute(
            """
            UPDATE user_ip_whitelist
            SET is_active = :enabled, updated_at = CURRENT_TIMESTAMP
            WHERE id = ANY(:ip_ids)
            RETURNING id
            """,
            {
                "enabled": request.enabled,
                "ip_ids": request.ip_ids
            }
        ).fetchall()

        db.commit()

        return {
            "success": True,
            "message": f"成功更新{len(result)}个IP地址",
            "updated_count": len(result)
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"批量操作失败: {str(e)}"
        )


@router.post("/ip-whitelist/validate")
async def validate_ip_format(
    request: IpValidationRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin)
):
    """
    验证IP格式
    """
    try:
        import ipaddress
        try:
            ipaddress.ip_address(request.ip_address)
            return {
                "valid": True,
                "message": "IP地址格式正确",
                "ip_type": "IPv4" if "." in request.ip_address else "IPv6"
            }
        except ValueError:
            return {
                "valid": False,
                "message": "无效的IP地址格式",
                "ip_type": None
            }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"验证IP格式失败: {str(e)}"
        )


@router.get("/password-policy")
async def get_password_policy(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取密码策略
    """
    try:
        # 从现有系统的PasswordPolicy表获取数据
        result = db.execute(
            """
            SELECT
                MIN(password_expiry_interval) as min_expiry,
                MAX(password_expiry_interval) as max_expiry,
                AVG(password_expiry_interval) as avg_expiry
            FROM password_policy
            WHERE force_password_change = true
            """
        ).fetchone()

        return {
            "min_length": settings.PASSWORD_MIN_LENGTH,
            "expiry_days": settings.PASSWORD_EXPIRY_DAYS,
            "current_stats": {
                "min_expiry": result.min_expiry,
                "max_expiry": result.max_expiry,
                "avg_expiry": result.avg_expiry
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取密码策略失败: {str(e)}"
        )


# 密码策略相关模型
class PasswordPolicyUpdateRequest(BaseModel):
    min_length: Optional[int] = None
    expiry_days: Optional[int] = None
    require_uppercase: Optional[bool] = None
    require_lowercase: Optional[bool] = None
    require_numbers: Optional[bool] = None
    require_special_chars: Optional[bool] = None


class PasswordTestRequest(BaseModel):
    password: str


@router.put("/password-policy")
async def update_password_policy(
    request: PasswordPolicyUpdateRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    更新密码策略
    """
    try:
        # 获取当前配置
        current_policy = await get_password_policy(current_user, db)

        # 构建更新数据
        update_data = {
            "min_length": request.min_length or current_policy["min_length"],
            "expiry_days": request.expiry_days or current_policy["expiry_days"],
            "require_uppercase": request.require_uppercase if request.require_uppercase is not None else True,
            "require_lowercase": request.require_lowercase if request.require_lowercase is not None else True,
            "require_numbers": request.require_numbers if request.require_numbers is not None else True,
            "require_special_chars": request.require_special_chars if request.require_special_chars is not None else False
        }

        # 保存到数据库
        db.execute(
            """
            INSERT INTO admin_config (config_key, config_value, description, created_by)
            VALUES ('password_policy', :config_value, '密码策略配置', :created_by)
            ON CONFLICT (config_key)
            DO UPDATE SET config_value = :config_value, updated_at = CURRENT_TIMESTAMP
            """,
            {
                "config_value": update_data,
                "created_by": current_user["username"]
            }
        )

        db.commit()

        return {
            "success": True,
            "message": "密码策略更新成功",
            "policy": update_data
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新密码策略失败: {str(e)}"
        )


@router.post("/password-policy/test-complexity")
async def test_password_complexity(
    request: PasswordTestRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin)
):
    """
    测试密码复杂度
    """
    try:
        password = request.password
        complexity_score = 0
        feedback = []

        # 长度检查
        if len(password) >= 8:
            complexity_score += 1
        else:
            feedback.append("密码长度至少8位")

        # 大写字母检查
        if any(c.isupper() for c in password):
            complexity_score += 1
        else:
            feedback.append("密码应包含大写字母")

        # 小写字母检查
        if any(c.islower() for c in password):
            complexity_score += 1
        else:
            feedback.append("密码应包含小写字母")

        # 数字检查
        if any(c.isdigit() for c in password):
            complexity_score += 1
        else:
            feedback.append("密码应包含数字")

        # 特殊字符检查
        if any(not c.isalnum() for c in password):
            complexity_score += 1
        else:
            feedback.append("密码应包含特殊字符")

        # 评估强度
        if complexity_score >= 4:
            strength = "强"
        elif complexity_score >= 3:
            strength = "中"
        else:
            strength = "弱"

        return {
            "score": complexity_score,
            "strength": strength,
            "feedback": feedback,
            "length": len(password)
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"测试密码复杂度失败: {str(e)}"
        )


@router.get("/password-policy/report")
async def generate_policy_report(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    生成密码策略报告
    """
    try:
        # 获取用户密码统计
        user_stats = db.execute(
            """
            SELECT
                COUNT(*) as total_users,
                COUNT(CASE WHEN last_password_change IS NULL THEN 1 END) as never_changed,
                COUNT(CASE WHEN last_password_change < NOW() - INTERVAL '90 days' THEN 1 END) as expired,
                COUNT(CASE WHEN is_locked = true THEN 1 END) as locked
            FROM users
            """
        ).fetchone()

        # 获取密码策略配置
        policy_config = db.execute(
            """
            SELECT config_value
            FROM admin_config
            WHERE config_key = 'password_policy'
            """
        ).fetchone()

        policy_data = policy_config.config_value if policy_config else {}

        return {
            "user_statistics": {
                "total_users": user_stats.total_users,
                "never_changed_password": user_stats.never_changed,
                "expired_passwords": user_stats.expired,
                "locked_users": user_stats.locked
            },
            "policy_configuration": policy_data,
            "report_generated_at": datetime.now().isoformat(),
            "generated_by": current_user["username"]
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"生成密码策略报告失败: {str(e)}"
        )


@router.post("/password-policy/reset-defaults")
async def reset_password_policy_defaults(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    重置密码策略为默认值
    """
    try:
        default_policy = {
            "min_length": 8,
            "expiry_days": 90,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special_chars": False
        }

        # 保存默认配置
        db.execute(
            """
            INSERT INTO admin_config (config_key, config_value, description, created_by)
            VALUES ('password_policy', :config_value, '密码策略配置', :created_by)
            ON CONFLICT (config_key)
            DO UPDATE SET config_value = :config_value, updated_at = CURRENT_TIMESTAMP
            """,
            {
                "config_value": default_policy,
                "created_by": current_user["username"]
            }
        )

        db.commit()

        return {
            "success": True,
            "message": "密码策略已重置为默认值",
            "default_policy": default_policy
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"重置密码策略失败: {str(e)}"
        )


@router.get("/dashboard/stats")
async def get_security_dashboard_stats(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取安全概览统计
    """
    try:
        # 登录失败统计
        failed_login_stats = db.execute(
            """
            SELECT
                COUNT(*) as total_failed,
                COUNT(CASE WHEN timestamp > NOW() - INTERVAL '24 hours' THEN 1 END) as last_24h,
                COUNT(CASE WHEN timestamp > NOW() - INTERVAL '7 days' THEN 1 END) as last_7d
            FROM login_attempt
            WHERE success = false
            """
        ).fetchone()

        # 用户锁定统计
        locked_users_stats = db.execute(
            """
            SELECT
                COUNT(*) as total_locked,
                COUNT(CASE WHEN is_locked = true THEN 1 END) as currently_locked
            FROM user_lock_status
            """
        ).fetchone()

        # IP白名单统计
        ip_whitelist_stats = db.execute(
            """
            SELECT COUNT(*) as total_ips
            FROM user_ip_whitelist
            WHERE is_active = true
            """
        ).fetchone()

        return {
            "failed_logins": {
                "total": failed_login_stats.total_failed,
                "last_24h": failed_login_stats.last_24h,
                "last_7d": failed_login_stats.last_7d
            },
            "locked_users": {
                "total": locked_users_stats.total_locked,
                "currently_locked": locked_users_stats.currently_locked
            },
            "ip_whitelist": {
                "total_ips": ip_whitelist_stats.total_ips
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取安全统计失败: {str(e)}"
        )


@router.get("/security-events")
async def get_recent_security_events(
    limit: int = 10,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取最近安全事件
    """
    try:
        # 获取最近的安全事件
        events_result = db.execute(
            """
            SELECT
                event_type,
                description,
                ip_address,
                user_id,
                username,
                timestamp,
                severity
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT :limit
            """,
            {"limit": limit}
        ).fetchall()

        events = [
            {
                "event_type": row.event_type,
                "description": row.description,
                "ip_address": row.ip_address,
                "user_id": row.user_id,
                "username": row.username,
                "timestamp": row.timestamp,
                "severity": row.severity
            }
            for row in events_result
        ]

        return {
            "events": events,
            "total": len(events)
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取安全事件失败: {str(e)}"
        )


# 会话管理相关模型
class SessionResponse(BaseModel):
    session_id: str
    user_id: str
    username: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    is_active: bool


class SessionListResponse(BaseModel):
    sessions: List[SessionResponse]
    total: int


class BatchTerminateRequest(BaseModel):
    session_ids: List[str]


@router.get("/sessions/stats")
async def get_session_stats(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取会话统计
    """
    try:
        # 获取活跃会话统计
        active_sessions_stats = db.execute(
            """
            SELECT
                COUNT(*) as total_sessions,
                COUNT(CASE WHEN last_activity > NOW() - INTERVAL '30 minutes' THEN 1 END) as active_last_30min,
                COUNT(CASE WHEN last_activity > NOW() - INTERVAL '1 hour' THEN 1 END) as active_last_hour,
                COUNT(DISTINCT user_id) as unique_users
            FROM user_sessions
            WHERE is_active = true
            """
        ).fetchone()

        return {
            "total_sessions": active_sessions_stats.total_sessions,
            "active_last_30min": active_sessions_stats.active_last_30min,
            "active_last_hour": active_sessions_stats.active_last_hour,
            "unique_users": active_sessions_stats.unique_users
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取会话统计失败: {str(e)}"
        )


@router.get("/sessions/active", response_model=SessionListResponse)
async def get_active_sessions(
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    获取活跃会话列表
    """
    try:
        # 获取活跃会话
        sessions_result = db.execute(
            """
            SELECT
                session_id,
                user_id,
                username,
                ip_address,
                user_agent,
                created_at,
                last_activity,
                is_active
            FROM user_sessions
            WHERE is_active = true
            ORDER BY last_activity DESC
            """
        ).fetchall()

        sessions = [
            SessionResponse(
                session_id=row.session_id,
                user_id=row.user_id,
                username=row.username,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                created_at=row.created_at,
                last_activity=row.last_activity,
                is_active=row.is_active
            )
            for row in sessions_result
        ]

        return SessionListResponse(sessions=sessions, total=len(sessions))

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取活跃会话列表失败: {str(e)}"
        )


@router.delete("/sessions/{session_id}")
async def terminate_session(
    session_id: str,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    强制结束会话
    """
    try:
        # 检查会话是否存在
        existing = db.execute(
            """
            SELECT session_id FROM user_sessions
            WHERE session_id = :session_id AND is_active = true
            """,
            {"session_id": session_id}
        ).fetchone()

        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="会话不存在或已结束"
            )

        # 结束会话
        result = db.execute(
            """
            UPDATE user_sessions
            SET is_active = false, terminated_at = CURRENT_TIMESTAMP, terminated_by = :terminated_by
            WHERE session_id = :session_id
            RETURNING session_id
            """,
            {
                "session_id": session_id,
                "terminated_by": current_user["username"]
            }
        ).fetchone()

        db.commit()

        return {"success": True, "message": "会话已强制结束"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"结束会话失败: {str(e)}"
        )


@router.post("/sessions/batch-terminate")
async def batch_terminate_sessions(
    request: BatchTerminateRequest,
    current_user: dict = Depends(AuthManager.get_current_auth_admin),
    db: Session = Depends(get_db)
):
    """
    批量结束会话
    """
    try:
        if not request.session_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="会话ID列表不能为空"
            )

        # 批量结束会话
        result = db.execute(
            """
            UPDATE user_sessions
            SET is_active = false, terminated_at = CURRENT_TIMESTAMP, terminated_by = :terminated_by
            WHERE session_id = ANY(:session_ids) AND is_active = true
            RETURNING session_id
            """,
            {
                "session_ids": request.session_ids,
                "terminated_by": current_user["username"]
            }
        ).fetchall()

        db.commit()

        return {
            "success": True,
            "message": f"成功结束{len(result)}个会话",
            "terminated_count": len(result)
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"批量结束会话失败: {str(e)}"
        )