from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import uuid

from utils.database import get_db
from utils.auth import AuthManager
from models.admin_users import AdminUser
from utils.openwebui_client import openwebui_client
from config import settings

router = APIRouter(prefix="/api/sys-admin", tags=["系统管理员"])


# API Key管理相关模型
class ApiKeyCreateRequest(BaseModel):
    name: str
    expires_in_days: Optional[int] = 30


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    api_key: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool


class ApiKeyListResponse(BaseModel):
    api_keys: List[ApiKeyResponse]
    total: int


class ValidateApiKeyResponse(BaseModel):
    valid: bool
    name: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None


# Open WebUI代理相关模型
class OpenWebUIUser(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: str


class OpenWebUIUsersResponse(BaseModel):
    users: List[OpenWebUIUser]
    total: int


# 代理请求相关模型
class ProxyRequest(BaseModel):
    api_key: str
    method: str
    path: str
    data: Optional[dict] = None
    params: Optional[dict] = None


@router.get("/api-keys", response_model=ApiKeyListResponse)
async def get_api_keys(
    current_user: dict = Depends(AuthManager.get_current_sys_admin),
    db: Session = Depends(get_db)
):
    """
    获取API Key列表
    """
    try:
        result = db.execute(
            """
            SELECT id, name, api_key, created_by, created_at, expires_at, is_active
            FROM admin_api_keys
            ORDER BY created_at DESC
            """
        ).fetchall()

        api_keys = [
            ApiKeyResponse(
                id=row.id,
                name=row.name,
                api_key=row.api_key[:8] + "****" + row.api_key[-4:],  # 部分隐藏
                created_by=row.created_by,
                created_at=row.created_at,
                expires_at=row.expires_at,
                is_active=row.is_active
            )
            for row in result
        ]

        return ApiKeyListResponse(api_keys=api_keys, total=len(api_keys))

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取API Key列表失败: {str(e)}"
        )


@router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    request: ApiKeyCreateRequest,
    current_user: dict = Depends(AuthManager.get_current_sys_admin),
    db: Session = Depends(get_db)
):
    """
    创建API Key
    """
    try:
        # 生成API Key
        api_key = f"sk_{uuid.uuid4().hex}"

        # 计算过期时间
        expires_at = None
        if request.expires_in_days:
            expires_at = datetime.now() + timedelta(days=request.expires_in_days)

        # 插入数据库
        result = db.execute(
            """
            INSERT INTO admin_api_keys (name, api_key, created_by, expires_at)
            VALUES (:name, :api_key, :created_by, :expires_at)
            RETURNING id, name, api_key, created_by, created_at, expires_at, is_active
            """,
            {
                "name": request.name,
                "api_key": api_key,
                "created_by": current_user["username"],
                "expires_at": expires_at
            }
        ).fetchone()

        db.commit()

        return ApiKeyResponse(
            id=result.id,
            name=result.name,
            api_key=result.api_key,  # 返回完整API Key（仅创建时）
            created_by=result.created_by,
            created_at=result.created_at,
            expires_at=result.expires_at,
            is_active=result.is_active
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"创建API Key失败: {str(e)}"
        )


@router.delete("/api-keys/{api_key_id}")
async def delete_api_key(
    api_key_id: int,
    current_user: dict = Depends(AuthManager.get_current_sys_admin),
    db: Session = Depends(get_db)
):
    """
    删除API Key
    """
    try:
        result = db.execute(
            """
            DELETE FROM admin_api_keys
            WHERE id = :id
            RETURNING id
            """,
            {"id": api_key_id}
        ).fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API Key不存在"
            )

        db.commit()

        return {"success": True, "message": "API Key删除成功"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"删除API Key失败: {str(e)}"
        )


@router.get("/validate-api-key/{api_key}", response_model=ValidateApiKeyResponse)
async def validate_api_key(
    api_key: str,
    current_user: dict = Depends(AuthManager.get_current_sys_admin),
    db: Session = Depends(get_db)
):
    """
    验证API Key有效性
    """
    try:
        result = db.execute(
            """
            SELECT name, expires_at, is_active
            FROM admin_api_keys
            WHERE api_key = :api_key
            """,
            {"api_key": api_key}
        ).fetchone()

        if not result:
            return ValidateApiKeyResponse(valid=False)

        # 检查是否过期
        is_expired = False
        if result.expires_at and result.expires_at < datetime.now():
            is_expired = True

        valid = result.is_active and not is_expired

        return ValidateApiKeyResponse(
            valid=valid,
            name=result.name,
            expires_at=result.expires_at,
            is_active=result.is_active
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"验证API Key失败: {str(e)}"
        )


@router.get("/open-webui/users", response_model=OpenWebUIUsersResponse)
async def get_openwebui_users(
    current_user: dict = Depends(AuthManager.get_current_sys_admin)
):
    """
    获取Open WebUI用户列表（代理）
    """
    try:
        # 使用OpenWebUI客户端获取用户列表
        users_data = await openwebui_client.get_users()

        # 转换响应格式
        users = []
        for user_data in users_data:
            users.append(OpenWebUIUser(
                id=str(user_data.get("id", "")),
                name=user_data.get("username", ""),
                email=user_data.get("email", ""),
                role=user_data.get("role", "user"),
                created_at=user_data.get("created_at", "")
            ))

        return OpenWebUIUsersResponse(users=users, total=len(users))

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取用户列表失败: {str(e)}"
        )


@router.get("/dashboard/stats")
async def get_dashboard_stats(
    current_user: dict = Depends(AuthManager.get_current_sys_admin),
    db: Session = Depends(get_db)
):
    """
    获取系统概览统计
    """
    try:
        # API Key统计
        api_key_stats = db.execute(
            """
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN is_active THEN 1 END) as active,
                COUNT(CASE WHEN NOT is_active OR (expires_at < NOW()) THEN 1 END) as expired
            FROM admin_api_keys
            """
        ).fetchone()

        # 用户统计
        user_stats = db.execute(
            """
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN admin_role = 'sys_admin' THEN 1 END) as sys_admins,
                COUNT(CASE WHEN admin_role = 'auth_admin' THEN 1 END) as auth_admins,
                COUNT(CASE WHEN admin_role = 'audit_admin' THEN 1 END) as audit_admins
            FROM users
            WHERE admin_role IS NOT NULL
            """
        ).fetchone()

        return {
            "api_keys": {
                "total": api_key_stats.total,
                "active": api_key_stats.active,
                "expired": api_key_stats.expired
            },
            "users": {
                "total": user_stats.total,
                "sys_admins": user_stats.sys_admins,
                "auth_admins": user_stats.auth_admins,
                "audit_admins": user_stats.audit_admins
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取统计信息失败: {str(e)}"
        )


# 通用代理端点
@router.post("/proxy")
async def proxy_request(
    request: ProxyRequest,
    current_user: dict = Depends(AuthManager.get_current_sys_admin)
):
    """
    通用代理请求到Open WebUI后端
    """
    try:
        # 验证API Key
        if not request.api_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="API Key不能为空"
            )

        # 准备请求头
        headers = {
            "Authorization": f"Bearer {request.api_key}",
            "Content-Type": "application/json"
        }

        # 构建请求URL
        url = f"{settings.OPENWEBUI_URL}{request.path}"

        # 根据方法发送请求
        if request.method.upper() == "GET":
            response = requests.get(url, headers=headers, params=request.params, timeout=30)
        elif request.method.upper() == "POST":
            response = requests.post(url, headers=headers, json=request.data, params=request.params, timeout=30)
        elif request.method.upper() == "PUT":
            response = requests.put(url, headers=headers, json=request.data, params=request.params, timeout=30)
        elif request.method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, params=request.params, timeout=30)
        elif request.method.upper() == "PATCH":
            response = requests.patch(url, headers=headers, json=request.data, params=request.params, timeout=30)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"不支持的HTTP方法: {request.method}"
            )

        # 返回响应
        if response.status_code >= 400:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Open WebUI API调用失败: {response.text}"
            )

        # 尝试解析JSON响应，如果不是JSON则返回原始文本
        try:
            return response.json()
        except:
            return {"data": response.text}

    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Open WebUI服务不可用: {str(e)}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"代理请求失败: {str(e)}"
        )