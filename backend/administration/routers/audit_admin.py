from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta

from utils.database import get_db
from utils.auth import AuthManager

router = APIRouter(prefix="/api/audit-admin", tags=["审计管理员"])


# 审计日志相关模型
class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    user_name: str
    user_role: str
    action: str
    resource: str
    details: str
    ip_address: str


class AuditLogListResponse(BaseModel):
    logs: List[AuditLogResponse]
    total: int
    page: int
    size: int


class AuditStatsResponse(BaseModel):
    total_actions: int
    actions_by_role: dict
    actions_by_type: dict
    recent_activity: List[dict]


@router.get("/logs", response_model=AuditLogListResponse)
async def get_audit_logs(
    page: int = 1,
    size: int = 20,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user_role: Optional[str] = None,
    action_type: Optional[str] = None,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取审计日志
    """
    try:
        # 构建查询条件
        where_conditions = []
        params = {}

        # 日期范围过滤
        if start_date:
            where_conditions.append("timestamp >= :start_date")
            params["start_date"] = start_date

        if end_date:
            where_conditions.append("timestamp <= :end_date")
            params["end_date"] = end_date

        # 用户角色过滤
        if user_role:
            where_conditions.append("user_role = :user_role")
            params["user_role"] = user_role

        # 操作类型过滤
        if action_type:
            where_conditions.append("verb = :action_type")
            params["action_type"] = action_type

        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

        # 获取总数
        total_result = db.execute(
            f"""
            SELECT COUNT(*) as total
            FROM audit_log
            WHERE {where_clause}
            """,
            params
        ).fetchone()

        total = total_result.total if total_result else 0

        # 计算分页
        offset = (page - 1) * size

        # 获取日志数据
        logs_result = db.execute(
            f"""
            SELECT
                id, timestamp, user_name, user_role,
                verb as action, request_uri as resource,
                request_object as details, source_ip as ip_address
            FROM audit_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
            """,
            {**params, "limit": size, "offset": offset}
        ).fetchall()

        logs = [
            AuditLogResponse(
                id=row.id,
                timestamp=row.timestamp,
                user_name=row.user_name,
                user_role=row.user_role,
                action=row.action,
                resource=row.resource,
                details=row.details or "",
                ip_address=row.ip_address
            )
            for row in logs_result
        ]

        return AuditLogListResponse(
            logs=logs,
            total=total,
            page=page,
            size=size
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取审计日志失败: {str(e)}"
        )


@router.get("/stats", response_model=AuditStatsResponse)
async def get_audit_stats(
    days: int = 30,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取审计统计
    """
    try:
        # 总操作数
        total_result = db.execute(
            """
            SELECT COUNT(*) as total
            FROM audit_log
            WHERE timestamp >= :start_date
            """,
            {"start_date": datetime.now() - timedelta(days=days)}
        ).fetchone()

        # 按角色统计
        role_stats_result = db.execute(
            """
            SELECT user_role, COUNT(*) as count
            FROM audit_log
            WHERE timestamp >= :start_date
            GROUP BY user_role
            """,
            {"start_date": datetime.now() - timedelta(days=days)}
        ).fetchall()

        actions_by_role = {row.user_role: row.count for row in role_stats_result}

        # 按操作类型统计
        type_stats_result = db.execute(
            """
            SELECT verb as action_type, COUNT(*) as count
            FROM audit_log
            WHERE timestamp >= :start_date
            GROUP BY verb
            """,
            {"start_date": datetime.now() - timedelta(days=days)}
        ).fetchall()

        actions_by_type = {row.action_type: row.count for row in type_stats_result}

        # 最近活动趋势
        recent_activity_result = db.execute(
            """
            SELECT
                DATE(timestamp) as date,
                COUNT(*) as count
            FROM audit_log
            WHERE timestamp >= :start_date
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
            LIMIT 14
            """,
            {"start_date": datetime.now() - timedelta(days=14)}
        ).fetchall()

        recent_activity = [
            {"date": row.date.strftime("%Y-%m-%d"), "count": row.count}
            for row in recent_activity_result
        ]

        return AuditStatsResponse(
            total_actions=total_result.total if total_result else 0,
            actions_by_role=actions_by_role,
            actions_by_type=actions_by_type,
            recent_activity=recent_activity
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取审计统计失败: {str(e)}"
        )


@router.get("/admin-actions")
async def get_admin_actions(
    page: int = 1,
    size: int = 20,
    admin_role: Optional[str] = None,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取管理员操作记录
    """
    try:
        # 构建查询条件
        where_conditions = ["user_role IN ('sys_admin', 'auth_admin', 'audit_admin')"]
        params = {}

        if admin_role:
            where_conditions.append("user_role = :admin_role")
            params["admin_role"] = admin_role

        where_clause = " AND ".join(where_conditions)

        # 获取总数
        total_result = db.execute(
            f"""
            SELECT COUNT(*) as total
            FROM audit_log
            WHERE {where_clause}
            """,
            params
        ).fetchone()

        total = total_result.total if total_result else 0

        # 计算分页
        offset = (page - 1) * size

        # 获取管理员操作数据
        actions_result = db.execute(
            f"""
            SELECT
                id, timestamp, user_name, user_role,
                verb as action, request_uri as resource,
                request_object as details, source_ip as ip_address
            FROM audit_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
            """,
            {**params, "limit": size, "offset": offset}
        ).fetchall()

        actions = [
            {
                "id": row.id,
                "timestamp": row.timestamp,
                "user_name": row.user_name,
                "user_role": row.user_role,
                "action": row.action,
                "resource": row.resource,
                "details": row.details or "",
                "ip_address": row.ip_address
            }
            for row in actions_result
        ]

        return {
            "actions": actions,
            "total": total,
            "page": page,
            "size": size
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取管理员操作记录失败: {str(e)}"
        )


@router.get("/dashboard/stats")
async def get_audit_dashboard_stats(
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取审计概览统计
    """
    try:
        # 今日统计
        today_stats = db.execute(
            """
            SELECT
                COUNT(*) as total_today,
                COUNT(CASE WHEN user_role = 'sys_admin' THEN 1 END) as sys_admin_today,
                COUNT(CASE WHEN user_role = 'auth_admin' THEN 1 END) as auth_admin_today,
                COUNT(CASE WHEN user_role = 'audit_admin' THEN 1 END) as audit_admin_today
            FROM audit_log
            WHERE DATE(timestamp) = CURRENT_DATE
            """
        ).fetchone()

        # 本周统计
        week_stats = db.execute(
            """
            SELECT
                COUNT(*) as total_week,
                COUNT(CASE WHEN user_role = 'sys_admin' THEN 1 END) as sys_admin_week,
                COUNT(CASE WHEN user_role = 'auth_admin' THEN 1 END) as auth_admin_week,
                COUNT(CASE WHEN user_role = 'audit_admin' THEN 1 END) as audit_admin_week
            FROM audit_log
            WHERE timestamp >= DATE_TRUNC('week', CURRENT_DATE)
            """
        ).fetchone()

        # 操作类型统计
        action_types = db.execute(
            """
            SELECT verb as action_type, COUNT(*) as count
            FROM audit_log
            WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
            GROUP BY verb
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall()

        # 活跃管理员
        active_admins = db.execute(
            """
            SELECT user_name, user_role, COUNT(*) as action_count
            FROM audit_log
            WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
            GROUP BY user_name, user_role
            ORDER BY action_count DESC
            LIMIT 5
            """
        ).fetchall()

        return {
            "today": {
                "total": today_stats.total_today,
                "sys_admin": today_stats.sys_admin_today,
                "auth_admin": today_stats.auth_admin_today,
                "audit_admin": today_stats.audit_admin_today
            },
            "week": {
                "total": week_stats.total_week,
                "sys_admin": week_stats.sys_admin_week,
                "auth_admin": week_stats.auth_admin_week,
                "audit_admin": week_stats.audit_admin_week
            },
            "top_actions": [
                {"action_type": row.action_type, "count": row.count}
                for row in action_types
            ],
            "active_admins": [
                {
                    "user_name": row.user_name,
                    "user_role": row.user_role,
                    "action_count": row.action_count
                }
                for row in active_admins
            ]
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取审计概览统计失败: {str(e)}"
        )


# 审计日志详情相关模型
class AuditLogDetailResponse(BaseModel):
    id: int
    timestamp: datetime
    user_name: str
    user_role: str
    action: str
    resource: str
    details: str
    ip_address: str
    user_agent: Optional[str] = None
    response_status: Optional[int] = None
    response_time: Optional[float] = None
    request_headers: Optional[dict] = None
    request_body: Optional[dict] = None
    response_body: Optional[dict] = None


class AuditLogSearchRequest(BaseModel):
    keyword: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    user_name: Optional[str] = None
    user_role: Optional[str] = None
    action_type: Optional[str] = None
    ip_address: Optional[str] = None
    page: int = 1
    size: int = 20


class AuditLogExportRequest(BaseModel):
    format: str = "csv"  # csv, json, excel
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    user_role: Optional[str] = None
    action_type: Optional[str] = None


class BatchDeleteRequest(BaseModel):
    log_ids: List[int]


@router.get("/logs/{log_id}", response_model=AuditLogDetailResponse)
async def get_audit_log_detail(
    log_id: int,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取审计日志详情
    """
    try:
        # 获取日志详情
        log_result = db.execute(
            """
            SELECT
                id, timestamp, user_name, user_role,
                verb as action, request_uri as resource,
                request_object as details, source_ip as ip_address,
                user_agent, response_status, response_time,
                request_headers, request_body, response_body
            FROM audit_log
            WHERE id = :log_id
            """,
            {"log_id": log_id}
        ).fetchone()

        if not log_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="审计日志不存在"
            )

        return AuditLogDetailResponse(
            id=log_result.id,
            timestamp=log_result.timestamp,
            user_name=log_result.user_name,
            user_role=log_result.user_role,
            action=log_result.action,
            resource=log_result.resource,
            details=log_result.details or "",
            ip_address=log_result.ip_address,
            user_agent=log_result.user_agent,
            response_status=log_result.response_status,
            response_time=log_result.response_time,
            request_headers=log_result.request_headers,
            request_body=log_result.request_body,
            response_body=log_result.response_body
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取审计日志详情失败: {str(e)}"
        )


@router.post("/logs/search", response_model=AuditLogListResponse)
async def search_audit_logs(
    request: AuditLogSearchRequest,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    搜索审计日志
    """
    try:
        # 构建查询条件
        where_conditions = []
        params = {}

        # 关键词搜索
        if request.keyword:
            where_conditions.append("""
                (user_name ILIKE :keyword OR
                 verb ILIKE :keyword OR
                 request_uri ILIKE :keyword OR
                 request_object::text ILIKE :keyword)
            """)
            params["keyword"] = f"%{request.keyword}%"

        # 日期范围过滤
        if request.start_date:
            where_conditions.append("timestamp >= :start_date")
            params["start_date"] = request.start_date

        if request.end_date:
            where_conditions.append("timestamp <= :end_date")
            params["end_date"] = request.end_date

        # 用户名称过滤
        if request.user_name:
            where_conditions.append("user_name ILIKE :user_name")
            params["user_name"] = f"%{request.user_name}%"

        # 用户角色过滤
        if request.user_role:
            where_conditions.append("user_role = :user_role")
            params["user_role"] = request.user_role

        # 操作类型过滤
        if request.action_type:
            where_conditions.append("verb = :action_type")
            params["action_type"] = request.action_type

        # IP地址过滤
        if request.ip_address:
            where_conditions.append("source_ip ILIKE :ip_address")
            params["ip_address"] = f"%{request.ip_address}%"

        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

        # 获取总数
        total_result = db.execute(
            f"""
            SELECT COUNT(*) as total
            FROM audit_log
            WHERE {where_clause}
            """,
            params
        ).fetchone()

        total = total_result.total if total_result else 0

        # 计算分页
        offset = (request.page - 1) * request.size

        # 获取日志数据
        logs_result = db.execute(
            f"""
            SELECT
                id, timestamp, user_name, user_role,
                verb as action, request_uri as resource,
                request_object as details, source_ip as ip_address
            FROM audit_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
            """,
            {**params, "limit": request.size, "offset": offset}
        ).fetchall()

        logs = [
            AuditLogResponse(
                id=row.id,
                timestamp=row.timestamp,
                user_name=row.user_name,
                user_role=row.user_role,
                action=row.action,
                resource=row.resource,
                details=row.details or "",
                ip_address=row.ip_address
            )
            for row in logs_result
        ]

        return AuditLogListResponse(
            logs=logs,
            total=total,
            page=request.page,
            size=request.size
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"搜索审计日志失败: {str(e)}"
        )


@router.post("/logs/export")
async def export_audit_logs(
    request: AuditLogExportRequest,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    导出审计日志
    """
    try:
        # 构建查询条件
        where_conditions = []
        params = {}

        # 日期范围过滤
        if request.start_date:
            where_conditions.append("timestamp >= :start_date")
            params["start_date"] = request.start_date

        if request.end_date:
            where_conditions.append("timestamp <= :end_date")
            params["end_date"] = request.end_date

        # 用户角色过滤
        if request.user_role:
            where_conditions.append("user_role = :user_role")
            params["user_role"] = request.user_role

        # 操作类型过滤
        if request.action_type:
            where_conditions.append("verb = :action_type")
            params["action_type"] = request.action_type

        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

        # 获取日志数据
        logs_result = db.execute(
            f"""
            SELECT
                id, timestamp, user_name, user_role,
                verb as action, request_uri as resource,
                request_object as details, source_ip as ip_address,
                user_agent, response_status, response_time
            FROM audit_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            """,
            params
        ).fetchall()

        # 根据格式生成导出数据
        if request.format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.writer(output)

            # 写入表头
            writer.writerow(["ID", "时间戳", "用户名", "用户角色", "操作", "资源", "详情", "IP地址", "用户代理", "响应状态", "响应时间"])

            # 写入数据
            for row in logs_result:
                writer.writerow([
                    row.id,
                    row.timestamp.isoformat(),
                    row.user_name,
                    row.user_role,
                    row.action,
                    row.resource,
                    row.details or "",
                    row.ip_address,
                    row.user_agent or "",
                    row.response_status or "",
                    row.response_time or ""
                ])

            content = output.getvalue()
            output.close()

            return {
                "filename": f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "content": content,
                "content_type": "text/csv"
            }

        elif request.format == "json":
            logs_data = [
                {
                    "id": row.id,
                    "timestamp": row.timestamp.isoformat(),
                    "user_name": row.user_name,
                    "user_role": row.user_role,
                    "action": row.action,
                    "resource": row.resource,
                    "details": row.details or "",
                    "ip_address": row.ip_address,
                    "user_agent": row.user_agent,
                    "response_status": row.response_status,
                    "response_time": row.response_time
                }
                for row in logs_result
            ]

            import json
            return {
                "filename": f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "content": json.dumps(logs_data, ensure_ascii=False, indent=2),
                "content_type": "application/json"
            }

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="不支持的导出格式"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"导出审计日志失败: {str(e)}"
        )


@router.post("/logs/batch-delete")
async def batch_delete_audit_logs(
    request: BatchDeleteRequest,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    批量删除审计日志
    """
    try:
        if not request.log_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="日志ID列表不能为空"
            )

        # 批量删除日志
        result = db.execute(
            """
            DELETE FROM audit_log
            WHERE id = ANY(:log_ids)
            RETURNING id
            """,
            {"log_ids": request.log_ids}
        ).fetchall()

        db.commit()

        return {
            "success": True,
            "message": f"成功删除{len(result)}条审计日志",
            "deleted_count": len(result)
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"批量删除审计日志失败: {str(e)}"
        )


@router.post("/logs/cleanup")
async def cleanup_expired_logs(
    retention_days: int = 90,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    清理过期审计日志
    """
    try:
        # 删除超过保留期限的日志
        result = db.execute(
            """
            DELETE FROM audit_log
            WHERE timestamp < CURRENT_DATE - INTERVAL ':days days'
            RETURNING id
            """,
            {"days": retention_days}
        ).fetchall()

        db.commit()

        return {
            "success": True,
            "message": f"成功清理{len(result)}条过期审计日志",
            "cleaned_count": len(result)
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"清理过期审计日志失败: {str(e)}"
        )


# 统计分析相关模型
class OperationTypeStatsResponse(BaseModel):
    operation_types: List[dict]
    total_operations: int


class UserActivityStatsResponse(BaseModel):
    user_activity: List[dict]
    total_users: int


class TimeTrendStatsResponse(BaseModel):
    time_trend: List[dict]
    period: str


class RiskEventStatsResponse(BaseModel):
    risk_events: List[dict]
    total_risks: int


class AuditReportRequest(BaseModel):
    report_type: str  # daily, weekly, monthly, custom
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    include_charts: bool = True


@router.get("/statistics/operation-types", response_model=OperationTypeStatsResponse)
async def get_operation_type_stats(
    days: int = 30,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取操作类型统计
    """
    try:
        # 获取操作类型统计
        stats_result = db.execute(
            """
            SELECT
                verb as operation_type,
                COUNT(*) as count,
                COUNT(DISTINCT user_name) as unique_users
            FROM audit_log
            WHERE timestamp >= :start_date
            GROUP BY verb
            ORDER BY count DESC
            """,
            {"start_date": datetime.now() - timedelta(days=days)}
        ).fetchall()

        operation_types = [
            {
                "operation_type": row.operation_type,
                "count": row.count,
                "unique_users": row.unique_users
            }
            for row in stats_result
        ]

        total_operations = sum(row.count for row in stats_result)

        return OperationTypeStatsResponse(
            operation_types=operation_types,
            total_operations=total_operations
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取操作类型统计失败: {str(e)}"
        )


@router.get("/statistics/user-activity", response_model=UserActivityStatsResponse)
async def get_user_activity_stats(
    days: int = 30,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取用户活动统计
    """
    try:
        # 获取用户活动统计
        stats_result = db.execute(
            """
            SELECT
                user_name,
                user_role,
                COUNT(*) as action_count,
                MIN(timestamp) as first_action,
                MAX(timestamp) as last_action
            FROM audit_log
            WHERE timestamp >= :start_date
            GROUP BY user_name, user_role
            ORDER BY action_count DESC
            """,
            {"start_date": datetime.now() - timedelta(days=days)}
        ).fetchall()

        user_activity = [
            {
                "user_name": row.user_name,
                "user_role": row.user_role,
                "action_count": row.action_count,
                "first_action": row.first_action.isoformat(),
                "last_action": row.last_action.isoformat()
            }
            for row in stats_result
        ]

        total_users = len(user_activity)

        return UserActivityStatsResponse(
            user_activity=user_activity,
            total_users=total_users
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取用户活动统计失败: {str(e)}"
        )


@router.get("/statistics/time-trend", response_model=TimeTrendStatsResponse)
async def get_time_trend_stats(
    period: str = "daily",  # daily, weekly, monthly
    days: int = 30,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取时间趋势统计
    """
    try:
        # 根据时间段确定分组
        if period == "daily":
            group_by = "DATE(timestamp)"
            date_format = "%Y-%m-%d"
        elif period == "weekly":
            group_by = "DATE_TRUNC('week', timestamp)"
            date_format = "%Y-W%U"
        elif period == "monthly":
            group_by = "DATE_TRUNC('month', timestamp)"
            date_format = "%Y-%m"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="不支持的统计周期"
            )

        # 获取时间趋势统计
        stats_result = db.execute(
            f"""
            SELECT
                {group_by} as period,
                COUNT(*) as action_count,
                COUNT(DISTINCT user_name) as unique_users
            FROM audit_log
            WHERE timestamp >= :start_date
            GROUP BY {group_by}
            ORDER BY period
            """,
            {"start_date": datetime.now() - timedelta(days=days)}
        ).fetchall()

        time_trend = [
            {
                "period": row.period.strftime(date_format),
                "action_count": row.action_count,
                "unique_users": row.unique_users
            }
            for row in stats_result
        ]

        return TimeTrendStatsResponse(
            time_trend=time_trend,
            period=period
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取时间趋势统计失败: {str(e)}"
        )


@router.get("/statistics/risk-events", response_model=RiskEventStatsResponse)
async def get_risk_event_stats(
    days: int = 30,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    获取风险事件统计
    """
    try:
        # 定义风险操作类型
        risk_actions = ["DELETE", "UPDATE", "CREATE", "LOGIN_FAILED", "ACCESS_DENIED"]

        # 获取风险事件统计
        stats_result = db.execute(
            """
            SELECT
                verb as action_type,
                COUNT(*) as count,
                COUNT(DISTINCT user_name) as unique_users
            FROM audit_log
            WHERE timestamp >= :start_date
            AND verb = ANY(:risk_actions)
            GROUP BY verb
            ORDER BY count DESC
            """,
            {
                "start_date": datetime.now() - timedelta(days=days),
                "risk_actions": risk_actions
            }
        ).fetchall()

        risk_events = [
            {
                "action_type": row.action_type,
                "count": row.count,
                "unique_users": row.unique_users,
                "risk_level": "high" if row.action_type in ["DELETE", "ACCESS_DENIED"] else "medium"
            }
            for row in stats_result
        ]

        total_risks = sum(row.count for row in stats_result)

        return RiskEventStatsResponse(
            risk_events=risk_events,
            total_risks=total_risks
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取风险事件统计失败: {str(e)}"
        )


@router.post("/statistics/generate-report")
async def generate_audit_report(
    request: AuditReportRequest,
    current_user: dict = Depends(AuthManager.get_current_audit_admin),
    db: Session = Depends(get_db)
):
    """
    生成审计报告
    """
    try:
        # 确定报告日期范围
        if request.report_type == "daily":
            start_date = datetime.now() - timedelta(days=1)
            end_date = datetime.now()
        elif request.report_type == "weekly":
            start_date = datetime.now() - timedelta(days=7)
            end_date = datetime.now()
        elif request.report_type == "monthly":
            start_date = datetime.now() - timedelta(days=30)
            end_date = datetime.now()
        elif request.report_type == "custom":
            if not request.start_date or not request.end_date:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="自定义报告需要指定开始和结束日期"
                )
            start_date = datetime.fromisoformat(request.start_date)
            end_date = datetime.fromisoformat(request.end_date)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="不支持的报告类型"
            )

        # 获取报告数据
        total_actions = db.execute(
            """
            SELECT COUNT(*) as total
            FROM audit_log
            WHERE timestamp BETWEEN :start_date AND :end_date
            """,
            {"start_date": start_date, "end_date": end_date}
        ).fetchone()

        user_stats = db.execute(
            """
            SELECT
                COUNT(DISTINCT user_name) as unique_users,
                COUNT(DISTINCT user_role) as unique_roles
            FROM audit_log
            WHERE timestamp BETWEEN :start_date AND :end_date
            """,
            {"start_date": start_date, "end_date": end_date}
        ).fetchone()

        top_operations = db.execute(
            """
            SELECT verb as operation_type, COUNT(*) as count
            FROM audit_log
            WHERE timestamp BETWEEN :start_date AND :end_date
            GROUP BY verb
            ORDER BY count DESC
            LIMIT 10
            """,
            {"start_date": start_date, "end_date": end_date}
        ).fetchall()

        risk_events = db.execute(
            """
            SELECT COUNT(*) as risk_count
            FROM audit_log
            WHERE timestamp BETWEEN :start_date AND :end_date
            AND verb IN ('DELETE', 'UPDATE', 'CREATE', 'LOGIN_FAILED', 'ACCESS_DENIED')
            """,
            {"start_date": start_date, "end_date": end_date}
        ).fetchone()

        # 构建报告
        report = {
            "report_type": request.report_type,
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            "summary": {
                "total_actions": total_actions.total if total_actions else 0,
                "unique_users": user_stats.unique_users if user_stats else 0,
                "unique_roles": user_stats.unique_roles if user_stats else 0,
                "risk_events": risk_events.risk_count if risk_events else 0
            },
            "top_operations": [
                {
                    "operation_type": row.operation_type,
                    "count": row.count
                }
                for row in top_operations
            ],
            "generated_at": datetime.now().isoformat(),
            "generated_by": current_user["username"]
        }

        # 如果包含图表数据，添加趋势数据
        if request.include_charts:
            daily_trend = db.execute(
                """
                SELECT
                    DATE(timestamp) as date,
                    COUNT(*) as action_count
                FROM audit_log
                WHERE timestamp BETWEEN :start_date AND :end_date
                GROUP BY DATE(timestamp)
                ORDER BY date
                """,
                {"start_date": start_date, "end_date": end_date}
            ).fetchall()

            report["trend_data"] = [
                {
                    "date": row.date.strftime("%Y-%m-%d"),
                    "action_count": row.action_count
                }
                for row in daily_trend
            ]

        return report

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"生成审计报告失败: {str(e)}"
        )