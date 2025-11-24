from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from utils.database import get_db
from utils.auth import LoginManager, AuthManager
from models.admin_users import AdminUser

router = APIRouter(prefix="/api/auth", tags=["认证"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    access_token: str = None
    token_type: str = None
    user: dict = None
    password_expiry: dict = None
    error: str = None
    message: str = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ChangePasswordResponse(BaseModel):
    success: bool
    message: str


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    用户登录
    """
    result = LoginManager.login_user(db, request.username, request.password)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )

    if not result["success"]:
        if result["error"] == "password_expired":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["message"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="登录失败"
            )

    return result


@router.post("/login-form")
async def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2兼容的登录接口
    """
    result = LoginManager.login_user(db, form_data.username, form_data.password)

    if not result or not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "access_token": result["access_token"],
        "token_type": "bearer"
    }


@router.get("/check-password-expiry")
async def check_password_expiry(
    current_user: dict = Depends(AuthManager.get_current_user),
    db: Session = Depends(get_db)
):
    """
    检查密码是否过期
    """
    result = AdminUser.check_password_expiry(db, current_user["username"])
    return result


@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(AuthManager.get_current_user),
    db: Session = Depends(get_db)
):
    """
    修改密码
    """
    success = AdminUser.change_password(
        db,
        current_user["username"],
        request.current_password,
        request.new_password
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="密码修改失败，请检查当前密码是否正确"
        )

    return ChangePasswordResponse(
        success=True,
        message="密码修改成功"
    )


@router.post("/logout")
async def logout(
    current_user: dict = Depends(AuthManager.get_current_user)
):
    """
    用户登出
    """
    # 在实际应用中，这里可以处理token黑名单等
    return {"success": True, "message": "登出成功"}


@router.get("/me")
async def get_current_user_info(
    current_user: dict = Depends(AuthManager.get_current_user)
):
    """
    获取当前用户信息
    """
    return {
        "username": current_user["username"],
        "role": current_user["admin_role"],
        "display_name": current_user["name"],
        "email": current_user["email"],
        "is_builtin_admin": current_user["is_builtin_admin"]
    }