"""
Security utility functions for password expiration and policy checks.
"""
import logging
import time
from typing import Optional

from open_webui.env import SRC_LOG_LEVELS
from open_webui.internal.db import get_db
from open_webui.models.security import PasswordPolicy, SecurityConfig
from fastapi import HTTPException

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["MAIN"])


def check_password_expiry(user_email: str) -> bool:
    """
    Check if a user's password has expired.

    Args:
        user_email: The email of the user to check

    Returns:
        bool: True if password has expired, False otherwise

    Raises:
        HTTPException: If password has expired, raises 401 with "PASSWORD_EXPIRED" detail
    """
    try:
        with get_db() as db:
            # Get password policy for user
            password_policy = db.query(PasswordPolicy).filter(
                PasswordPolicy.user_email == user_email
            ).first()

            if not password_policy:
                # No password policy exists, so password is not expired
                return False

            # Get password expiry configuration
            security_config = db.query(SecurityConfig).filter(
                SecurityConfig.key == "PASSWORD_EXPIRY_DAYS"
            ).first()

            password_expiry_days = 90  # Default value
            if security_config:
                try:
                    password_expiry_days = int(security_config.value)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid PASSWORD_EXPIRY_DAYS value: {security_config.value}")

            # Check if password has expired
            current_time = int(time.time())
            password_expiry_time = password_policy.password_set_at + (password_expiry_days * 86400)

            if current_time > password_expiry_time:
                return True

            return False

    except Exception as e:
        logger.error(f"Error checking password expiry for {user_email}: {str(e)}")
        # In case of error, assume password is not expired to avoid blocking users
        return False


def enforce_password_expiry_check(user_email: str):
    """
    Enforce password expiry check and raise HTTPException if password has expired.

    Args:
        user_email: The email of the user to check

    Raises:
        HTTPException: 401 with "PASSWORD_EXPIRED" detail if password has expired
    """
    if check_password_expiry(user_email):
        raise HTTPException(
            status_code=401,
            detail="PASSWORD_EXPIRED"
        )


def update_password_timestamp(user_email: str):
    """
    Update the password timestamp for a user.

    Args:
        user_email: The email of the user to update
    """
    try:
        with get_db() as db:
            password_policy = db.query(PasswordPolicy).filter(
                PasswordPolicy.user_email == user_email
            ).first()

            if not password_policy:
                # Create new password policy
                import uuid
                password_policy = PasswordPolicy(
                    id=str(uuid.uuid4()),
                    user_email=user_email,
                    password_set_at=int(time.time()),
                    force_password_change=True
                )
                db.add(password_policy)
            else:
                # Update existing password policy
                password_policy.password_set_at = int(time.time())

            db.commit()

    except Exception as e:
        logger.error(f"Error updating password timestamp for {user_email}: {str(e)}")
        # Don't raise exception as this shouldn't block the main operation