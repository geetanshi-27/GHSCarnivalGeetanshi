"""Authentication endpoints for admin login"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Dict, Tuple

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from pydantic import BaseModel

from app.db.prisma import prisma
from app.api.utils.security import (
    get_current_user,
    verify_password,
    create_access_token,
    get_password_hash
)

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)

# Simple in-memory backoff for failed logins.
# Note: This is best-effort for single-process deployments and dev; for production,
# use a shared store (Redis) or an API gateway/WAF rate limiter.
_FAILED_LOGINS: Dict[str, Tuple[int, float]] = {}
_WINDOW_SECONDS = 300.0
_MAX_DELAY_SECONDS = 2.0


def _prune_failed_logins(now: float) -> None:
    if not _FAILED_LOGINS:
        return
    # Remove entries outside the window to prevent unbounded growth
    expired = [ip for ip, (_count, first_ts) in _FAILED_LOGINS.items() if (now - first_ts) > _WINDOW_SECONDS]
    for ip in expired:
        _FAILED_LOGINS.pop(ip, None)


def _client_ip(request: Request) -> str:
    # If behind a trusted proxy, you'd typically honor X-Forwarded-For.
    # We keep this conservative by default.
    return (request.client.host if request.client else "unknown")


class LoginRequest(BaseModel):
    email: str
    password: str


class UpdateProfileRequest(BaseModel):
    email: str | None = None
    password: str | None = None
    current_password: str  # Required to verify identity before changing password


class LoginResponse(BaseModel):
    user: dict
    csrf_token: str


class UserResponse(BaseModel):
    user: dict


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, request: Request, response: Response) -> dict:
    """
    Admin login endpoint.
    Sets HttpOnly cookie with JWT and returns CSRF token.
    """
    # Find user by email
    user = await prisma.user.find_unique(
        where={"email": credentials.email},
        include={"sport": True}
    )
    
    now = time.time()
    _prune_failed_logins(now)

    if not user:
        ip = _client_ip(request)
        count, first_ts = _FAILED_LOGINS.get(ip, (0, now))
        if (now - first_ts) > _WINDOW_SECONDS:
            count, first_ts = 0, now
        count += 1
        _FAILED_LOGINS[ip] = (count, first_ts)
        await asyncio.sleep(min(0.25 + 0.25 * count, _MAX_DELAY_SECONDS))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Verify password
    if not verify_password(credentials.password, user.passwordHash):
        ip = _client_ip(request)
        count, first_ts = _FAILED_LOGINS.get(ip, (0, now))
        if (now - first_ts) > _WINDOW_SECONDS:
            count, first_ts = 0, now
        count += 1
        _FAILED_LOGINS[ip] = (count, first_ts)
        await asyncio.sleep(min(0.25 + 0.25 * count, _MAX_DELAY_SECONDS))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Create access token
    access_token = create_access_token(data={"sub": user.id})
    
    # Generate CSRF token
    csrf_token = secrets.token_urlsafe(32)

    # Clear failed-login backoff on success
    ip = _client_ip(request)
    _FAILED_LOGINS.pop(ip, None)
    
    # Log user agent at DEBUG level for troubleshooting iOS issues
    if logger.isEnabledFor(logging.DEBUG):
        user_agent = request.headers.get("user-agent", "unknown")
        logger.debug(f"Login: {user.email} | UA: {user_agent}")
    
    # Set HttpOnly cookie with JWT
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,  # Required for cross-origin cookies
        samesite="none",  # Allow cross-origin cookies
        max_age=60 * 60 * 24 * 7,  # 7 days
        path="/"
    )
    
    # Set CSRF token in a readable cookie (frontend needs this)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # Frontend needs to read this
        secure=True,  # Required for cross-origin cookies
        samesite="none",  # Allow cross-origin cookies
        max_age=60 * 60 * 24 * 7,  # 7 days
        path="/"
    )
    
    # Prepare user data for response
    user_data = {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "sportId": user.sportId,
    }
    
    # Include sport info if user is a sport admin
    if user.sport:
        user_data["sport"] = {
            "id": user.sport.id,
            "name": user.sport.name,
            "slug": user.sport.slug,
        }
    
    return {
        "user": user_data,
        "csrf_token": csrf_token
    }


@router.get("/me")
async def get_current_user_info(current_user=Depends(get_current_user)) -> dict:
    """
    Get current authenticated user information.
    Used by frontend to verify token and get user details.
    """
    user_data = {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "role": current_user.role,
        "sportId": current_user.sportId,
    }
    
    # Include sport info if user is a sport admin
    if current_user.sport:
        user_data["sport"] = {
            "id": current_user.sport.id,
            "name": current_user.sport.name,
            "slug": current_user.sport.slug,
        }
    
    return {"user": user_data}


@router.post("/verify-token")
async def verify_token(current_user=Depends(get_current_user)) -> dict:
    """
    Verify if the provided token is valid.
    Returns user info if valid, raises 401 if invalid.
    """
    return {
        "valid": True,
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "role": current_user.role,
        }
    }


@router.post("/logout")
async def logout(response: Response) -> dict:
    """
    Logout by clearing authentication cookies.
    """
    response.delete_cookie(key="access_token", path="/", secure=True, samesite="none")
    response.delete_cookie(key="csrf_token", path="/", secure=True, samesite="none")
    return {"message": "Logged out successfully"}


@router.patch("/profile")
async def update_profile(
    data: UpdateProfileRequest,
    current_user=Depends(get_current_user)
) -> dict:
    """
    Update current user's email and/or password.
    Requires current password for verification.
    """
    # Verify current password
    if not verify_password(data.current_password, current_user.passwordHash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    # Prepare update data
    update_data = {}
    
    # Update email if provided
    if data.email:
        # Check if email is already taken
        existing_user = await prisma.user.find_unique(
            where={"email": data.email}
        )
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use",
            )
        update_data["email"] = data.email
    
    # Update password if provided
    if data.password:
        update_data["passwordHash"] = get_password_hash(data.password)
    
    # Update user
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No changes provided",
        )
    
    updated_user = await prisma.user.update(
        where={"id": current_user.id},
        data=update_data,
        include={"sport": True}
    )
    
    user_data = {
        "id": updated_user.id,
        "email": updated_user.email,
        "username": updated_user.username,
        "role": updated_user.role,
        "sportId": updated_user.sportId,
    }
    
    if updated_user.sport:
        user_data["sport"] = {
            "id": updated_user.sport.id,
            "name": updated_user.sport.name,
            "slug": updated_user.sport.slug,
        }
    
    return {
        "message": "Profile updated successfully",
        "user": user_data
    }

