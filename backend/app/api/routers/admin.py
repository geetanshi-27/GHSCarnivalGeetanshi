from __future__ import annotations

import json
from enum import Enum
from typing import Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.db.prisma import prisma
from app.db.prisma_client.fields import Json
from app.api.utils.security import get_current_user, get_current_super_admin, validate_csrf_token

router = APIRouter(prefix="/admin", tags=["admin"])


class MatchStatus(str, Enum):
    UPCOMING = "UPCOMING"
    LIVE = "LIVE"
    COMPLETED = "COMPLETED"


class UpsertMatchBody(BaseModel):
    sportSlug: str
    teamA: str
    teamB: str
    status: MatchStatus = MatchStatus.UPCOMING
    startTime: str | None = None
    venue: str | None = None
    score: dict[str, Any] | None = None


class UpdateMatchBody(BaseModel):
    teamA: str | None = None
    teamB: str | None = None
    status: MatchStatus | None = None
    startTime: str | None = None
    venue: str | None = None
    score: dict[str, Any] | None = None


class CreateAnnouncementBody(BaseModel):
    title: str
    body: str
    pinned: bool = False


class UpdateAnnouncementBody(BaseModel):
    title: str | None = None
    body: str | None = None
    pinned: bool | None = None


@router.post("/matches")
async def create_match(
    body: UpsertMatchBody, 
    current_admin=Depends(get_current_user),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    sport = await prisma.sport.find_unique(where={"slug": body.sportSlug})
    if sport is None:
        raise HTTPException(status_code=404, detail="Sport not found")

    if current_admin.role != "SUPER_ADMIN":
        if current_admin.sportId != sport.id:
            raise HTTPException(
                status_code=403, 
                detail="You do not have permission to manage this sport"
            )

    # Build create data - only include optional fields if they have values
    create_data = {
        "sportId": sport.id,
        "teamA": body.teamA,
        "teamB": body.teamB,
        "status": body.status,
    }
    
    if body.startTime is not None:
        create_data["startTime"] = body.startTime
    if body.venue is not None:
        create_data["venue"] = body.venue
    if body.score is not None:
        # Convert dict to Prisma Json type
        create_data["score"] = Json(body.score)

    match = await prisma.match.create(data=create_data)
    return {"item": match}


@router.get("/matches/{match_id}")
async def get_match(
    match_id: str,
    current_admin=Depends(get_current_user)
) -> dict:
    match = await prisma.match.find_unique(
        where={"id": match_id},
        include={"sport": True}
    )
    if match is None:
        raise HTTPException(status_code=404, detail="Match not found")
    
    # Check permission
    if current_admin.role != "SUPER_ADMIN":
        if current_admin.sportId != match.sportId:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to view this match"
            )
    
    return {"item": match}


@router.patch("/matches/{match_id}")
async def update_match(
    match_id: str,
    body: UpdateMatchBody,
    current_admin=Depends(get_current_user),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    # Find the match
    match = await prisma.match.find_unique(
        where={"id": match_id},
        include={"sport": True}
    )
    if match is None:
        raise HTTPException(status_code=404, detail="Match not found")
    
    # Check permission
    if current_admin.role != "SUPER_ADMIN":
        if current_admin.sportId != match.sportId:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to update this match"
            )
    
    # Build update data (only include fields that were provided)
    update_data = {}
    if body.teamA is not None:
        update_data["teamA"] = body.teamA
    if body.teamB is not None:
        update_data["teamB"] = body.teamB
    if body.status is not None:
        update_data["status"] = body.status
    if body.startTime is not None:
        update_data["startTime"] = body.startTime
    if body.venue is not None:
        update_data["venue"] = body.venue
    if body.score is not None:
        # Convert dict to Prisma Json type
        update_data["score"] = Json(body.score)
    
    # Skip update if no fields were provided
    if not update_data:
        return {"item": match}
    
    # Update the match
    updated_match = await prisma.match.update(
        where={"id": match_id},
        data=update_data,
        include={"sport": True}
    )
    
    return {"item": updated_match}


@router.delete("/matches/{match_id}")
async def delete_match(
    match_id: str,
    current_admin=Depends(get_current_user),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    # Find the match
    match = await prisma.match.find_unique(where={"id": match_id})
    if match is None:
        raise HTTPException(status_code=404, detail="Match not found")
    
    # Check permission
    if current_admin.role != "SUPER_ADMIN":
        if current_admin.sportId != match.sportId:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to delete this match"
            )
    
    # Delete the match
    await prisma.match.delete(where={"id": match_id})
    
    return {"message": "Match deleted successfully"}


@router.get("/matches")
async def list_admin_matches(
    current_admin=Depends(get_current_user),
    sport_id: str | None = None,
    status: str | None = None
) -> dict:
    """List matches for admin - filtered by their sport if not SUPER_ADMIN"""
    where_clause = {}
    
    # Sport admins can only see their sport's matches
    if current_admin.role != "SUPER_ADMIN":
        where_clause["sportId"] = current_admin.sportId
    elif sport_id:
        where_clause["sportId"] = sport_id
    
    if status:
        where_clause["status"] = status
    
    matches = await prisma.match.find_many(
        where=where_clause,
        include={"sport": True},
        order=[{"status": "asc"}, {"updatedAt": "desc"}],  # LIVE first for admins
        take=200  # Limit to prevent excessive data transfer
    )
    
    return {"items": matches}


# Announcement Management
@router.post("/announcements")
async def create_announcement(
    body: CreateAnnouncementBody,
    current_admin=Depends(get_current_super_admin),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    """Create an announcement (SUPER_ADMIN only)"""
    
    announcement = await prisma.announcement.create(
        data={
            "title": body.title,
            "body": body.body,
            "pinned": body.pinned
        }
    )
    
    return {"item": announcement}


@router.patch("/announcements/{announcement_id}")
async def update_announcement(
    announcement_id: str,
    body: UpdateAnnouncementBody,
    current_admin=Depends(get_current_super_admin),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    """Update an announcement (SUPER_ADMIN only)"""
    
    announcement = await prisma.announcement.find_unique(
        where={"id": announcement_id}
    )
    if announcement is None:
        raise HTTPException(status_code=404, detail="Announcement not found")
    
    update_data = {}
    if body.title is not None:
        update_data["title"] = body.title
    if body.body is not None:
        update_data["body"] = body.body
    if body.pinned is not None:
        update_data["pinned"] = body.pinned
    
    updated_announcement = await prisma.announcement.update(
        where={"id": announcement_id},
        data=update_data
    )
    
    return {"item": updated_announcement}


@router.delete("/announcements/{announcement_id}")
async def delete_announcement(
    announcement_id: str,
    current_admin=Depends(get_current_super_admin),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    """Delete an announcement (SUPER_ADMIN only)"""
    
    try:
        await prisma.announcement.delete(where={"id": announcement_id})
    except Exception:
        raise HTTPException(status_code=404, detail="Announcement not found")
    
    return {"message": "Announcement deleted successfully"}


# User Management (SUPER_ADMIN only)
class UpdateUserBody(BaseModel):
    email: str | None = None
    password: str | None = None


@router.get("/users")
async def list_users(
    current_admin=Depends(get_current_super_admin)
) -> dict:
    """List all admin users (SUPER_ADMIN only)"""
    from app.api.utils.security import get_password_hash
    
    users = await prisma.user.find_many(
        include={"sport": True},
        order={"createdAt": "asc"}
    )
    
    # Return users without password hashes
    users_data = []
    for user in users:
        user_dict = user.model_dump(mode='json')
        user_dict.pop('passwordHash', None)
        users_data.append(user_dict)
    
    return {"items": users_data}


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    body: UpdateUserBody,
    current_admin=Depends(get_current_super_admin),
    _csrf: None = Depends(validate_csrf_token)
) -> dict:
    """Update user email or password (SUPER_ADMIN only)"""
    from app.api.utils.security import get_password_hash
    
    # Find the user
    user = await prisma.user.find_unique(where={"id": user_id})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent super admin from modifying themselves via this endpoint
    if user.id == current_admin.id:
        raise HTTPException(
            status_code=403,
            detail="Cannot modify your own account via this endpoint"
        )
    
    update_data = {}
    
    if body.email is not None:
        # Check if email is already taken by another user
        existing = await prisma.user.find_unique(where={"email": body.email})
        if existing and existing.id != user_id:
            raise HTTPException(
                status_code=400,
                detail="Email already in use"
            )
        update_data["email"] = body.email
    
    if body.password is not None:
        # Hash the new password
        update_data["passwordHash"] = get_password_hash(body.password)
    
    if not update_data:
        raise HTTPException(
            status_code=400,
            detail="No fields to update"
        )
    
    # Update the user
    updated_user = await prisma.user.update(
        where={"id": user_id},
        data=update_data,
        include={"sport": True}
    )
    
    # Return without password hash
    user_dict = updated_user.model_dump(mode='json')
    user_dict.pop('passwordHash', None)
    
    return {"item": user_dict}
