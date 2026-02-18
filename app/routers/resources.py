"""Public routes for discovered resources."""
import logging
from typing import Optional
from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.db import get_db
from app.dependencies import get_current_user
from app.models.auth import User
from app.models import DiscoveredResource
from app.templates_engine import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/resources",
    tags=["resources"],
)


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def resources_list(
    request: Request,
    search: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Public resources listing page."""
    per_page = 20

    # Only show approved resources
    query = db.query(DiscoveredResource).filter(
        DiscoveredResource.status == "approved"
    )

    # Apply filters
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (DiscoveredResource.title.ilike(search_term)) |
            (DiscoveredResource.summary.ilike(search_term)) |
            (DiscoveredResource.source.ilike(search_term))
        )

    if resource_type:
        query = query.filter(DiscoveredResource.resource_type == resource_type)

    if source:
        query = query.filter(DiscoveredResource.source == source)

    # Get filter options
    resource_types = db.query(DiscoveredResource.resource_type).filter(
        DiscoveredResource.status == "approved",
        DiscoveredResource.resource_type.isnot(None)
    ).distinct().all()
    resource_types = [r[0] for r in resource_types if r[0]]

    sources = db.query(DiscoveredResource.source).filter(
        DiscoveredResource.status == "approved",
        DiscoveredResource.source.isnot(None)
    ).distinct().all()
    sources = [s[0] for s in sources if s[0]]

    # Pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page

    resources = query.order_by(
        desc(DiscoveredResource.publication_date),
        desc(DiscoveredResource.discovered_at)
    ).offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse(
        "resources/index.html",
        {
            "request": request,
            "user": user,
            "resources": resources,
            "search": search,
            "current_resource_type": resource_type,
            "current_source": source,
            "resource_types": resource_types,
            "sources": sources,
            "page": page,
            "total_pages": total_pages,
            "total": total,
        }
    )


@router.get("/{slug}", response_class=HTMLResponse)
async def resource_detail(
    slug: str,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Public resource detail page."""
    resource = db.query(DiscoveredResource).filter(
        DiscoveredResource.slug == slug,
        DiscoveredResource.status == "approved"
    ).first()

    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Get related resources (same source or type)
    related = db.query(DiscoveredResource).filter(
        DiscoveredResource.status == "approved",
        DiscoveredResource.id != resource.id,
        (
            (DiscoveredResource.source == resource.source) |
            (DiscoveredResource.resource_type == resource.resource_type)
        )
    ).order_by(desc(DiscoveredResource.publication_date)).limit(4).all()

    return templates.TemplateResponse(
        "resources/detail.html",
        {
            "request": request,
            "user": user,
            "resource": resource,
            "related_resources": related,
        }
    )
