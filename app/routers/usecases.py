"""Public routes for use cases."""
import logging
from typing import Optional
from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.db import get_db
from app.dependencies import get_current_user
from app.models.auth import User
from app.models import UseCase
from app.templates_engine import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/use-cases",
    tags=["use-cases"],
)


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def usecases_list(
    request: Request,
    search: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    organization_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Public use cases listing page."""
    per_page = 20

    # Only show approved use cases
    query = db.query(UseCase).filter(UseCase.status == "approved")

    # Apply filters
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (UseCase.title.ilike(search_term)) |
            (UseCase.summary.ilike(search_term)) |
            (UseCase.organization.ilike(search_term))
        )

    if country:
        query = query.filter(UseCase.country == country)

    if organization_type:
        query = query.filter(UseCase.organization_type == organization_type)

    # Get filter options
    countries = db.query(UseCase.country).filter(
        UseCase.status == "approved",
        UseCase.country.isnot(None)
    ).distinct().all()
    countries = sorted([c[0] for c in countries if c[0]])

    org_types = db.query(UseCase.organization_type).filter(
        UseCase.status == "approved",
        UseCase.organization_type.isnot(None)
    ).distinct().all()
    org_types = [o[0] for o in org_types if o[0]]

    # Pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page

    usecases = query.order_by(
        desc(UseCase.source_date),
        desc(UseCase.discovered_at)
    ).offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse(
        "usecases/index.html",
        {
            "request": request,
            "user": user,
            "usecases": usecases,
            "search": search,
            "current_country": country,
            "current_organization_type": organization_type,
            "countries": countries,
            "organization_types": org_types,
            "page": page,
            "total_pages": total_pages,
            "total": total,
        }
    )


@router.get("/{slug}", response_class=HTMLResponse)
async def usecase_detail(
    slug: str,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Public use case detail page."""
    usecase = db.query(UseCase).filter(
        UseCase.slug == slug,
        UseCase.status == "approved"
    ).first()

    if not usecase:
        raise HTTPException(status_code=404, detail="Use case not found")

    # Get related use cases (same organization type or country)
    related = db.query(UseCase).filter(
        UseCase.status == "approved",
        UseCase.id != usecase.id,
        (
            (UseCase.organization_type == usecase.organization_type) |
            (UseCase.country == usecase.country)
        )
    ).order_by(desc(UseCase.source_date)).limit(4).all()

    return templates.TemplateResponse(
        "usecases/detail.html",
        {
            "request": request,
            "user": user,
            "usecase": usecase,
            "related_usecases": related,
        }
    )
