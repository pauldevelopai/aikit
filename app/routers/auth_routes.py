"""Authentication routes."""
from typing import Optional
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.auth import User
from app.dependencies import get_current_user
from app.services.auth import create_user, authenticate_user, create_session, delete_session
from app.settings import settings
from app.middleware.csrf import CSRFProtectionMiddleware
from app.templates_engine import templates
from app.products.registry import ProductRegistry, EditionRegistry


router = APIRouter(tags=["auth"])


def get_available_products():
    """Get all available products with their editions for login page."""
    all_products = ProductRegistry.list_all()
    products_with_editions = []

    for p in all_products:
        editions = EditionRegistry.list_for_product(p.id)
        # Only include products that have at least one edition
        if editions:
            products_with_editions.append({
                "product": p,
                "editions": editions,
            })

    return products_with_editions


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    response: Response,
    next: Optional[str] = None,
    user: Optional[User] = Depends(get_current_user),
):
    """Login page."""
    # Already logged in — redirect
    if user:
        return RedirectResponse(url=next or "/", status_code=302)

    csrf_token = CSRFProtectionMiddleware.generate_token()
    available_products = get_available_products()

    template_response = templates.TemplateResponse(
        "auth/login.html",
        {
            "request": request,
            "csrf_token": csrf_token,
            "user": None,
            "next": next or "",
            "available_products": available_products,
            "selected_product": "ai_toolkit",  # Default selection
        }
    )
    CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
    return template_response


@router.post("/auth/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    product: Optional[str] = Form(None),
    next: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """Process login form."""
    user = authenticate_user(db, username, password)

    available_products = get_available_products()

    if not user:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "Invalid username or password",
                "csrf_token": csrf_token,
                "user": None,
                "next": next or "",
                "available_products": available_products,
                "selected_product": product or "ai_toolkit",
            }
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response

    # Get the form data to extract edition selection
    form_data = await request.form()
    edition_key = f"edition_{product}" if product else "edition_ai_toolkit"
    edition = form_data.get(edition_key)

    # Update user's product/edition preference
    if product:
        user.selected_product = product
        user.selected_edition = edition
        db.commit()

    # Validate redirect URL (must be relative, not protocol-relative)
    redirect_url = "/"
    if next and next.startswith("/") and not next.startswith("//"):
        redirect_url = next

    session = create_session(db, str(user.id))
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session.session_token,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_MAX_AGE
    )
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    response: Response,
    user: Optional[User] = Depends(get_current_user),
):
    """Registration page."""
    if user:
        return RedirectResponse(url="/", status_code=302)

    csrf_token = CSRFProtectionMiddleware.generate_token()
    template_response = templates.TemplateResponse(
        "auth/register.html",
        {"request": request, "csrf_token": csrf_token, "user": None}
    )
    CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
    return template_response


@router.post("/auth/register")
async def register(
    request: Request,
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process registration form."""
    if len(password) < 8:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": "Password must be at least 8 characters", "csrf_token": csrf_token, "user": None}
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response

    try:
        user = create_user(db, email, username, password)
        session = create_session(db, str(user.id))
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=session.session_token,
            httponly=settings.COOKIE_HTTPONLY,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            max_age=settings.SESSION_MAX_AGE
        )
        return response
    except ValueError as e:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/register.html",
            {"request": request, "error": str(e), "csrf_token": csrf_token, "user": None}
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(
    request: Request,
    response: Response,
    success: Optional[str] = None,
):
    """Show the forgot password form."""
    csrf_token = CSRFProtectionMiddleware.generate_token()
    template_response = templates.TemplateResponse(
        "auth/forgot_password.html",
        {
            "request": request,
            "csrf_token": csrf_token,
            "user": None,
            "success": success,
        }
    )
    CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
    return template_response


@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    """Process forgot password form - send reset email."""
    from app.services.email import generate_reset_token, send_reset_email

    # Always show success message to prevent email enumeration
    user = db.query(User).filter(User.email == email).first()

    if user:
        token = generate_reset_token(email)
        # Build reset URL from the request's base URL
        base_url = str(request.base_url).rstrip("/")
        reset_url = f"{base_url}/reset-password?token={token}"
        send_reset_email(email, reset_url)

    # Always redirect with success to prevent email enumeration
    return RedirectResponse(url="/forgot-password?success=1", status_code=303)


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    response: Response,
    token: str = "",
):
    """Show the reset password form."""
    from app.services.email import verify_reset_token

    if not token:
        return RedirectResponse(url="/forgot-password", status_code=302)

    # Verify token is valid before showing form
    email = verify_reset_token(token)
    if not email:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/reset_password.html",
            {
                "request": request,
                "csrf_token": csrf_token,
                "user": None,
                "token": token,
                "error": "This reset link has expired or is invalid. Please request a new one.",
            }
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response

    csrf_token = CSRFProtectionMiddleware.generate_token()
    template_response = templates.TemplateResponse(
        "auth/reset_password.html",
        {
            "request": request,
            "csrf_token": csrf_token,
            "user": None,
            "token": token,
        }
    )
    CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
    return template_response


@router.post("/reset-password")
async def reset_password(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    """Process password reset form."""
    from app.services.email import verify_reset_token
    from app.services.auth import hash_password

    # Verify token
    email = verify_reset_token(token)
    if not email:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/reset_password.html",
            {
                "request": request,
                "csrf_token": csrf_token,
                "user": None,
                "token": token,
                "error": "This reset link has expired or is invalid. Please request a new one.",
            }
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response

    # Validate passwords match
    if password != password_confirm:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/reset_password.html",
            {
                "request": request,
                "csrf_token": csrf_token,
                "user": None,
                "token": token,
                "error": "Passwords do not match.",
            }
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response

    # Validate password length
    if len(password) < 8:
        csrf_token = CSRFProtectionMiddleware.generate_token()
        template_response = templates.TemplateResponse(
            "auth/reset_password.html",
            {
                "request": request,
                "csrf_token": csrf_token,
                "user": None,
                "token": token,
                "error": "Password must be at least 8 characters.",
            }
        )
        CSRFProtectionMiddleware.set_csrf_cookie(template_response, csrf_token)
        return template_response

    # Find user and update password
    user = db.query(User).filter(User.email == email).first()
    if user:
        user.hashed_password = hash_password(password)
        db.commit()

    # Redirect to login with success message
    return RedirectResponse(url="/login", status_code=303)


@router.post("/auth/logout")
async def logout(
    request: Request,
    db: Session = Depends(get_db)
):
    """Logout (delete session)."""
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        delete_session(db, session_token)

    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return response
