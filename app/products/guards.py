"""
Feature Guards for Route Protection.

This module provides mechanisms to protect routes based on feature flags
tied to the current Product + Edition. Features that are disabled in the
current edition will show a friendly "not available" message.

Usage:
    from app.products.guards import require_feature, FeatureDisabledError

    # As a dependency
    @router.get("/reviews")
    async def reviews_page(
        request: Request,
        _: None = Depends(require_feature("reviews"))
    ):
        ...

    # Multiple features
    @router.get("/advanced")
    async def advanced_page(
        request: Request,
        _: None = Depends(require_features(["advanced_search", "tool_finder"]))
    ):
        ...
"""

from typing import Callable, Optional, Union
from functools import wraps
from fastapi import Request, HTTPException, Depends
from fastapi.responses import HTMLResponse

from app.products.context import get_current_edition, get_feature_flags


class FeatureDisabledError(Exception):
    """
    Raised when a feature is not available in the current edition.

    Attributes:
        feature_name: Name of the disabled feature
        message: User-friendly message
    """

    def __init__(self, feature_name: str, message: Optional[str] = None):
        self.feature_name = feature_name
        self.message = message or "This feature is not available in this version of the app."
        super().__init__(self.message)


def check_feature(feature_name: str, request: Optional[Request] = None) -> bool:
    """
    Check if a feature is enabled in the current edition.

    Args:
        feature_name: Name of the feature to check (e.g., "reviews", "strategy")
        request: Optional FastAPI request object

    Returns:
        True if feature is enabled, False otherwise
    """
    try:
        flags = get_feature_flags(request)
        return flags.is_enabled(feature_name)
    except Exception:
        # If we can't determine feature status, default to disabled for safety
        return False


def require_feature(feature_name: str):
    """
    FastAPI dependency that requires a feature to be enabled.

    Use this as a dependency in route handlers to protect routes
    based on feature flags.

    Args:
        feature_name: Name of the feature to require (e.g., "reviews", "strategy")

    Returns:
        A dependency function that raises FeatureDisabledError if feature is disabled

    Example:
        @router.get("/reviews")
        async def reviews_page(
            request: Request,
            _: None = Depends(require_feature("reviews"))
        ):
            return templates.TemplateResponse(...)
    """
    async def dependency(request: Request):
        if not check_feature(feature_name, request):
            raise FeatureDisabledError(feature_name)
        return None

    return dependency


def require_features(feature_names: list[str]):
    """
    FastAPI dependency that requires multiple features to be enabled.

    All listed features must be enabled for the route to be accessible.

    Args:
        feature_names: List of feature names to require

    Returns:
        A dependency function that raises FeatureDisabledError if any feature is disabled

    Example:
        @router.get("/advanced-search")
        async def advanced_search(
            request: Request,
            _: None = Depends(require_features(["advanced_search", "tool_finder"]))
        ):
            return templates.TemplateResponse(...)
    """
    async def dependency(request: Request):
        for feature_name in feature_names:
            if not check_feature(feature_name, request):
                raise FeatureDisabledError(feature_name)
        return None

    return dependency


def require_any_feature(feature_names: list[str]):
    """
    FastAPI dependency that requires at least one feature to be enabled.

    At least one of the listed features must be enabled.

    Args:
        feature_names: List of feature names (at least one must be enabled)

    Returns:
        A dependency function that raises FeatureDisabledError if all features are disabled
    """
    async def dependency(request: Request):
        for feature_name in feature_names:
            if check_feature(feature_name, request):
                return None
        # None of the features are enabled
        raise FeatureDisabledError(
            feature_names[0],
            "This feature is not available in this version of the app."
        )

    return dependency


# =============================================================================
# CONVENIENCE DEPENDENCIES FOR COMMON FEATURES
# =============================================================================

def require_rag():
    """Require RAG feature."""
    return require_feature("rag")


def require_reviews():
    """Require reviews feature."""
    return require_feature("reviews")


def require_strategy():
    """Require strategy feature."""
    return require_feature("strategy")


def require_recommendations():
    """Require recommendations feature."""
    return require_feature("recommendations")


def require_tool_finder():
    """Require tool finder feature."""
    return require_feature("tool_finder")


def require_advanced_search():
    """Require advanced search feature."""
    return require_feature("advanced_search")


def require_browse():
    """Require browse feature."""
    return require_feature("browse")


def require_sources():
    """Require sources feature."""
    return require_feature("sources")


def require_clusters():
    """Require clusters feature."""
    return require_feature("clusters")


def require_foundations():
    """Require foundations feature."""
    return require_feature("foundations")


def require_playbooks():
    """Require playbooks feature."""
    return require_feature("playbooks")


def require_activity_history():
    """Require activity history feature."""
    return require_feature("activity_history")


# =============================================================================
# ADMIN FEATURE GUARDS
# =============================================================================

def require_admin_dashboard():
    """Require admin dashboard feature."""
    return require_feature("admin_dashboard")


def require_admin_ingestion():
    """Require admin ingestion feature."""
    return require_feature("admin_ingestion")


def require_admin_users():
    """Require admin user management feature."""
    return require_feature("admin_users")


def require_admin_analytics():
    """Require admin analytics feature."""
    return require_feature("admin_analytics")


def require_admin_feedback():
    """Require admin feedback feature."""
    return require_feature("admin_feedback")


def require_admin_playbooks():
    """Require admin playbook management feature."""
    return require_feature("admin_playbooks")


def require_admin_discovery():
    """Require admin discovery feature."""
    return require_feature("admin_discovery")


# =============================================================================
# TEMPLATE HELPERS
# =============================================================================

def get_feature_disabled_context(
    request: Request,
    feature_name: str,
    redirect_url: str = "/"
) -> dict:
    """
    Get template context for the feature disabled page.

    Args:
        request: FastAPI request object
        feature_name: Name of the disabled feature
        redirect_url: URL to redirect back to

    Returns:
        Dict with context for the feature_disabled.html template
    """
    # Import here to avoid circular imports
    from app.products.context import get_current_product, get_current_edition

    try:
        product = get_current_product(request)
        edition = get_current_edition(request)
        product_name = product.name
        edition_sealed = edition.is_sealed
    except Exception:
        product_name = "the application"
        edition_sealed = False

    return {
        "request": request,
        "feature_name": feature_name,
        "redirect_url": redirect_url,
        "edition_sealed": edition_sealed,
    }
