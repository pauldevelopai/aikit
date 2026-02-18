"""
AI Audio Product Definition.

This is a placeholder product for future development.
AI Audio will be a distinct app for audio production and editing tools.
"""

from app.products.config import (
    Product,
    Edition,
    FeatureFlags,
    Branding,
    NavigationItem,
    ContentScope,
)
from app.products.registry import ProductRegistry, EditionRegistry


# =============================================================================
# PRODUCT DEFINITION (Placeholder)
# =============================================================================

AI_AUDIO_PRODUCT = Product(
    id="ai_audio",
    name="AI Audio",
    description="AI-powered audio production and editing toolkit",
    branding=Branding(
        logo_text="AI Audio",
        logo_path=None,
        primary_color="#8B5CF6",    # Purple
        secondary_color="#6D28D9",  # Dark purple
        accent_color="#F59E0B",     # Amber
    ),
    navigation=[
        # Placeholder navigation - to be defined when product is built
        NavigationItem(
            label="Audio Tools",
            route="/audio/tools",
            icon="music",
            requires_auth=False,
        ),
        NavigationItem(
            label="Projects",
            route="/audio/projects",
            icon="folder",
            requires_auth=True,
        ),
    ],
    content_scope=ContentScope.AUDIO,
    is_active=False,  # Not yet active - placeholder only
)


# =============================================================================
# EDITION DEFINITIONS (Placeholder)
# =============================================================================

# No editions defined yet - will be created when product development begins
# Example of what V1 might look like:
#
# AI_AUDIO_V1_EDITION = Edition(
#     product_id="ai_audio",
#     version="v1",
#     display_name="AI Audio V1",
#     feature_flags=FeatureFlags(...),
#     is_sealed=False,
#     is_active=True,
# )


# =============================================================================
# REGISTRATION
# =============================================================================

def register_audio() -> None:
    """
    Register the AI Audio product.

    Currently registers only the product placeholder.
    Editions will be registered when product development begins.
    """
    ProductRegistry.register(AI_AUDIO_PRODUCT)

    # No editions to register yet
    # EditionRegistry.register(AI_AUDIO_V1_EDITION)
