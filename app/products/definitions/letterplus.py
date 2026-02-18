"""
Letter+ Product Definition.

This is a placeholder product for future development.
Letter+ will be a distinct app for writing and letter composition.
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

LETTERPLUS_PRODUCT = Product(
    id="letter_plus",
    name="Letter+",
    description="AI-powered writing and letter composition assistant",
    branding=Branding(
        logo_text="Letter+",
        logo_path=None,
        primary_color="#EC4899",    # Pink
        secondary_color="#BE185D",  # Dark pink
        accent_color="#14B8A6",     # Teal
    ),
    navigation=[
        # Placeholder navigation - to be defined when product is built
        NavigationItem(
            label="Compose",
            route="/letter/compose",
            icon="pen",
            requires_auth=True,
        ),
        NavigationItem(
            label="Templates",
            route="/letter/templates",
            icon="template",
            requires_auth=False,
        ),
        NavigationItem(
            label="My Letters",
            route="/letter/archive",
            icon="archive",
            requires_auth=True,
        ),
    ],
    content_scope=ContentScope.WRITING,
    is_active=False,  # Not yet active - placeholder only
)


# =============================================================================
# EDITION DEFINITIONS (Placeholder)
# =============================================================================

# No editions defined yet - will be created when product development begins
# Example of what V1 might look like:
#
# LETTERPLUS_V1_EDITION = Edition(
#     product_id="letter_plus",
#     version="v1",
#     display_name="Letter+ V1",
#     feature_flags=FeatureFlags(...),
#     is_sealed=False,
#     is_active=True,
# )


# =============================================================================
# REGISTRATION
# =============================================================================

def register_letterplus() -> None:
    """
    Register the Letter+ product.

    Currently registers only the product placeholder.
    Editions will be registered when product development begins.
    """
    ProductRegistry.register(LETTERPLUS_PRODUCT)

    # No editions to register yet
    # EditionRegistry.register(LETTERPLUS_V1_EDITION)
