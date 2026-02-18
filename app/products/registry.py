"""
Product and Edition Registry.

This module provides centralized registration and lookup for products
and their editions. It serves as the single source of truth for
what products and versions exist in the system.
"""

from typing import Optional
from app.products.config import Product, Edition


class ProductRegistry:
    """
    Registry for all products in the system.

    This is a singleton-pattern registry that holds all product definitions.
    Products are registered at application startup and looked up at runtime.
    """

    _products: dict[str, Product] = {}

    @classmethod
    def register(cls, product: Product) -> None:
        """
        Register a product.

        Args:
            product: Product instance to register

        Raises:
            ValueError: If product ID already registered
        """
        if product.id in cls._products:
            raise ValueError(f"Product '{product.id}' is already registered")
        cls._products[product.id] = product

    @classmethod
    def get(cls, product_id: str) -> Optional[Product]:
        """
        Get a product by ID.

        Args:
            product_id: Product identifier

        Returns:
            Product instance or None if not found
        """
        return cls._products.get(product_id)

    @classmethod
    def get_or_raise(cls, product_id: str) -> Product:
        """
        Get a product by ID, raising if not found.

        Args:
            product_id: Product identifier

        Returns:
            Product instance

        Raises:
            KeyError: If product not found
        """
        product = cls.get(product_id)
        if product is None:
            raise KeyError(f"Product '{product_id}' not found")
        return product

    @classmethod
    def list_all(cls) -> list[Product]:
        """Get all registered products."""
        return list(cls._products.values())

    @classmethod
    def list_active(cls) -> list[Product]:
        """Get all active products."""
        return [p for p in cls._products.values() if p.is_active]

    @classmethod
    def clear(cls) -> None:
        """Clear all registered products (for testing)."""
        cls._products.clear()


class EditionRegistry:
    """
    Registry for all editions across all products.

    Editions are registered at application startup. The registry tracks
    which edition is active for each product and enforces sealing rules.
    """

    _editions: dict[str, Edition] = {}  # Key: "product_id:version"
    _active_editions: dict[str, str] = {}  # Key: product_id, Value: edition_id

    @classmethod
    def register(cls, edition: Edition) -> None:
        """
        Register an edition.

        Args:
            edition: Edition instance to register

        Raises:
            ValueError: If edition already registered or product not found
        """
        # Validate product exists
        if ProductRegistry.get(edition.product_id) is None:
            raise ValueError(
                f"Cannot register edition '{edition.edition_id}': "
                f"product '{edition.product_id}' not found"
            )

        if edition.edition_id in cls._editions:
            raise ValueError(f"Edition '{edition.edition_id}' is already registered")

        cls._editions[edition.edition_id] = edition

        # Track active edition per product
        if edition.is_active:
            # If there's already an active edition, deactivate it
            current_active = cls._active_editions.get(edition.product_id)
            if current_active and current_active != edition.edition_id:
                existing = cls._editions.get(current_active)
                if existing:
                    existing.is_active = False

            cls._active_editions[edition.product_id] = edition.edition_id

    @classmethod
    def get(cls, product_id: str, version: str) -> Optional[Edition]:
        """
        Get an edition by product ID and version.

        Args:
            product_id: Product identifier
            version: Version label

        Returns:
            Edition instance or None if not found
        """
        edition_id = f"{product_id}:{version}"
        return cls._editions.get(edition_id)

    @classmethod
    def get_or_raise(cls, product_id: str, version: str) -> Edition:
        """
        Get an edition, raising if not found.

        Args:
            product_id: Product identifier
            version: Version label

        Returns:
            Edition instance

        Raises:
            KeyError: If edition not found
        """
        edition = cls.get(product_id, version)
        if edition is None:
            raise KeyError(f"Edition '{product_id}:{version}' not found")
        return edition

    @classmethod
    def get_active(cls, product_id: str) -> Optional[Edition]:
        """
        Get the active edition for a product.

        Args:
            product_id: Product identifier

        Returns:
            Active Edition instance or None
        """
        active_id = cls._active_editions.get(product_id)
        if active_id:
            return cls._editions.get(active_id)
        return None

    @classmethod
    def get_active_or_raise(cls, product_id: str) -> Edition:
        """
        Get the active edition for a product, raising if none.

        Args:
            product_id: Product identifier

        Returns:
            Active Edition instance

        Raises:
            KeyError: If no active edition for product
        """
        edition = cls.get_active(product_id)
        if edition is None:
            raise KeyError(f"No active edition for product '{product_id}'")
        return edition

    @classmethod
    def list_for_product(cls, product_id: str) -> list[Edition]:
        """
        Get all editions for a product.

        Args:
            product_id: Product identifier

        Returns:
            List of editions for the product
        """
        return [
            e for e in cls._editions.values()
            if e.product_id == product_id
        ]

    @classmethod
    def list_all(cls) -> list[Edition]:
        """Get all registered editions."""
        return list(cls._editions.values())

    @classmethod
    def list_sealed(cls) -> list[Edition]:
        """Get all sealed editions."""
        return [e for e in cls._editions.values() if e.is_sealed]

    @classmethod
    def seal_edition(
        cls,
        product_id: str,
        version: str,
        reason: Optional[str] = None
    ) -> Edition:
        """
        Seal an edition, making it read-only.

        Args:
            product_id: Product identifier
            version: Version label
            reason: Optional reason for sealing

        Returns:
            The sealed edition

        Raises:
            KeyError: If edition not found
            ValueError: If edition already sealed
        """
        edition = cls.get_or_raise(product_id, version)
        edition.seal(reason)

        # If this was the active edition, remove it from active tracking
        if cls._active_editions.get(product_id) == edition.edition_id:
            del cls._active_editions[product_id]

        return edition

    @classmethod
    def set_active(cls, product_id: str, version: str) -> Edition:
        """
        Set the active edition for a product.

        Args:
            product_id: Product identifier
            version: Version label

        Returns:
            The newly active edition

        Raises:
            KeyError: If edition not found
            ValueError: If edition is sealed
        """
        edition = cls.get_or_raise(product_id, version)

        if edition.is_sealed:
            raise ValueError(
                f"Cannot activate sealed edition '{edition.edition_id}'"
            )

        # Deactivate current active
        current_active = cls.get_active(product_id)
        if current_active:
            current_active.is_active = False

        # Activate new edition
        edition.is_active = True
        cls._active_editions[product_id] = edition.edition_id

        return edition

    @classmethod
    def create_from_existing(
        cls,
        product_id: str,
        source_version: str,
        new_version: str,
        display_name: Optional[str] = None,
        feature_overrides: Optional[dict] = None,
        make_active: bool = True,
    ) -> Edition:
        """
        Create a new edition by cloning an existing one.

        This is the primary way to create new versions:
        1. Find the source edition to clone
        2. Create new edition with new version label
        3. Optionally override features
        4. Register the new edition

        Args:
            product_id: Product identifier
            source_version: Version to clone from
            new_version: New version label
            display_name: Optional custom display name
            feature_overrides: Optional feature flag overrides
            make_active: Whether to make the new edition active

        Returns:
            The newly created and registered edition

        Raises:
            KeyError: If source edition not found
            ValueError: If new version already exists
        """
        source = cls.get_or_raise(product_id, source_version)

        # Check new version doesn't exist
        if cls.get(product_id, new_version):
            raise ValueError(
                f"Edition '{product_id}:{new_version}' already exists"
            )

        new_edition = source.clone_for_new_version(
            new_version=new_version,
            display_name=display_name,
            feature_overrides=feature_overrides,
        )

        if not make_active:
            new_edition.is_active = False

        cls.register(new_edition)
        return new_edition

    @classmethod
    def clear(cls) -> None:
        """Clear all registered editions (for testing)."""
        cls._editions.clear()
        cls._active_editions.clear()


# Convenience functions for simpler access
def get_product(product_id: str) -> Optional[Product]:
    """Get a product by ID."""
    return ProductRegistry.get(product_id)


def get_edition(product_id: str, version: str) -> Optional[Edition]:
    """Get an edition by product ID and version."""
    return EditionRegistry.get(product_id, version)


def get_active_edition(product_id: str) -> Optional[Edition]:
    """Get the active edition for a product."""
    return EditionRegistry.get_active(product_id)


def list_products() -> list[Product]:
    """Get all registered products."""
    return ProductRegistry.list_all()


def list_editions(product_id: Optional[str] = None) -> list[Edition]:
    """
    Get editions, optionally filtered by product.

    Args:
        product_id: Optional product ID to filter by

    Returns:
        List of editions
    """
    if product_id:
        return EditionRegistry.list_for_product(product_id)
    return EditionRegistry.list_all()


def create_new_edition(
    product_id: str,
    source_version: str,
    new_version: str,
    **kwargs
) -> Edition:
    """
    Create a new edition by cloning an existing one.

    Args:
        product_id: Product identifier
        source_version: Version to clone from
        new_version: New version label
        **kwargs: Additional arguments (display_name, feature_overrides, make_active)

    Returns:
        The newly created edition
    """
    return EditionRegistry.create_from_existing(
        product_id=product_id,
        source_version=source_version,
        new_version=new_version,
        **kwargs
    )
