"""Application startup validation and initialization."""
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.settings import settings
from app.db import engine

logger = logging.getLogger(__name__)


def validate_settings() -> None:
    """
    Validate all required settings at startup.

    Raises:
        ValueError: If required settings are missing or invalid
    """
    logger.info(f"Validating settings for ENV={settings.ENV}")

    # Run comprehensive validation
    settings.validate_required_for_env()
    settings.validate_embedding_config()

    logger.info("✓ Settings validation passed")


def validate_database() -> None:
    """
    Validate database connection and required tables.

    Raises:
        Exception: If database is unreachable or tables are missing
    """
    logger.info("Validating database connection...")

    try:
        # Test connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        logger.info("✓ Database connection successful")

        # Check for required tables
        required_tables = [
            'users',
            'sessions',
            'toolkit_documents',
            'toolkit_chunks',
            'chat_logs',
            'feedback'
        ]

        with engine.connect() as conn:
            # Query PostgreSQL system tables
            result = conn.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public'"
                )
            )
            existing_tables = {row[0] for row in result}

        missing_tables = set(required_tables) - existing_tables

        if missing_tables:
            raise ValueError(
                f"Missing required database tables: {', '.join(missing_tables)}. "
                "Run migrations with: alembic upgrade head"
            )

        logger.info(f"✓ All required tables present: {', '.join(required_tables)}")

    except Exception as e:
        logger.error(f"✗ Database validation failed: {e}")
        raise


def ensure_admin_user() -> None:
    """
    Create an admin user from ADMIN_EMAIL + ADMIN_PASSWORD env vars if no admin exists.

    This runs at startup to ensure there's always an admin account available.
    Only creates the user if both env vars are set AND no user with that email exists.
    """
    admin_email = settings.ADMIN_EMAIL
    admin_password = settings.ADMIN_PASSWORD

    if not admin_email or not admin_password:
        logger.info("ADMIN_EMAIL or ADMIN_PASSWORD not set, skipping auto-admin creation")
        return

    from app.models.auth import User
    from app.services.auth import create_user

    with Session(engine) as db:
        existing = db.query(User).filter(User.email == admin_email).first()
        if existing:
            logger.info(f"Admin user {admin_email} already exists, skipping creation")
            return

        try:
            # Generate a username from the email
            username = admin_email.split("@")[0]
            # Check if username already taken, append _admin if so
            existing_username = db.query(User).filter(User.username == username).first()
            if existing_username:
                username = f"{username}_admin"

            create_user(db, admin_email, username, admin_password, is_admin=True)
            logger.info(f"Auto-created admin user: {admin_email}")
        except ValueError as e:
            logger.warning(f"Could not create admin user: {e}")


def run_startup_validation() -> None:
    """
    Run all startup validations.

    This is called during application startup and will fail fast
    with clear error messages if any validation fails.

    Raises:
        Exception: If any validation fails
    """
    logger.info("=" * 60)
    logger.info("Starting application startup validation")
    logger.info("=" * 60)

    try:
        # Validate settings
        validate_settings()

        # Validate database
        validate_database()

        # Auto-create admin user if configured
        ensure_admin_user()

        logger.info("=" * 60)
        logger.info("✓ All startup validations passed")
        logger.info("=" * 60)

    except Exception as e:
        logger.error("=" * 60)
        logger.error("✗ Startup validation failed")
        logger.error("=" * 60)
        logger.error(f"Error: {e}")
        logger.error("")
        logger.error("Application will not start until this is resolved.")
        raise
