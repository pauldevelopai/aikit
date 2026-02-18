"""Email sending service using SMTP."""
import hmac
import hashlib
import logging
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from app.settings import settings

logger = logging.getLogger(__name__)


def generate_reset_token(email: str) -> str:
    """
    Generate an HMAC-signed password reset token.

    Token format: {email}:{timestamp}:{signature}
    Signature = HMAC-SHA256(SECRET_KEY, email + timestamp)
    """
    timestamp = str(int(time.time()))
    message = f"{email}:{timestamp}"
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{email}:{timestamp}:{signature}"


def verify_reset_token(token: str, max_age_seconds: int = 3600) -> Optional[str]:
    """
    Verify an HMAC-signed password reset token.

    Returns the email if valid, None if invalid or expired.
    """
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None

        email, timestamp_str, signature = parts
        timestamp = int(timestamp_str)

        # Check expiry
        if time.time() - timestamp > max_age_seconds:
            return None

        # Verify signature
        message = f"{email}:{timestamp_str}"
        expected_signature = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return None

        return email
    except (ValueError, TypeError):
        return None


def send_reset_email(to_email: str, reset_url: str) -> bool:
    """
    Send a password reset email.

    Returns True if sent successfully, False otherwise.
    """
    if not settings.SMTP_HOST or not settings.SMTP_FROM_EMAIL:
        logger.warning("SMTP not configured, cannot send reset email")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset - AI Toolkit"
    msg["From"] = settings.SMTP_FROM_EMAIL
    msg["To"] = to_email

    text_body = f"""Password Reset Request

You requested a password reset for your AI Toolkit account.

Click the link below to reset your password (valid for 1 hour):
{reset_url}

If you did not request this, please ignore this email.
"""

    html_body = f"""
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f8fafc; border-radius: 8px; padding: 32px; text-align: center;">
        <h2 style="color: #1e40af; margin-bottom: 16px;">Password Reset</h2>
        <p style="color: #4b5563; margin-bottom: 24px;">
            You requested a password reset for your AI Toolkit account.
        </p>
        <a href="{reset_url}"
           style="display: inline-block; background-color: #3b82f6; color: white; padding: 12px 32px; border-radius: 6px; text-decoration: none; font-weight: 600;">
            Reset Password
        </a>
        <p style="color: #9ca3af; font-size: 14px; margin-top: 24px;">
            This link is valid for 1 hour. If you did not request this, please ignore this email.
        </p>
    </div>
</body>
</html>
"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        if settings.SMTP_USE_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)

        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

        server.sendmail(settings.SMTP_FROM_EMAIL, to_email, msg.as_string())
        server.quit()

        logger.info(f"Password reset email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send reset email to {to_email}: {e}")
        return False
