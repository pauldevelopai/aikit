"""Create admin user and run kit ingestion."""
import sys
from app.db import SessionLocal
from app.services.auth import create_user

db = SessionLocal()
try:
    user = create_user(db, email="admin@toolkit.ai", username="admin", password="Admin2025!")
    user.is_admin = True
    db.commit()
    print(f"Admin created: {user.id}")
except ValueError as e:
    print(f"User may already exist: {e}")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
finally:
    db.close()
