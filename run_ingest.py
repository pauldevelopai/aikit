"""Run kit ingestion into production database."""
from app.db import SessionLocal
from app.services.ingestion import ingest_from_kit

db = SessionLocal()
try:
    print("Starting kit ingestion...")
    doc = ingest_from_kit(
        db=db,
        version_tag="kit-v1",
        create_embeddings=True
    )
    print(f"Ingestion complete!")
    print(f"Document ID: {doc.id}")
    print(f"Chunks created: {doc.chunk_count}")
except Exception as e:
    print(f"Error during ingestion: {e}")
    import traceback
    traceback.print_exc()
finally:
    db.close()
