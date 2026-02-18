"""CLI tool for ingesting documents."""
import argparse
import os
import sys

from app.db import SessionLocal
from app.services.ingestion import ingest_document


def main():
    """Main CLI entrypoint for document ingestion."""
    parser = argparse.ArgumentParser(description='Ingest a DOCX document into the toolkit database')
    parser.add_argument('--file', required=True, help='Path to DOCX file')
    parser.add_argument('--version', required=True, help='Version tag for this document')
    parser.add_argument('--no-embeddings', action='store_true', help='Skip creating embeddings')

    args = parser.parse_args()

    # Validate file exists
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    if not args.file.endswith('.docx'):
        print(f"Error: File must be a .docx file: {args.file}")
        sys.exit(1)

    # Get filename
    source_filename = os.path.basename(args.file)

    print(f"Ingesting document: {source_filename}")
    print(f"Version tag: {args.version}")
    print(f"Create embeddings: {not args.no_embeddings}")
    print()

    # Ingest document
    db = SessionLocal()
    try:
        doc = ingest_document(
            db=db,
            file_path=args.file,
            version_tag=args.version,
            source_filename=source_filename,
            create_embeddings=not args.no_embeddings
        )

        print(f"✅ Successfully ingested document")
        print(f"   Document ID: {doc.id}")
        print(f"   Version: {doc.version_tag}")
        print(f"   Chunks created: {doc.chunk_count}")
        print(f"   Upload date: {doc.upload_date}")

        # Count chunks with embeddings
        from app.models.toolkit import ToolkitChunk
        chunks_with_embeddings = db.query(ToolkitChunk).filter(
            ToolkitChunk.document_id == doc.id,
            ToolkitChunk.embedding.isnot(None)
        ).count()
        print(f"   Chunks with embeddings: {chunks_with_embeddings}")

    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()


if __name__ == '__main__':
    main()
