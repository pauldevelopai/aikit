# ToolkitRAG

AI Toolkit Learning Platform - A production-ready web application built with FastAPI and PostgreSQL.

## Local Run

### Prerequisites
- Docker and Docker Compose installed and running
- No additional dependencies required

### Start the Application

```bash
# Navigate to project directory
cd aitools

# Start PostgreSQL + Application (builds on first run)
docker compose up --build
```

The application will:
1. Wait for PostgreSQL to be ready
2. Run Alembic migrations automatically
3. Start the FastAPI application on port 8000

### Verify Installation

```bash
# Check health endpoint
curl http://localhost:8000/health

# Check database connectivity
curl http://localhost:8000/ready

# Open in browser
open http://localhost:8000
```

### Run Tests

```bash
# Run full test suite
docker compose run --rm app pytest

# Run with verbose output
docker compose run --rm app pytest -v

# Run specific test file
docker compose run --rm app pytest tests/test_health.py
```

### Stop the Application

```bash
# Stop containers
docker compose down

# Stop and remove volumes (clears database)
docker compose down -v
```

## Endpoints

### Public Endpoints
- **Homepage**: http://localhost:8000
- **Health Check**: http://localhost:8000/health
- **Readiness Check**: http://localhost:8000/ready (verifies DB connectivity)

### Admin Endpoints
- **Ingest Document**: http://localhost:8000/admin/ingest
- **List Documents**: http://localhost:8000/admin/documents

### RAG API Endpoints
- **Search**: `POST /api/rag/search` - Vector similarity search
- **Answer**: `POST /api/rag/answer` - RAG-based Q&A with citations

## Project Structure

```
aitools/
├── app/
│   ├── main.py           # FastAPI application
│   ├── settings.py       # Configuration
│   ├── db.py             # Database session
│   ├── models/           # SQLAlchemy models
│   ├── routers/          # API routes
│   │   └── health.py     # Health endpoints
│   ├── services/         # Business logic
│   └── templates/        # Jinja2 templates
│       └── index.html    # Homepage
├── docker/
│   ├── Dockerfile        # Application container
│   └── entrypoint.sh     # Startup script
├── alembic/              # Database migrations
│   ├── env.py            # Migration environment
│   └── versions/         # Migration files
├── tests/                # Test suite
│   ├── conftest.py       # Pytest fixtures
│   ├── test_health.py    # Health endpoint tests
│   ├── test_db.py        # Database tests
│   └── test_homepage.py  # Homepage tests
└── docker-compose.yml    # Docker orchestration
```

## Development

### Database Migrations

```bash
# Create a new migration
docker compose run --rm app alembic revision --autogenerate -m "description"

# Apply migrations (done automatically on startup)
docker compose run --rm app alembic upgrade head

# Rollback migration
docker compose run --rm app alembic downgrade -1
```

### View Logs

```bash
# All services
docker compose logs -f

# Application only
docker compose logs -f app

# Database only
docker compose logs -f db
```

### Access Database

```bash
# Connect to PostgreSQL
docker compose exec db psql -U toolkitrag -d toolkitrag
```

## How to Ingest Toolkit

### Method 1: Web UI (Recommended)

1. **Start the application**:
```bash
docker compose up
```

2. **Navigate to admin ingest page**:
```
http://localhost:8000/admin/ingest
```

3. **Fill in the form**:
   - **Version Tag**: Unique identifier (e.g., `v1.0.0`)
   - **DOCX File**: Select your `.docx` file
   - **Admin Password**: Enter password from `.env` (default: `admin123`)
   - **Create Embeddings**: Check if you have OpenAI API key configured

4. **Submit** - The system will:
   - Upload and save the file to `/data/uploads`
   - Parse the DOCX using python-docx
   - Create chunks (800-1200 chars with 150 char overlap)
   - Store chunks in `toolkit_chunks` table
   - Create embeddings if enabled (requires `OPENAI_API_KEY` in `.env`)

5. **View results**:
```
http://localhost:8000/admin/documents
```

### Method 2: CLI

```bash
# Ingest with embeddings
docker compose run --rm app python -m app.ingest \
  --file /path/to/document.docx \
  --version v1.0.0

# Ingest without embeddings (faster, no API key needed)
docker compose run --rm app python -m app.ingest \
  --file /path/to/document.docx \
  --version v1.0.0 \
  --no-embeddings
```

**Example**: Ingest a file from your host machine:
```bash
# Copy file to uploads directory
cp ~/Documents/my-toolkit.docx "./data/uploads/"

# Ingest from container
docker compose run --rm app python -m app.ingest \
  --file /data/uploads/my-toolkit.docx \
  --version v1.0.0
```

### Verify Ingestion

```bash
# Check toolkit_documents table
docker compose exec db psql -U toolkitrag -d toolkitrag -c \
  "SELECT version_tag, chunk_count, upload_date FROM toolkit_documents;"

# Check toolkit_chunks table
docker compose exec db psql -U toolkitrag -d toolkitrag -c \
  "SELECT COUNT(*), AVG(LENGTH(chunk_text)) FROM toolkit_chunks;"

# Check embeddings (if created)
docker compose exec db psql -U toolkitrag -d toolkitrag -c \
  "SELECT COUNT(*) FROM toolkit_chunks WHERE embedding IS NOT NULL;"
```

### Configuration

**Required**:
- `ADMIN_PASSWORD` in `.env` (for web UI)

**Embedding Provider Options**:

The application supports pluggable embedding providers configured via the `EMBEDDING_PROVIDER` environment variable:

1. **OpenAI (Production - Default)**:
   ```bash
   EMBEDDING_PROVIDER=openai
   OPENAI_API_KEY=sk-your-actual-key
   EMBEDDING_MODEL=text-embedding-3-small
   EMBEDDING_DIMENSIONS=1536
   ```
   - Requires valid OpenAI API key
   - Creates real embeddings for production use
   - App fails fast at startup if provider is `openai` but API key is missing

2. **Local Stub (Testing Only)**:
   ```bash
   EMBEDDING_PROVIDER=local_stub
   EMBEDDING_DIMENSIONS=1536
   ```
   - Deterministic hash-based embeddings
   - No external API calls
   - Perfect for CI/CD and testing
   - Same text always produces same embedding

**Fail-Fast Validation**:

The application validates embedding configuration at startup. If `EMBEDDING_PROVIDER=openai` but `OPENAI_API_KEY` is missing or invalid, the application will fail to start with a clear error message:

```
Configuration error: EMBEDDING_PROVIDER is set to 'openai' but OPENAI_API_KEY is not configured.
Either set a valid OPENAI_API_KEY or change EMBEDDING_PROVIDER to 'local_stub' for testing.
```

**Without Embeddings**:

You can still ingest documents without creating embeddings by using the `--no-embeddings` flag in the CLI or unchecking the checkbox in the web UI. Embeddings can be added later without re-ingesting.

## RAG API Usage

### Search Endpoint

Search for similar chunks using vector similarity:

```bash
curl -X POST http://localhost:8000/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the best practices for AI?",
    "top_k": 5,
    "similarity_threshold": 0.7
  }'
```

**Response**:
```json
{
  "results": [
    {
      "chunk_id": "uuid",
      "chunk_text": "Always validate AI outputs...",
      "similarity_score": 0.85,
      "heading": "Best Practices",
      "metadata": {},
      "document_version": "v1.0.0"
    }
  ],
  "count": 5
}
```

**Optional Filters**:
```json
{
  "query": "AI tools",
  "filters": {
    "cluster": "tools",
    "tool_name": "ChatGPT",
    "tags": ["productivity"]
  }
}
```

### Answer Endpoint

Generate answers with citations using RAG:

```bash
curl -X POST http://localhost:8000/api/rag/answer \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the best practices for using AI tools?",
    "top_k": 5,
    "similarity_threshold": 0.7
  }'
```

**Response**:
```json
{
  "answer": "Based on the toolkit, the best practices include...",
  "citations": [
    {
      "chunk_id": "uuid",
      "heading": "Best Practices",
      "snippet": "Always validate AI outputs before...",
      "similarity_score": 0.85,
      "document_version": "v1.0.0",
      "metadata": {}
    }
  ],
  "similarity_scores": [0.85, 0.78, 0.72],
  "refusal": false
}
```

**Refusal Behavior**:

If no chunks meet the similarity threshold or database is empty:
```json
{
  "answer": "Not found in the toolkit",
  "citations": [],
  "similarity_scores": [],
  "refusal": true
}
```

### Configuration

**RAG Settings** (in `.env`):
- `RAG_TOP_K=5` - Number of chunks to retrieve
- `RAG_SIMILARITY_THRESHOLD=0.7` - Minimum similarity score (0-1)
- `RAG_MAX_CONTEXT_LENGTH=4000` - Maximum context characters

**OpenAI Chat Settings** (for answer generation):
- `OPENAI_CHAT_MODEL=gpt-4o-mini` - Model for answer generation
- `OPENAI_CHAT_TEMPERATURE=0.1` - Low temperature for factual responses

**Grounding Rules**:
1. Answers use ONLY information from retrieved chunks
2. All answers include citations with chunk IDs
3. Low similarity triggers refusal with "Not found in the toolkit"
4. Every Q&A is saved to `chat_logs` table

## Tech Stack

- **Backend**: FastAPI 0.109+
- **Database**: PostgreSQL with pgvector extension
- **Migrations**: Alembic
- **Templates**: Jinja2
- **Styling**: Tailwind CSS (CDN)
- **Testing**: Pytest
- **Container**: Docker & Docker Compose

## Troubleshooting

### Port Already in Use

If port 8000 or 5432 is already in use:

```bash
# Find and stop the process using the port
lsof -ti:8000 | xargs kill -9
lsof -ti:5432 | xargs kill -9
```

### Database Connection Issues

```bash
# Rebuild containers
docker compose down -v
docker compose up --build
```

### Clear All Data

```bash
# Remove containers, networks, and volumes
docker compose down -v
```
