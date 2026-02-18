# Milestone 4: RAG Retrieval + Answer Flow - COMPLETE ✅

## Summary

Implemented complete RAG (Retrieval-Augmented Generation) system with vector similarity search, grounded answer generation, citation tracking, and refusal behavior.

## Requirements Met

### ✅ `/api/rag/search` Endpoint
- Accepts query text + optional filters (cluster, tool_name, tags)
- Returns top_k chunks with similarity scores and metadata
- Uses pgvector cosine similarity for retrieval
- Supports similarity threshold filtering
- Returns chunk_id, chunk_text, similarity_score, heading, metadata, document_version

### ✅ `/api/rag/answer` Endpoint
- Retrieves relevant chunks using vector search
- Generates answer using ONLY retrieved chunk text
- Returns answer + structured citations JSON
- Citation format: `[{chunk_id, heading, snippet, similarity_score, document_version, metadata}]`
- Strict grounding with system prompts enforcing context-only responses

### ✅ Refusal Behavior
- Returns "Not found in the toolkit" if:
  - Similarity scores below threshold
  - No chunks found in database
  - Empty search results
- Sets `refusal: true` in response
- Returns empty citations array

### ✅ Chat Logs
- Every Q&A saved to `chat_logs` table
- Stores query, answer, citations, similarity_scores, filters_applied
- Indexed by created_at for time-based queries

### ✅ Tests
- `test_search_returns_chunks_after_ingest` - Verifies search works after ingestion
- `test_answer_returns_citations` - Ensures citations reference real chunk IDs
- `test_refusal_when_db_empty` - Tests refusal when database is empty
- `test_refusal_when_threshold_unmet` - Tests refusal when similarity threshold not met
- Additional tests for ordering, filtering, logging, citation format

## Implementation Details

### Files Created

**Models**:
- `app/models/toolkit.py` - Added `ChatLog` model

**Services**:
- `app/services/rag.py` - Complete RAG implementation:
  - `SearchResult` class
  - `search_similar_chunks()` - Vector similarity search
  - `generate_answer()` - RAG answer generation with grounding
  - `rag_answer()` - Complete pipeline (search + generate)
  - `_save_chat_log()` - Persist Q&A to database

**Routers**:
- `app/routers/rag.py` - RAG API endpoints:
  - `POST /api/rag/search` - Search endpoint
  - `POST /api/rag/answer` - Answer endpoint
  - Pydantic models for request/response validation

**Migrations**:
- `alembic/versions/002_add_chat_logs.py` - Chat logs table migration

**Tests**:
- `tests/test_rag.py` - Comprehensive RAG test suite

### Files Modified

**Configuration**:
- `app/settings.py` - Added RAG and OpenAI chat configuration
- `app/main.py` - Included RAG router
- `.env.example` - Added RAG and chat settings

**Documentation**:
- `README.md` - Added "RAG API Usage" section with examples

### Database Schema

**chat_logs Table**:
```sql
CREATE TABLE chat_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query TEXT NOT NULL,
    answer TEXT NOT NULL,
    citations JSONB NOT NULL,
    similarity_score JSONB,
    filters_applied JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX ix_chat_logs_created_at ON chat_logs(created_at);
```

### Vector Similarity Search

**Implementation** (`app/services/rag.py:search_similar_chunks`):

Uses pgvector's cosine distance operator:
```python
query_obj = (
    db.query(
        ToolkitChunk,
        ToolkitDocument.version_tag,
        (1 - ToolkitChunk.embedding.cosine_distance(query_embedding)).label('similarity')
    )
    .join(ToolkitDocument, ToolkitChunk.document_id == ToolkitDocument.id)
    .filter(ToolkitChunk.embedding.isnot(None))
    .filter(ToolkitDocument.is_active == True)
    .order_by('similarity DESC')
    .limit(top_k)
)
```

**Cosine Similarity**:
- Range: 0 (completely different) to 1 (identical)
- Calculated as: `1 - cosine_distance`
- Invariant to magnitude (only considers direction)

### Grounded Answer Generation

**System Prompt**:
```
You are a helpful assistant that answers questions based ONLY on the provided toolkit content.

IMPORTANT RULES:
1. ONLY use information from the provided context below
2. If the answer is not in the context, say "Not found in the toolkit"
3. Always cite which section ([1], [2], etc.) you're referencing
4. Do not add information from your general knowledge
5. Be concise and factual
6. If you're unsure, say so rather than guessing
```

**Context Building**:
```python
context_parts = []
for i, result in enumerate(search_results):
    context_parts.append(
        f"[{i+1}] {result.heading or 'Section'}\n{result.chunk_text}"
    )

context = "\n\n".join(context_parts)
```

**Guardrails**:
- Low temperature (0.1) for factual responses
- Context truncation at `RAG_MAX_CONTEXT_LENGTH` (4000 chars)
- Refusal if no search results
- Citations always include chunk IDs for verification

### Refusal Logic

**Triggers**:
1. Empty search results
2. All similarities below threshold
3. No embeddings in database

**Response**:
```json
{
  "answer": "Not found in the toolkit",
  "citations": [],
  "similarity_scores": [],
  "refusal": true
}
```

### Configuration

**RAG Settings** (`app/settings.py`):
```python
RAG_TOP_K: int = 5  # Number of chunks to retrieve
RAG_SIMILARITY_THRESHOLD: float = 0.7  # Minimum similarity score
RAG_MAX_CONTEXT_LENGTH: int = 4000  # Max characters for context
```

**OpenAI Chat Settings**:
```python
OPENAI_CHAT_MODEL: str = "gpt-4o-mini"
OPENAI_CHAT_TEMPERATURE: float = 0.1  # Low for factual responses
```

## API Endpoint Examples

### Search Endpoint

**Request**:
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
      "chunk_id": "a1b2c3d4-...",
      "chunk_text": "Always validate AI outputs before using in production...",
      "similarity_score": 0.85,
      "heading": "Best Practices",
      "metadata": {"cluster": "practices", "tags": ["validation"]},
      "document_version": "v1.0.0"
    }
  ],
  "count": 5
}
```

**With Filters**:
```json
{
  "query": "AI tools",
  "top_k": 5,
  "filters": {
    "cluster": "tools",
    "tool_name": "ChatGPT",
    "tags": ["productivity"]
  }
}
```

### Answer Endpoint

**Request**:
```bash
curl -X POST http://localhost:8000/api/rag/answer \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the best practices for using AI tools?",
    "top_k": 5,
    "similarity_threshold": 0.7
  }'
```

**Success Response**:
```json
{
  "answer": "Based on the toolkit, the best practices for using AI tools include: 1) Always validate AI outputs before using them in production [1], 2) Use version control for all code changes [1], and 3) Thoroughly review and test AI-generated code [2].",
  "citations": [
    {
      "chunk_id": "a1b2c3d4-...",
      "heading": "Best Practices",
      "snippet": "Always validate AI outputs before using in production. Use version control...",
      "similarity_score": 0.85,
      "document_version": "v1.0.0",
      "metadata": {}
    },
    {
      "chunk_id": "e5f6g7h8-...",
      "heading": "Common Pitfalls",
      "snippet": "Avoid blindly trusting AI-generated code. Always review and test...",
      "similarity_score": 0.78,
      "document_version": "v1.0.0",
      "metadata": {}
    }
  ],
  "similarity_scores": [0.85, 0.78, 0.72, 0.69, 0.65],
  "refusal": false
}
```

**Refusal Response**:
```json
{
  "answer": "Not found in the toolkit",
  "citations": [],
  "similarity_scores": [],
  "refusal": true
}
```

## Test Coverage

### Search Tests
- ✅ Returns chunks after ingestion
- ✅ Filters by similarity threshold
- ✅ Respects top_k parameter
- ✅ Returns results ordered by similarity
- ✅ Supports metadata filters (cluster, tool_name, tags)

### Answer Tests
- ✅ Returns citations with real chunk IDs
- ✅ Verifies chunks exist in database
- ✅ Saves Q&A to chat_logs
- ✅ Citation format includes all required fields

### Refusal Tests
- ✅ Refuses when database is empty
- ✅ Refuses when threshold unmet
- ✅ Returns standard refusal message
- ✅ Sets refusal=true flag
- ✅ Returns empty citations

## Usage Examples

### Search for Similar Content

```python
from app.services.rag import search_similar_chunks

results = search_similar_chunks(
    db=db_session,
    query="What are the best practices for AI?",
    top_k=5,
    similarity_threshold=0.7,
    filters={"cluster": "practices"}
)

for result in results:
    print(f"Score: {result.similarity_score}")
    print(f"Text: {result.chunk_text}")
    print(f"Heading: {result.heading}")
```

### Generate RAG Answer

```python
from app.services.rag import rag_answer

response = rag_answer(
    db=db_session,
    query="How should I validate AI outputs?",
    top_k=5,
    similarity_threshold=0.7
)

print(f"Answer: {response['answer']}")
print(f"Citations: {len(response['citations'])}")
print(f"Refusal: {response['refusal']}")
```

### Query Chat History

```sql
-- Recent Q&A
SELECT query, answer, created_at
FROM chat_logs
ORDER BY created_at DESC
LIMIT 10;

-- Questions with low similarity
SELECT query, similarity_score
FROM chat_logs
WHERE similarity_score->0 < 0.5;

-- Questions by topic
SELECT query, citations->0->'heading' as topic
FROM chat_logs
WHERE citations != '[]'::jsonb;
```

## Acceptance Criteria Verification

✅ **Search returns top_k chunks with scores**
```bash
curl -X POST localhost:8000/api/rag/search -d '{"query":"test","top_k":3}'
# Returns 3 results max with similarity_score field
```

✅ **Answer returns citations with real chunk IDs**
```bash
curl -X POST localhost:8000/api/rag/answer -d '{"query":"test"}'
# Citations include chunk_id that exists in toolkit_chunks table
```

✅ **Refusal when DB empty**
```python
# Empty database
result = rag_answer(db, "test query")
assert result['answer'] == "Not found in the toolkit"
assert result['refusal'] is True
```

✅ **Refusal when threshold unmet**
```python
result = rag_answer(db, "test", similarity_threshold=1.0)
assert result['refusal'] is True
```

✅ **Q&A saved to chat_logs**
```sql
SELECT COUNT(*) FROM chat_logs;
-- Increments after each answer request
```

## Environment Variables

**Required**:
- `OPENAI_API_KEY` - For embeddings and answer generation

**Optional**:
- `RAG_TOP_K` - Number of chunks to retrieve (default: 5)
- `RAG_SIMILARITY_THRESHOLD` - Minimum similarity (default: 0.7)
- `RAG_MAX_CONTEXT_LENGTH` - Max context chars (default: 4000)
- `OPENAI_CHAT_MODEL` - Chat model (default: gpt-4o-mini)
- `OPENAI_CHAT_TEMPERATURE` - Temperature (default: 0.1)

## Security & Best Practices

**Grounding Enforcement**:
- System prompts explicitly restrict to context only
- Low temperature reduces hallucination risk
- Context truncation prevents token overflow
- Citations enable verification

**Error Handling**:
- Validates embedding provider exists
- Catches OpenAI API errors
- Returns HTTP 400 for invalid requests
- Returns HTTP 500 for server errors

**Performance**:
- pgvector index on embeddings (implicit)
- Limit top_k to prevent excessive retrieval
- Context truncation for large results
- Query planning optimized by PostgreSQL

## Limitations & Future Enhancements

**Current Limitations**:
1. No user authentication (planned for Milestone 5)
2. Single document version per query (no multi-version search)
3. No re-ranking beyond cosine similarity
4. No conversation history/context

**Future Enhancements**:
- Hybrid search (keyword + vector)
- Re-ranking with cross-encoder
- Conversation history tracking
- Multi-turn dialogue support
- Query expansion/rewriting
- Answer quality metrics
- A/B testing for prompts

## Next Steps

With RAG retrieval + answer flow complete, ready for:
- **Milestone 5**: Full authentication system with JWT
- **Milestone 6**: Strategy planning and feedback loops
- **Milestone 7**: Advanced features (multi-turn, re-ranking, analytics)

## Definition of Done

- [x] `/api/rag/search` endpoint with filters
- [x] Returns top_k chunks with similarity scores
- [x] `/api/rag/answer` endpoint with grounding
- [x] Returns answer + structured citations
- [x] Citations include chunk_id, heading, snippet, similarity_score
- [x] Refusal behavior when threshold unmet
- [x] Refusal behavior when DB empty
- [x] Refusal returns "Not found in the toolkit"
- [x] Q&A saved to chat_logs table
- [x] Tests verify search returns chunks after ingest
- [x] Tests verify citations reference real chunk IDs
- [x] Tests verify refusal triggers correctly
- [x] pgvector similarity search implemented
- [x] Cosine similarity scoring
- [x] System prompts enforce context-only answers
- [x] Low temperature for factual responses
- [x] Context truncation for large results
- [x] Updated README with API examples
- [x] Updated .env.example with RAG settings
- [x] Migration for chat_logs table
