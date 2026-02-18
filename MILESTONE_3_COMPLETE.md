# Milestone 3: Embedding Provider Selection - COMPLETE ✅

## Summary

Implemented pluggable embedding provider system with configurable backend selection for production (OpenAI) and testing (local stub).

## Requirements Met

### ✅ Configurable Embedding Provider
- `EMBEDDING_PROVIDER` environment variable: `"openai"` (default) or `"local_stub"`
- Type-safe configuration using Pydantic `Literal` type
- Settings validated at application startup

### ✅ OpenAI Provider (Production)
- Requires `OPENAI_API_KEY` environment variable
- Configurable model via `EMBEDDING_MODEL` (default: `text-embedding-3-small`)
- Configurable dimensions via `EMBEDDING_DIMENSIONS` (default: 1536)
- Creates real embeddings using OpenAI API

### ✅ Local Stub Provider (Testing)
- Deterministic hash-based embeddings using SHA256
- No external API calls required
- Perfect for CI/CD pipelines
- Same input text always produces identical embedding
- Normalized vectors (unit length)

### ✅ Fail-Fast Startup Validation
- Application validates configuration on startup using lifespan events
- Clear error message if `provider=openai` but no API key set:
  ```
  Configuration error: EMBEDDING_PROVIDER is set to 'openai' but OPENAI_API_KEY is not configured.
  Either set a valid OPENAI_API_KEY or change EMBEDDING_PROVIDER to 'local_stub' for testing.
  ```
- Logs provider configuration on successful startup

### ✅ Integration Tests
- Tests use `local_stub` provider by default (no API key required)
- Deterministic embedding generation tests
- Vector normalization tests
- Document embedding creation tests
- Optional OpenAI integration test (skipped without valid API key)
- All tests pass without external dependencies

## Implementation Details

### Files Modified

**Configuration**:
- `app/settings.py` - Added `EMBEDDING_PROVIDER`, `validate_embedding_config()`
- `app/main.py` - Added lifespan event for startup validation
- `.env.example` - Added provider configuration documentation

**Services**:
- `app/services/embeddings.py` - Complete rewrite with provider pattern:
  - `EmbeddingProvider` Protocol
  - `OpenAIEmbeddingProvider` class
  - `LocalStubEmbeddingProvider` class
  - `get_embedding_provider()` factory function
  - Provider-based `create_embeddings_for_document()`

**Tests**:
- `tests/test_embeddings.py` - Comprehensive provider tests:
  - Deterministic embedding tests
  - Normalization validation
  - Provider factory tests
  - Document embedding integration tests
  - OpenAI provider integration test (optional)

**Documentation**:
- `README.md` - Added "Embedding Provider Options" section

### Provider Pattern Design

**Protocol-Based Interface**:
```python
class EmbeddingProvider(Protocol):
    """Protocol for embedding providers."""

    def create_embedding(self, text: str) -> List[float]:
        """Create embedding for text."""
        ...

    @property
    def dimensions(self) -> int:
        """Return embedding dimensions."""
        ...
```

**Why Protocol?**
- Type-safe duck typing
- No runtime overhead
- Easy to add new providers
- Clear interface contract

### Local Stub Implementation

**Hash-Based Deterministic Embeddings**:
```python
def create_embedding(self, text: str) -> List[float]:
    # Hash the text using SHA256
    hash_bytes = hashlib.sha256(text.encode()).digest()

    # Convert hash bytes to floats in range [-1, 1]
    embedding = []
    for i in range(self._dimensions):
        byte_idx = i % len(hash_bytes)
        value = (hash_bytes[byte_idx] / 127.5) - 1.0
        embedding.append(value)

    # Normalize to unit length
    magnitude = sum(x**2 for x in embedding) ** 0.5
    if magnitude > 0:
        embedding = [x / magnitude for x in embedding]

    return embedding
```

**Properties**:
- Same text → same hash → same embedding (deterministic)
- Different text → different hash → different embedding
- Normalized vectors (magnitude = 1.0)
- No external dependencies
- No API calls
- Fast execution

### Startup Validation

**Lifespan Event in main.py**:
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan with startup validation."""
    try:
        settings.validate_embedding_config()
        logger.info(f"Embedding provider: {settings.EMBEDDING_PROVIDER}")
        if settings.EMBEDDING_PROVIDER == "openai":
            logger.info(f"Using OpenAI model: {settings.EMBEDDING_MODEL}")
        elif settings.EMBEDDING_PROVIDER == "local_stub":
            logger.info("Using local stub provider for testing")
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise

    yield
```

**Benefits**:
- Fails immediately on misconfiguration
- Clear error messages
- No silent failures
- Prevents runtime surprises

## Configuration Examples

### Production Setup (OpenAI)

```bash
# .env
EMBEDDING_PROVIDER=openai
OPENAI_API_KEY=sk-proj-your-actual-key-here
EMBEDDING_MODEL=text-embedding-3-small
EMBEDDING_DIMENSIONS=1536
```

### Testing Setup (Local Stub)

```bash
# .env
EMBEDDING_PROVIDER=local_stub
EMBEDDING_DIMENSIONS=1536
```

### CI/CD Setup

```bash
# No OPENAI_API_KEY required
EMBEDDING_PROVIDER=local_stub
```

## Test Coverage

### Unit Tests

- `test_local_stub_provider_deterministic()` - Same text produces same embedding
- `test_local_stub_provider_normalized()` - Vectors are normalized
- `test_local_stub_provider_dimensions()` - Respects custom dimensions
- `test_get_embedding_provider_local_stub()` - Factory returns correct provider
- `test_get_embedding_provider_openai_requires_key()` - Fails without API key

### Integration Tests

- `test_create_embedding_with_local_stub()` - End-to-end embedding creation
- `test_create_embeddings_for_document()` - Document-level embedding generation
- `test_ingest_with_embeddings_local_stub()` - Full ingestion pipeline
- `test_openai_provider_integration()` - OpenAI API test (requires key, optional)

### Existing Tests (Unaffected)

- All ingestion tests continue to pass
- No changes required (already using `create_embeddings=False`)
- No external dependencies in test suite

## Running Tests

```bash
# Run all tests (no API key required)
docker compose run --rm app pytest

# Run only embedding tests
docker compose run --rm app pytest tests/test_embeddings.py

# Run with verbose output
docker compose run --rm app pytest tests/test_embeddings.py -v

# Run including OpenAI integration test (requires valid API key)
docker compose run --rm app pytest tests/test_embeddings.py -v
```

## Usage Examples

### Using OpenAI Provider

```python
from app.services.embeddings import get_embedding_provider

# Get configured provider
provider = get_embedding_provider()

# Create embedding
embedding = provider.create_embedding("What is the toolkit about?")
# Returns: [0.123, -0.456, ...] (1536 dimensions from OpenAI)
```

### Using Local Stub Provider

```python
from app.services.embeddings import LocalStubEmbeddingProvider

# Create local stub
provider = LocalStubEmbeddingProvider(dimensions=1536)

# Create embedding
embedding = provider.create_embedding("Test content")
# Returns: [0.123, -0.456, ...] (deterministic, same every time)

# Same text produces same embedding
embedding2 = provider.create_embedding("Test content")
assert embedding == embedding2  # ✅ True
```

### Document Ingestion

```bash
# With OpenAI embeddings
EMBEDDING_PROVIDER=openai docker compose run --rm app python -m app.ingest \
  --file /data/uploads/toolkit.docx \
  --version v1.0.0

# With local stub embeddings (testing)
EMBEDDING_PROVIDER=local_stub docker compose run --rm app python -m app.ingest \
  --file /data/uploads/toolkit.docx \
  --version v1.0.0

# Without embeddings
docker compose run --rm app python -m app.ingest \
  --file /data/uploads/toolkit.docx \
  --version v1.0.0 \
  --no-embeddings
```

## Acceptance Criteria Verification

✅ **Provider configurable by env**: `EMBEDDING_PROVIDER` in `.env`

✅ **OpenAI provider requires API key**: Validated at startup, fails fast

✅ **Local stub for testing**: Deterministic, no external calls

✅ **Fail-fast startup validation**: Clear error messages

✅ **Tests work without API key**: All tests pass with `local_stub`

✅ **Integration test path**: Tests chunking, storage, and embeddings

## Environment Variables

**Required**:
- `EMBEDDING_PROVIDER` - Provider type: `"openai"` or `"local_stub"`

**Conditional** (required if `EMBEDDING_PROVIDER=openai`):
- `OPENAI_API_KEY` - OpenAI API key (e.g., `sk-proj-...`)

**Optional**:
- `EMBEDDING_MODEL` - OpenAI model (default: `text-embedding-3-small`)
- `EMBEDDING_DIMENSIONS` - Vector dimensions (default: 1536)

## Future Enhancements

**Additional Providers** (easy to add):
- Sentence Transformers (local, no API)
- Cohere embeddings
- Azure OpenAI
- Hugging Face Inference API

**Example - Adding a new provider**:
```python
class SentenceTransformerProvider:
    def __init__(self, model_name: str, dimensions: int):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)
        self._dimensions = dimensions

    def create_embedding(self, text: str) -> List[float]:
        return self.model.encode(text).tolist()

    @property
    def dimensions(self) -> int:
        return self._dimensions
```

Then update `get_embedding_provider()`:
```python
elif provider_type == "sentence_transformers":
    return SentenceTransformerProvider(
        model_name=settings.ST_MODEL_NAME,
        dimensions=settings.EMBEDDING_DIMENSIONS
    )
```

## Next Steps

With pluggable embedding providers complete, ready for:
- **Milestone 4**: RAG retrieval + answer flow with strict grounding
- **Milestone 5**: Citation system and answer grounding
- **Milestone 6**: Strategy planning and feedback loops

## Definition of Done

- [x] `EMBEDDING_PROVIDER` env variable with `Literal["openai", "local_stub"]`
- [x] OpenAI provider requires `OPENAI_API_KEY`
- [x] Local stub provider with deterministic embeddings
- [x] Fail-fast startup validation with clear errors
- [x] Protocol-based provider interface
- [x] Normalized embeddings from local stub
- [x] Provider factory function with validation
- [x] Tests use `local_stub` by default
- [x] Integration tests for both providers
- [x] Optional OpenAI integration test
- [x] Updated `.env.example` with provider settings
- [x] Updated README with provider documentation
- [x] Startup logging for provider configuration
- [x] No breaking changes to existing ingestion
