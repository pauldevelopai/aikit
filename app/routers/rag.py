"""RAG API endpoints."""
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.rag import search_similar_chunks, rag_answer


router = APIRouter(prefix="/api/rag", tags=["RAG"])


# Request/Response Models
class SearchRequest(BaseModel):
    """Search request model."""
    query: str = Field(..., min_length=1, description="Search query text")
    top_k: Optional[int] = Field(5, ge=1, le=20, description="Number of results to return")
    similarity_threshold: Optional[float] = Field(0.0, ge=0.0, le=1.0, description="Minimum similarity score")
    filters: Optional[Dict[str, Any]] = Field(None, description="Optional filters (cluster, tool_name, tags)")


class ChunkResult(BaseModel):
    """Single chunk search result."""
    chunk_id: str
    chunk_text: str
    similarity_score: float
    heading: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    document_version: Optional[str] = None


class SearchResponse(BaseModel):
    """Search response model."""
    results: List[ChunkResult]
    count: int


class AnswerRequest(BaseModel):
    """Answer generation request model."""
    query: str = Field(..., min_length=1, description="Question to answer")
    top_k: Optional[int] = Field(None, ge=1, le=20, description="Number of chunks to retrieve")
    similarity_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Minimum similarity score")
    filters: Optional[Dict[str, Any]] = Field(None, description="Optional filters")


class Citation(BaseModel):
    """Citation model."""
    chunk_id: str
    heading: Optional[str]
    snippet: str
    similarity_score: float
    document_version: Optional[str]
    metadata: Optional[Dict[str, Any]]


class AnswerResponse(BaseModel):
    """Answer response model."""
    answer: str
    citations: List[Citation]
    similarity_scores: List[float]
    refusal: bool = Field(False, description="True if answer was refused due to low similarity")


@router.post("/search", response_model=SearchResponse)
async def search(
    request: SearchRequest,
    db: Session = Depends(get_db)
) -> SearchResponse:
    """
    Search for similar chunks using vector similarity.

    Returns top_k chunks with similarity scores and metadata.
    Supports optional filters for cluster, tool_name, and tags.
    """
    try:
        results = search_similar_chunks(
            db=db,
            query=request.query,
            top_k=request.top_k or 5,
            similarity_threshold=request.similarity_threshold or 0.0,
            filters=request.filters
        )

        chunk_results = [
            ChunkResult(
                chunk_id=r.chunk_id,
                chunk_text=r.chunk_text,
                similarity_score=r.similarity_score,
                heading=r.heading,
                metadata=r.metadata,
                document_version=r.document_version
            )
            for r in results
        ]

        return SearchResponse(
            results=chunk_results,
            count=len(chunk_results)
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.post("/answer", response_model=AnswerResponse)
async def answer(
    request: AnswerRequest,
    db: Session = Depends(get_db)
) -> AnswerResponse:
    """
    Generate answer using RAG with strict grounding.

    Retrieves relevant chunks and generates an answer using ONLY retrieved content.
    Returns answer with citations including chunk_id, heading, snippet, and similarity score.

    Refusal behavior:
    - If similarity below threshold OR no chunks found: returns "Not found in the toolkit" with empty citations
    - Sets refusal=True in response
    """
    try:
        result = rag_answer(
            db=db,
            query=request.query,
            top_k=request.top_k,
            similarity_threshold=request.similarity_threshold,
            filters=request.filters
        )

        citations = [
            Citation(
                chunk_id=c['chunk_id'],
                heading=c['heading'],
                snippet=c['snippet'],
                similarity_score=c['similarity_score'],
                document_version=c['document_version'],
                metadata=c['metadata']
            )
            for c in result['citations']
        ]

        return AnswerResponse(
            answer=result['answer'],
            citations=citations,
            similarity_scores=result['similarity_scores'],
            refusal=result['refusal']
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Answer generation failed: {str(e)}")
