"""Deduplication service for discovered tools."""
import re
import logging
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import NamedTuple

from sqlalchemy.orm import Session

from app.models import DiscoveredTool, ToolMatch
from app.services.discovery.sources import RawToolData

logger = logging.getLogger(__name__)


class MatchResult(NamedTuple):
    """Result of a deduplication match."""
    match_type: str  # "exact_url", "domain", "name_exact", "name_fuzzy", "description_similar"
    match_score: float  # 0.0 - 1.0
    matched_tool_id: str | None  # UUID of matched discovered tool
    matched_kit_slug: str | None  # Slug of matched curated tool
    match_details: dict  # Additional context about the match


def extract_domain(url: str) -> str:
    """
    Extract normalized domain from URL.

    Examples:
        https://www.example.com/path -> example.com
        https://github.com/org/repo -> github.com/org/repo
        http://tool.example.io -> tool.example.io
    """
    try:
        parsed = urlparse(url.lower().strip())
        domain = parsed.netloc

        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]

        # For GitHub, include the org/repo path
        if domain == "github.com":
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                return f"{domain}/{path_parts[0]}/{path_parts[1]}"

        return domain
    except Exception:
        return url.lower().strip()


def normalize_name(name: str) -> str:
    """
    Normalize tool name for comparison.

    Removes common suffixes, punctuation, and converts to lowercase.

    Examples:
        "ChatGPT Plus" -> "chatgpt"
        "AI-Writer Pro" -> "aiwriter"
        "The Tool.io" -> "tool"
    """
    # Lowercase
    normalized = name.lower().strip()

    # Remove common suffixes/prefixes
    remove_words = [
        "ai", "tool", "tools", "app", "io", "pro", "plus", "beta", "the",
        "new", "free", "premium", "enterprise", "studio", "platform", "hub"
    ]

    # Remove punctuation and split
    words = re.sub(r'[^\w\s]', ' ', normalized).split()

    # Filter out common words (but keep at least one word)
    filtered = [w for w in words if w not in remove_words]
    if not filtered and words:
        filtered = [words[0]]

    return "".join(filtered)


def fuzzy_match_score(s1: str, s2: str) -> float:
    """
    Calculate fuzzy match score between two strings.

    Returns a score between 0.0 and 1.0.
    """
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def description_similarity(desc1: str, desc2: str) -> float:
    """
    Calculate description similarity using simple word overlap.

    For more sophisticated matching, consider using embeddings.
    """
    if not desc1 or not desc2:
        return 0.0

    # Tokenize and normalize
    words1 = set(re.sub(r'[^\w\s]', ' ', desc1.lower()).split())
    words2 = set(re.sub(r'[^\w\s]', ' ', desc2.lower()).split())

    # Remove common stop words
    stop_words = {
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "must", "shall", "can", "and", "or", "but",
        "if", "then", "else", "when", "at", "by", "for", "with", "about",
        "against", "between", "into", "through", "during", "before", "after",
        "above", "below", "to", "from", "up", "down", "in", "out", "on", "off",
        "over", "under", "again", "further", "then", "once", "here", "there",
        "where", "why", "how", "all", "each", "few", "more", "most", "other",
        "some", "such", "no", "nor", "not", "only", "own", "same", "so", "than",
        "too", "very", "s", "t", "just", "don", "now", "your", "this", "that",
        "it", "its", "of", "as"
    }

    words1 = words1 - stop_words
    words2 = words2 - stop_words

    if not words1 or not words2:
        return 0.0

    # Calculate Jaccard similarity
    intersection = words1 & words2
    union = words1 | words2

    return len(intersection) / len(union)


def deduplicate_tool(
    db: Session,
    raw_tool: RawToolData,
    existing_tools: list[DiscoveredTool] | None = None,
    kit_tools: list[dict] | None = None
) -> tuple[bool, list[MatchResult], float]:
    """
    Check if a tool is a duplicate and calculate confidence score.

    Args:
        db: Database session
        raw_tool: The raw tool data to check
        existing_tools: List of existing discovered tools to check against
            (if None, will query from database)
        kit_tools: List of curated kit tools to check against
            (if None, will not check curated tools)

    Returns:
        Tuple of:
            - is_duplicate: True if tool is definitely a duplicate
            - matches: List of potential matches found
            - confidence_score: Overall confidence (higher = less likely duplicate)
    """
    matches: list[MatchResult] = []
    is_duplicate = False

    # Extract comparison values
    tool_url = raw_tool.url.lower().strip().rstrip("/")
    tool_domain = extract_domain(raw_tool.url)
    tool_name_normalized = normalize_name(raw_tool.name)

    # Load existing tools if not provided
    if existing_tools is None:
        existing_tools = db.query(DiscoveredTool).filter(
            DiscoveredTool.status != "rejected"
        ).all()

    # 1. Check against existing discovered tools
    for existing in existing_tools:
        existing_url = existing.url.lower().strip().rstrip("/")

        # Exact URL match (100% confidence it's duplicate)
        if tool_url == existing_url:
            matches.append(MatchResult(
                match_type="exact_url",
                match_score=1.0,
                matched_tool_id=str(existing.id),
                matched_kit_slug=None,
                match_details={"matched_url": existing.url}
            ))
            is_duplicate = True
            continue

        # Domain match (90% confidence)
        if tool_domain == existing.url_domain:
            matches.append(MatchResult(
                match_type="domain",
                match_score=0.9,
                matched_tool_id=str(existing.id),
                matched_kit_slug=None,
                match_details={
                    "matched_domain": existing.url_domain,
                    "existing_url": existing.url
                }
            ))
            is_duplicate = True
            continue

        # Exact normalized name match (80% confidence)
        existing_name_normalized = normalize_name(existing.name)
        if tool_name_normalized == existing_name_normalized and tool_name_normalized:
            matches.append(MatchResult(
                match_type="name_exact",
                match_score=0.8,
                matched_tool_id=str(existing.id),
                matched_kit_slug=None,
                match_details={
                    "tool_name": raw_tool.name,
                    "matched_name": existing.name,
                    "normalized": tool_name_normalized
                }
            ))
            continue

        # Fuzzy name match (70% confidence if high similarity)
        if tool_name_normalized and existing_name_normalized:
            distance = levenshtein_distance(tool_name_normalized, existing_name_normalized)
            if distance <= 2 and len(tool_name_normalized) > 3:
                score = 1.0 - (distance / max(len(tool_name_normalized), len(existing_name_normalized)))
                if score >= 0.7:
                    matches.append(MatchResult(
                        match_type="name_fuzzy",
                        match_score=score * 0.7,  # Scale to max 0.7
                        matched_tool_id=str(existing.id),
                        matched_kit_slug=None,
                        match_details={
                            "tool_name": raw_tool.name,
                            "matched_name": existing.name,
                            "levenshtein_distance": distance
                        }
                    ))

        # Description similarity (60% confidence if very similar)
        if raw_tool.description and existing.description:
            desc_score = description_similarity(raw_tool.description, existing.description)
            if desc_score >= 0.6:
                matches.append(MatchResult(
                    match_type="description_similar",
                    match_score=desc_score * 0.6,  # Scale to max 0.6
                    matched_tool_id=str(existing.id),
                    matched_kit_slug=None,
                    match_details={
                        "similarity_score": desc_score,
                        "tool_description_preview": raw_tool.description[:100],
                        "matched_description_preview": existing.description[:100]
                    }
                ))

    # 2. Check against curated kit tools
    if kit_tools:
        for kit_tool in kit_tools:
            kit_url = kit_tool.get("url", "").lower().strip().rstrip("/")
            kit_slug = kit_tool.get("slug", "")
            kit_name = kit_tool.get("name", "")

            # Exact URL match
            if tool_url == kit_url:
                matches.append(MatchResult(
                    match_type="exact_url",
                    match_score=1.0,
                    matched_tool_id=None,
                    matched_kit_slug=kit_slug,
                    match_details={
                        "matched_url": kit_url,
                        "kit_tool_name": kit_name
                    }
                ))
                is_duplicate = True
                continue

            # Domain match
            kit_domain = extract_domain(kit_url) if kit_url else ""
            if tool_domain == kit_domain and kit_domain:
                matches.append(MatchResult(
                    match_type="domain",
                    match_score=0.9,
                    matched_tool_id=None,
                    matched_kit_slug=kit_slug,
                    match_details={
                        "matched_domain": kit_domain,
                        "kit_tool_name": kit_name
                    }
                ))
                is_duplicate = True
                continue

            # Exact normalized name match
            kit_name_normalized = normalize_name(kit_name)
            if tool_name_normalized == kit_name_normalized and tool_name_normalized:
                matches.append(MatchResult(
                    match_type="name_exact",
                    match_score=0.8,
                    matched_tool_id=None,
                    matched_kit_slug=kit_slug,
                    match_details={
                        "tool_name": raw_tool.name,
                        "kit_tool_name": kit_name,
                        "normalized": tool_name_normalized
                    }
                ))

    # Calculate confidence score
    # Higher score = more confident this is a NEW tool (not duplicate)
    if is_duplicate:
        confidence_score = 0.0
    elif matches:
        # Take the highest match score and invert it
        max_match_score = max(m.match_score for m in matches)
        confidence_score = 1.0 - max_match_score
    else:
        # No matches = high confidence it's new
        confidence_score = 0.95

    return is_duplicate, matches, confidence_score


def create_match_records(
    db: Session,
    tool: DiscoveredTool,
    matches: list[MatchResult]
) -> list[ToolMatch]:
    """
    Create ToolMatch records for potential duplicates.

    Args:
        db: Database session
        tool: The discovered tool
        matches: List of match results from deduplication

    Returns:
        List of created ToolMatch records
    """
    records: list[ToolMatch] = []

    for match in matches:
        # Skip very low confidence matches
        if match.match_score < 0.5:
            continue

        record = ToolMatch(
            tool_id=tool.id,
            matched_tool_id=match.matched_tool_id,
            matched_kit_slug=match.matched_kit_slug,
            match_type=match.match_type,
            match_score=match.match_score,
            match_details=match.match_details
        )
        db.add(record)
        records.append(record)

    return records
