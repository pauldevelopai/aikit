"""Base source protocol and data types for discovery pipeline."""
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from abc import abstractmethod


@dataclass
class RawToolData:
    """Raw tool data from a discovery source."""

    name: str
    url: str
    description: str
    source_url: str  # Attribution link - where we found it

    # Optional fields
    docs_url: str | None = None
    pricing_url: str | None = None
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    last_updated: str | None = None  # Date string from source
    extra_data: dict = field(default_factory=dict)  # Source-specific metadata

    def __post_init__(self):
        """Validate required fields."""
        if not self.name:
            raise ValueError("name is required")
        if not self.url:
            raise ValueError("url is required")
        if not self.source_url:
            raise ValueError("source_url is required for attribution")


@runtime_checkable
class DiscoverySource(Protocol):
    """Protocol for discovery sources."""

    @property
    def name(self) -> str:
        """Human-readable name for this source (e.g., 'GitHub Trending')."""
        ...

    @property
    def source_type(self) -> str:
        """Source type identifier (e.g., 'github', 'producthunt', 'awesome_list', 'directory')."""
        ...

    async def discover(self, config: dict | None = None) -> list[RawToolData]:
        """
        Fetch tools from this source.

        Args:
            config: Optional configuration for this discovery run

        Returns:
            List of discovered tools
        """
        ...


class BaseDiscoverySource:
    """Base class with common functionality for discovery sources."""

    def __init__(self, name: str, source_type: str):
        self._name = name
        self._source_type = source_type

    @property
    def name(self) -> str:
        return self._name

    @property
    def source_type(self) -> str:
        return self._source_type

    @abstractmethod
    async def discover(self, config: dict | None = None) -> list[RawToolData]:
        """Fetch tools from this source."""
        raise NotImplementedError

    def _clean_description(self, description: str | None) -> str:
        """Clean and normalize description text."""
        if not description:
            return ""
        # Remove excessive whitespace
        cleaned = " ".join(description.split())
        # Truncate very long descriptions
        if len(cleaned) > 2000:
            cleaned = cleaned[:1997] + "..."
        return cleaned

    def _extract_tags(self, text: str, categories: list[str] | None = None) -> list[str]:
        """Extract tags from text and categories."""
        tags = set()

        # Add categories as tags
        if categories:
            for cat in categories:
                tags.add(cat.lower().strip())

        # Extract common AI-related keywords
        ai_keywords = [
            "ai", "ml", "machine learning", "deep learning", "neural network",
            "nlp", "natural language", "computer vision", "llm", "gpt", "chatgpt",
            "openai", "anthropic", "claude", "automation", "no-code", "low-code",
            "api", "saas", "open source", "productivity", "writing", "coding",
            "image generation", "text-to-speech", "speech-to-text", "translation",
            "summarization", "content creation", "data analysis", "chatbot"
        ]

        text_lower = text.lower()
        for keyword in ai_keywords:
            if keyword in text_lower:
                tags.add(keyword)

        return list(tags)[:20]  # Limit to 20 tags
