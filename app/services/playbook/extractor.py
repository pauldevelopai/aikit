"""LLM-based extraction of playbook content from scraped sources.

IMPORTANT: All extracted content must be grounded in the scraped sources.
The LLM is used to extract and synthesize information from real sources,
not to generate fictional content.
"""
import json
import logging
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from app.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class ExtractedPlaybook:
    """Extracted playbook content from sources."""
    best_use_cases: str | None
    implementation_steps: str | None
    common_mistakes: str | None
    privacy_notes: str | None
    replaces_improves: str | None
    key_features: list[str]
    pricing_summary: str | None
    integration_notes: str | None
    source_citations: dict[str, list[str]]  # section -> list of source URLs that contributed


EXTRACTION_SYSTEM_PROMPT = """You are an expert at extracting and synthesizing information from web content to create practical implementation guides for newsrooms.

Your task is to analyze the provided source content and extract ONLY information that is directly present or clearly implied in the sources. DO NOT invent, fabricate, or assume information not in the sources.

CRITICAL RULES:
1. ONLY include information you can trace back to the provided sources
2. If information for a section is not found in the sources, return null for that section
3. For each piece of information, mentally note which source it came from
4. Write for a newsroom audience - journalists, editors, and media organizations
5. Be specific and practical, not generic or vague
6. Include concrete examples when found in sources
7. Preserve important caveats, limitations, and warnings from the sources

You must respond with a JSON object containing the following fields:
- best_use_cases: string or null - Best newsroom use cases for this tool (from real examples or documentation)
- implementation_steps: string or null - Step-by-step how a newsroom would implement this tool
- common_mistakes: string or null - Common mistakes, risks, or pitfalls mentioned in the sources
- privacy_notes: string or null - Privacy, source protection, and security notes relevant to journalism
- replaces_improves: string or null - What workflows or tools this replaces or improves
- key_features: array of strings - Key features particularly relevant to newsrooms
- pricing_summary: string or null - Pricing information relevant to newsroom budgets
- integration_notes: string or null - Integration with common newsroom tools (CMS, workflow tools, etc.)
- source_citations: object - Maps each non-null section name to array of source URLs that contributed

Be thorough but only include what's supported by the sources."""


EXTRACTION_USER_PROMPT = """Analyze the following scraped content from {tool_name}'s website and related pages to extract newsroom-relevant guidance.

TOOL: {tool_name}
TOOL URL: {tool_url}
TOOL DESCRIPTION: {tool_description}

SCRAPED SOURCES:
{sources_content}

Extract information from these sources to create a newsroom implementation playbook. Remember:
- ONLY include information found in the sources
- Return null for sections where no relevant information was found
- Be specific and practical for newsroom use

Respond with a JSON object."""


class PlaybookExtractor:
    """Extracts playbook content from scraped sources using LLM."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4000,
    ):
        """Initialize the extractor.

        Args:
            model: OpenAI model to use (default from settings)
            temperature: Lower temperature for more factual extraction
            max_tokens: Maximum tokens in response
        """
        self.model = model or settings.OPENAI_CHAT_MODEL
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)

    def _format_sources(self, sources: list[dict]) -> str:
        """Format scraped sources for the prompt.

        Args:
            sources: List of source dicts with url, title, extracted_content, source_type

        Returns:
            Formatted string of all sources
        """
        parts = []
        for i, source in enumerate(sources, 1):
            url = source.get("url", "Unknown URL")
            title = source.get("title", "Untitled")
            source_type = source.get("source_type", "unknown")
            content = source.get("extracted_content", "")

            # Truncate long content
            if len(content) > 3000:
                content = content[:3000] + "... [truncated]"

            parts.append(f"""
---
SOURCE {i}:
URL: {url}
Title: {title}
Type: {source_type}
Content:
{content}
---""")

        return "\n".join(parts)

    def _parse_response(self, response_text: str) -> dict[str, Any]:
        """Parse LLM response to extract JSON.

        Args:
            response_text: Raw response from LLM

        Returns:
            Parsed JSON dict
        """
        # Try to find JSON in the response
        text = response_text.strip()

        # If wrapped in markdown code block
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last lines (```json and ```)
            json_lines = []
            in_json = False
            for line in lines:
                if line.startswith("```") and not in_json:
                    in_json = True
                    continue
                elif line.startswith("```") and in_json:
                    break
                elif in_json:
                    json_lines.append(line)
            text = "\n".join(json_lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse extraction response: {e}")
            logger.debug(f"Response text: {text}")
            return {}

    def extract(
        self,
        tool_name: str,
        tool_url: str,
        tool_description: str,
        sources: list[dict],
    ) -> ExtractedPlaybook:
        """Extract playbook content from scraped sources.

        Args:
            tool_name: Name of the tool
            tool_url: Tool's main URL
            tool_description: Brief description of the tool
            sources: List of scraped source dicts

        Returns:
            ExtractedPlaybook with extracted content
        """
        if not sources:
            logger.warning(f"No sources provided for {tool_name}, returning empty playbook")
            return ExtractedPlaybook(
                best_use_cases=None,
                implementation_steps=None,
                common_mistakes=None,
                privacy_notes=None,
                replaces_improves=None,
                key_features=[],
                pricing_summary=None,
                integration_notes=None,
                source_citations={},
            )

        # Format sources for prompt
        sources_content = self._format_sources(sources)

        # Build prompt
        user_prompt = EXTRACTION_USER_PROMPT.format(
            tool_name=tool_name,
            tool_url=tool_url,
            tool_description=tool_description or "No description available",
            sources_content=sources_content,
        )

        try:
            # Call OpenAI
            completion = self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ]
            )

            response_text = completion.choices[0].message.content
            parsed = self._parse_response(response_text)

            return ExtractedPlaybook(
                best_use_cases=parsed.get("best_use_cases"),
                implementation_steps=parsed.get("implementation_steps"),
                common_mistakes=parsed.get("common_mistakes"),
                privacy_notes=parsed.get("privacy_notes"),
                replaces_improves=parsed.get("replaces_improves"),
                key_features=parsed.get("key_features", []),
                pricing_summary=parsed.get("pricing_summary"),
                integration_notes=parsed.get("integration_notes"),
                source_citations=parsed.get("source_citations", {}),
            )

        except Exception as e:
            logger.error(f"Error extracting playbook for {tool_name}: {e}")
            raise


class PlaybookEnricher:
    """Enriches existing playbook content with additional sources."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.1,
    ):
        self.model = model or settings.OPENAI_CHAT_MODEL
        self.temperature = temperature
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)

    def enrich_section(
        self,
        section_name: str,
        existing_content: str | None,
        new_sources: list[dict],
        tool_name: str,
    ) -> str | None:
        """Enrich a specific playbook section with new sources.

        Args:
            section_name: Name of the section to enrich
            existing_content: Current section content (may be None)
            new_sources: New sources to incorporate
            tool_name: Name of the tool

        Returns:
            Updated section content, or None if no relevant info found
        """
        if not new_sources:
            return existing_content

        sources_text = "\n\n".join([
            f"Source ({s.get('source_type', 'unknown')}): {s.get('url', 'Unknown')}\n{s.get('extracted_content', '')[:2000]}"
            for s in new_sources
        ])

        prompt = f"""You are updating the "{section_name}" section of a newsroom playbook for {tool_name}.

EXISTING CONTENT:
{existing_content or "(No existing content)"}

NEW SOURCES TO INCORPORATE:
{sources_text}

Update the section to incorporate any new relevant information from these sources. If the new sources don't add anything relevant to this section, return the existing content unchanged.

RULES:
1. Only include information from the sources
2. Maintain the practical, newsroom-focused tone
3. If existing content is good and sources add nothing new, keep existing content
4. Return null if there's no content for this section

Respond with just the updated section text (or null)."""

        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=1500,
                messages=[
                    {"role": "system", "content": "You enrich playbook sections with information from new sources. Be factual and source-grounded."},
                    {"role": "user", "content": prompt}
                ]
            )

            result = completion.choices[0].message.content.strip()
            if result.lower() == "null" or result.lower() == "none":
                return existing_content
            return result

        except Exception as e:
            logger.error(f"Error enriching section {section_name}: {e}")
            return existing_content
