"""Playbook generation pipeline.

Orchestrates scraping sources and extracting newsroom guidance.
"""
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models import DiscoveredTool, ToolPlaybook, PlaybookSource
from app.services.playbook.scraper import PlaybookScraper, ScrapedContent
from app.services.playbook.extractor import PlaybookExtractor, ExtractedPlaybook

logger = logging.getLogger(__name__)


def _guess_source_urls(tool: DiscoveredTool) -> list[tuple[str, str]]:
    """Guess potential useful URLs from a tool's main URL.

    Args:
        tool: The discovered tool

    Returns:
        List of (url, source_type) tuples to try scraping
    """
    urls = []
    base_url = tool.url.rstrip("/")

    # Always include the main URL
    urls.append((base_url, "official_docs"))

    # Common documentation/help paths
    common_paths = [
        ("/docs", "official_docs"),
        ("/documentation", "official_docs"),
        ("/help", "help_page"),
        ("/support", "help_page"),
        ("/faq", "help_page"),
        ("/about", "official_docs"),
        ("/features", "official_docs"),
        ("/pricing", "official_docs"),
        ("/blog", "blog_post"),
        ("/news", "blog_post"),
        ("/changelog", "changelog"),
        ("/updates", "changelog"),
        ("/getting-started", "tutorial"),
        ("/quickstart", "tutorial"),
        ("/use-cases", "case_study"),
        ("/customers", "case_study"),
        ("/case-studies", "case_study"),
        ("/privacy", "official_docs"),
        ("/security", "official_docs"),
        ("/api", "api_docs"),
        ("/integrations", "official_docs"),
    ]

    for path, source_type in common_paths:
        urls.append((f"{base_url}{path}", source_type))

    # Add docs_url if available and different
    if tool.docs_url and tool.docs_url != tool.url:
        urls.append((tool.docs_url, "official_docs"))

    # Add pricing_url if available
    if tool.pricing_url:
        urls.append((tool.pricing_url, "official_docs"))

    return urls


async def _scrape_and_discover(
    scraper: PlaybookScraper,
    tool: DiscoveredTool,
    max_sources: int = 10,
) -> list[ScrapedContent]:
    """Scrape initial URLs and discover additional related pages.

    Args:
        scraper: The scraper instance
        tool: The discovered tool
        max_sources: Maximum number of sources to scrape

    Returns:
        List of successfully scraped content
    """
    results = []
    scraped_urls = set()

    # Get initial URLs to try
    urls_to_try = _guess_source_urls(tool)

    # Scrape initial URLs
    for url, source_type in urls_to_try[:max_sources]:
        if url in scraped_urls:
            continue

        result = await scraper.scrape_url(url)
        scraped_urls.add(url)

        if result.success:
            # Attach source_type to result
            result.__dict__['source_type'] = source_type
            results.append(result)

            # Discover related URLs from main page
            if url == tool.url and result.raw_content:
                soup = BeautifulSoup(result.raw_content, 'html.parser')
                related = scraper.discover_related_urls(url, soup)

                # Add discovered URLs to our list
                for related_url, related_type in related:
                    if related_url not in scraped_urls and len(urls_to_try) < max_sources * 2:
                        urls_to_try.append((related_url, related_type))

        # Stop if we have enough
        if len(results) >= max_sources:
            break

    return results


async def generate_playbook(
    db: Session,
    tool_id: str,
    max_sources: int = 10,
    regenerate: bool = False,
) -> ToolPlaybook:
    """Generate a newsroom playbook for a discovered tool.

    This is the main entry point for playbook generation.

    Args:
        db: Database session
        tool_id: UUID of the discovered tool
        max_sources: Maximum number of sources to scrape
        regenerate: If True, regenerate even if playbook exists

    Returns:
        The created/updated ToolPlaybook

    Raises:
        ValueError: If tool not found
    """
    # Get the tool
    tool = db.query(DiscoveredTool).filter(DiscoveredTool.id == tool_id).first()
    if not tool:
        raise ValueError(f"Tool not found: {tool_id}")

    # Check for existing playbook
    existing = db.query(ToolPlaybook).filter(
        ToolPlaybook.discovered_tool_id == tool_id
    ).first()

    if existing and not regenerate:
        logger.info(f"Playbook already exists for {tool.name}, skipping")
        return existing

    if existing and regenerate:
        # Delete old sources
        db.query(PlaybookSource).filter(
            PlaybookSource.playbook_id == existing.id
        ).delete()
        playbook = existing
        playbook.status = "generating"
    else:
        # Create new playbook
        playbook = ToolPlaybook(
            discovered_tool_id=tool.id,
            status="generating",
        )
        db.add(playbook)

    db.commit()
    db.refresh(playbook)

    logger.info(f"Generating playbook for {tool.name} ({tool.url})")

    # Initialize services
    scraper = PlaybookScraper()
    extractor = PlaybookExtractor()

    try:
        # Scrape sources
        scraped_results = await _scrape_and_discover(scraper, tool, max_sources)

        if not scraped_results:
            logger.warning(f"No sources scraped for {tool.name}")
            playbook.status = "draft"
            playbook.source_count = 0
            db.commit()
            return playbook

        # Save scraped sources
        sources_for_extraction = []
        for result in scraped_results:
            source = PlaybookSource(
                playbook_id=playbook.id,
                url=result.url,
                source_type=getattr(result, 'source_type', 'official_docs'),
                title=result.title,
                raw_content=result.raw_content,
                extracted_content=result.extracted_content,
                content_hash=result.content_hash,
                scraped_at=result.scraped_at or datetime.now(timezone.utc),
                scrape_status="success" if result.success else "failed",
                scrape_error=result.error,
                is_primary=(result.url == tool.url),
            )
            db.add(source)

            if result.success and result.extracted_content:
                sources_for_extraction.append({
                    "url": result.url,
                    "title": result.title,
                    "extracted_content": result.extracted_content,
                    "source_type": getattr(result, 'source_type', 'official_docs'),
                })

        db.commit()

        # Extract playbook content
        if sources_for_extraction:
            extracted = extractor.extract(
                tool_name=tool.name,
                tool_url=tool.url,
                tool_description=tool.description or "",
                sources=sources_for_extraction,
            )

            # Update playbook with extracted content
            playbook.best_use_cases = extracted.best_use_cases
            playbook.implementation_steps = extracted.implementation_steps
            playbook.common_mistakes = extracted.common_mistakes
            playbook.privacy_notes = extracted.privacy_notes
            playbook.replaces_improves = extracted.replaces_improves
            playbook.key_features = extracted.key_features
            playbook.pricing_summary = extracted.pricing_summary
            playbook.integration_notes = extracted.integration_notes
            playbook.generation_model = extractor.model
            playbook.generation_prompt_version = "v1"

            # Update source contributions
            for section, source_urls in extracted.source_citations.items():
                for source in db.query(PlaybookSource).filter(
                    PlaybookSource.playbook_id == playbook.id,
                    PlaybookSource.url.in_(source_urls)
                ).all():
                    contributed = source.contributed_sections or []
                    if section not in contributed:
                        contributed.append(section)
                        source.contributed_sections = contributed

        playbook.source_count = len(scraped_results)
        playbook.status = "draft"
        playbook.generated_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(playbook)

        logger.info(f"Successfully generated playbook for {tool.name} with {len(scraped_results)} sources")
        return playbook

    except Exception as e:
        logger.error(f"Error generating playbook for {tool.name}: {e}")
        playbook.status = "draft"
        playbook.review_notes = f"Generation error: {str(e)}"
        db.commit()
        raise


async def add_sources_to_playbook(
    db: Session,
    playbook_id: str,
    urls: list[str],
    source_type: str = "official_docs",
) -> list[PlaybookSource]:
    """Add additional sources to an existing playbook.

    Args:
        db: Database session
        playbook_id: UUID of the playbook
        urls: List of URLs to scrape and add
        source_type: Type of sources being added

    Returns:
        List of created PlaybookSource records
    """
    playbook = db.query(ToolPlaybook).filter(ToolPlaybook.id == playbook_id).first()
    if not playbook:
        raise ValueError(f"Playbook not found: {playbook_id}")

    scraper = PlaybookScraper()
    created_sources = []

    for url in urls:
        # Check if URL already exists for this playbook
        existing = db.query(PlaybookSource).filter(
            PlaybookSource.playbook_id == playbook_id,
            PlaybookSource.url == url
        ).first()

        if existing:
            logger.info(f"Source already exists: {url}")
            continue

        result = await scraper.scrape_url(url)

        source = PlaybookSource(
            playbook_id=playbook.id,
            url=result.url,
            source_type=source_type,
            title=result.title,
            raw_content=result.raw_content,
            extracted_content=result.extracted_content,
            content_hash=result.content_hash,
            scraped_at=result.scraped_at or datetime.now(timezone.utc),
            scrape_status="success" if result.success else "failed",
            scrape_error=result.error,
        )
        db.add(source)
        created_sources.append(source)

    if created_sources:
        playbook.source_count = db.query(PlaybookSource).filter(
            PlaybookSource.playbook_id == playbook_id
        ).count()

    db.commit()
    return created_sources


def get_playbook_with_sources(
    db: Session,
    playbook_id: str,
) -> dict[str, Any] | None:
    """Get a playbook with all its sources.

    Args:
        db: Database session
        playbook_id: UUID of the playbook

    Returns:
        Dict with playbook data and sources, or None if not found
    """
    playbook = db.query(ToolPlaybook).filter(ToolPlaybook.id == playbook_id).first()
    if not playbook:
        return None

    sources = db.query(PlaybookSource).filter(
        PlaybookSource.playbook_id == playbook_id
    ).order_by(PlaybookSource.is_primary.desc(), PlaybookSource.created_at).all()

    return {
        "playbook": playbook,
        "sources": sources,
        "tool": playbook.discovered_tool,
    }
