"""Directory scraping discovery sources."""
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.services.discovery.sources import BaseDiscoverySource, RawToolData
from app.settings import settings

logger = logging.getLogger(__name__)

# Check if BeautifulSoup is available
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup not installed. Directory scraping will be limited.")


class DirectorySource(BaseDiscoverySource):
    """Discovers AI tools from curated directories via web scraping."""

    # Directories to scrape
    DIRECTORIES = [
        {
            "name": "There's An AI For That",
            "base_url": "https://theresanaiforthat.com",
            "list_url": "https://theresanaiforthat.com/alphabetical/",
            "type": "theresanaiforthat"
        },
        {
            "name": "Future Tools",
            "base_url": "https://www.futuretools.io",
            "list_url": "https://www.futuretools.io/tools",
            "type": "futuretools"
        }
    ]

    def __init__(self):
        super().__init__(
            name="AI Directories",
            source_type="directory"
        )
        self.rate_limit_delay = getattr(settings, 'DISCOVERY_RATE_LIMIT_DELAY', 2.0)

    async def discover(self, config: dict | None = None) -> list[RawToolData]:
        """
        Discover AI tools from curated directories.

        Config options:
            directories: list[dict] - Directories to scrape (default: DIRECTORIES)
            max_per_directory: int - Max tools per directory (default: 100)
        """
        if not BS4_AVAILABLE:
            logger.error("BeautifulSoup not installed. Install with: pip install beautifulsoup4")
            return []

        config = config or {}
        directories = config.get("directories", self.DIRECTORIES)
        max_per_directory = config.get("max_per_directory", 100)

        tools: list[RawToolData] = []
        seen_urls: set[str] = set()

        async with httpx.AsyncClient(
            timeout=30.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
            follow_redirects=True
        ) as client:
            for directory in directories:
                try:
                    # Respect robots.txt (simplified check)
                    if not await self._check_robots_txt(client, directory["base_url"]):
                        logger.warning(f"Skipping {directory['name']} due to robots.txt")
                        continue

                    # Scrape based on directory type
                    scraper_method = getattr(self, f"_scrape_{directory['type']}", None)
                    if scraper_method:
                        dir_tools = await scraper_method(client, directory, max_per_directory)
                        for tool in dir_tools:
                            if tool.url not in seen_urls:
                                seen_urls.add(tool.url)
                                tools.append(tool)

                    # Respectful delay between directories
                    await asyncio.sleep(self.rate_limit_delay * 2)

                except Exception as e:
                    logger.error(f"Error scraping {directory['name']}: {e}")
                    continue

        logger.info(f"Directories: discovered {len(tools)} tools")
        return tools

    async def _check_robots_txt(self, client: httpx.AsyncClient, base_url: str) -> bool:
        """Check if scraping is allowed by robots.txt."""
        try:
            response = await client.get(f"{base_url}/robots.txt")
            if response.status_code == 200:
                content = response.text.lower()
                # Very basic check - in production, use robotparser
                if "disallow: /" in content and "user-agent: *" in content:
                    # Check if there's an allow for our paths
                    if "allow:" not in content:
                        return False
            return True
        except Exception:
            # If we can't fetch robots.txt, proceed cautiously
            return True

    async def _scrape_theresanaiforthat(
        self,
        client: httpx.AsyncClient,
        directory: dict[str, str],
        max_results: int
    ) -> list[RawToolData]:
        """Scrape There's An AI For That directory."""
        tools: list[RawToolData] = []

        try:
            response = await client.get(directory["list_url"])
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            # Find tool cards (structure may vary)
            tool_cards = soup.select(".tool-card, .ai-tool, [data-tool]")[:max_results]

            for card in tool_cards:
                try:
                    tool = self._parse_taaft_card(card, directory)
                    if tool:
                        tools.append(tool)
                        await asyncio.sleep(self.rate_limit_delay)
                except Exception as e:
                    logger.debug(f"Error parsing tool card: {e}")
                    continue

        except httpx.HTTPStatusError as e:
            logger.error(f"Error fetching {directory['list_url']}: {e}")

        return tools

    def _parse_taaft_card(self, card: Any, directory: dict[str, str]) -> RawToolData | None:
        """Parse a tool card from There's An AI For That."""
        try:
            # Extract name
            name_elem = card.select_one("h3, h4, .tool-name, .title")
            if not name_elem:
                return None
            name = name_elem.get_text(strip=True)

            # Extract URL
            link_elem = card.select_one("a[href]")
            if not link_elem:
                return None

            href = link_elem.get("href", "")
            if href.startswith("/"):
                # Internal link - this is the tool's page on the directory
                source_url = urljoin(directory["base_url"], href)
                # The actual tool URL would need to be fetched from the detail page
                # For now, use the directory page as the source
                url = source_url
            else:
                url = href
                source_url = urljoin(directory["base_url"], href)

            # Extract description
            desc_elem = card.select_one(".description, .tagline, p")
            description = desc_elem.get_text(strip=True) if desc_elem else ""

            # Extract categories
            cat_elems = card.select(".category, .tag, .badge")
            categories = [elem.get_text(strip=True) for elem in cat_elems if elem.get_text(strip=True)]

            # Extract tags
            tags = self._extract_tags(f"{name} {description}", categories)

            return RawToolData(
                name=name,
                url=url,
                description=self._clean_description(description),
                source_url=source_url,
                categories=categories[:5],  # Limit categories
                tags=tags,
                extra_data={
                    "directory": directory["name"],
                    "directory_url": directory["base_url"]
                }
            )
        except Exception as e:
            logger.debug(f"Error parsing TAAFT card: {e}")
            return None

    async def _scrape_futuretools(
        self,
        client: httpx.AsyncClient,
        directory: dict[str, str],
        max_results: int
    ) -> list[RawToolData]:
        """Scrape Future Tools directory."""
        tools: list[RawToolData] = []

        try:
            response = await client.get(directory["list_url"])
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            # Find tool cards
            tool_cards = soup.select(".tool-card, .w-dyn-item, [data-w-id]")[:max_results]

            for card in tool_cards:
                try:
                    tool = self._parse_futuretools_card(card, directory)
                    if tool:
                        tools.append(tool)
                        await asyncio.sleep(self.rate_limit_delay)
                except Exception as e:
                    logger.debug(f"Error parsing Future Tools card: {e}")
                    continue

        except httpx.HTTPStatusError as e:
            logger.error(f"Error fetching {directory['list_url']}: {e}")

        return tools

    def _parse_futuretools_card(self, card: Any, directory: dict[str, str]) -> RawToolData | None:
        """Parse a tool card from Future Tools."""
        try:
            # Extract name
            name_elem = card.select_one("h2, h3, .tool-name, .heading")
            if not name_elem:
                return None
            name = name_elem.get_text(strip=True)

            # Extract URL
            link_elem = card.select_one("a[href*='http'], a.tool-link")
            if not link_elem:
                # Try to find any link
                link_elem = card.select_one("a[href]")

            if not link_elem:
                return None

            href = link_elem.get("href", "")
            if href.startswith("/"):
                source_url = urljoin(directory["base_url"], href)
                url = source_url
            else:
                url = href
                source_url = urljoin(directory["base_url"], card.select_one("a[href^='/']").get("href", "")) if card.select_one("a[href^='/']") else url

            # Skip non-http URLs
            if not url.startswith("http"):
                return None

            # Extract description
            desc_elem = card.select_one(".description, .tool-description, p")
            description = desc_elem.get_text(strip=True) if desc_elem else ""

            # Extract categories/tags
            tag_elems = card.select(".category, .tag, .label, .chip")
            categories = [elem.get_text(strip=True) for elem in tag_elems if elem.get_text(strip=True)]

            # Extract pricing info if visible
            pricing_elem = card.select_one(".pricing, .price, [class*='price']")
            pricing_info = pricing_elem.get_text(strip=True) if pricing_elem else None

            # Extract tags
            tags = self._extract_tags(f"{name} {description}", categories)

            extra_data = {
                "directory": directory["name"],
                "directory_url": directory["base_url"]
            }
            if pricing_info:
                extra_data["pricing_hint"] = pricing_info

            return RawToolData(
                name=name,
                url=url,
                description=self._clean_description(description),
                source_url=source_url,
                categories=categories[:5],
                tags=tags,
                extra_data=extra_data
            )
        except Exception as e:
            logger.debug(f"Error parsing Future Tools card: {e}")
            return None


class GenericDirectorySource(BaseDiscoverySource):
    """Generic directory scraper for custom directories."""

    def __init__(self, name: str, config: dict[str, Any]):
        """
        Initialize generic directory source.

        Config should include:
            base_url: str - Base URL of the directory
            list_url: str - URL of the tools list page
            selectors: dict - CSS selectors for scraping
                card: str - Selector for tool cards
                name: str - Selector for tool name within card
                url: str - Selector for tool URL within card
                description: str - Selector for description
                categories: str - Selector for categories (optional)
        """
        super().__init__(
            name=name,
            source_type="directory"
        )
        self.config = config
        self.rate_limit_delay = getattr(settings, 'DISCOVERY_RATE_LIMIT_DELAY', 2.0)

    async def discover(self, config: dict | None = None) -> list[RawToolData]:
        """Discover tools using configured selectors."""
        if not BS4_AVAILABLE:
            logger.error("BeautifulSoup not installed")
            return []

        config = config or {}
        max_results = config.get("max_results", 100)
        tools: list[RawToolData] = []

        selectors = self.config.get("selectors", {})
        if not selectors:
            logger.error(f"No selectors configured for {self.name}")
            return tools

        async with httpx.AsyncClient(
            timeout=30.0,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; AIToolsBot/1.0)"
            },
            follow_redirects=True
        ) as client:
            try:
                response = await client.get(self.config.get("list_url", ""))
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "html.parser")

                # Find tool cards
                cards = soup.select(selectors.get("card", ".tool"))[:max_results]

                for card in cards:
                    try:
                        tool = self._parse_generic_card(card, selectors)
                        if tool:
                            tools.append(tool)
                            await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logger.debug(f"Error parsing card: {e}")
                        continue

            except Exception as e:
                logger.error(f"Error scraping {self.name}: {e}")

        return tools

    def _parse_generic_card(self, card: Any, selectors: dict[str, str]) -> RawToolData | None:
        """Parse a tool card using configured selectors."""
        try:
            # Extract name
            name_elem = card.select_one(selectors.get("name", "h3"))
            if not name_elem:
                return None
            name = name_elem.get_text(strip=True)

            # Extract URL
            url_elem = card.select_one(selectors.get("url", "a[href]"))
            if not url_elem:
                return None
            url = url_elem.get("href", "")

            if url.startswith("/"):
                url = urljoin(self.config.get("base_url", ""), url)

            if not url.startswith("http"):
                return None

            # Extract description
            desc_elem = card.select_one(selectors.get("description", "p"))
            description = desc_elem.get_text(strip=True) if desc_elem else ""

            # Extract categories
            categories = []
            if selectors.get("categories"):
                cat_elems = card.select(selectors["categories"])
                categories = [elem.get_text(strip=True) for elem in cat_elems]

            # Build source URL
            source_url = self.config.get("list_url", url)

            return RawToolData(
                name=name,
                url=url,
                description=self._clean_description(description),
                source_url=source_url,
                categories=categories[:5],
                tags=self._extract_tags(f"{name} {description}", categories),
                extra_data={
                    "directory": self.name,
                    "directory_url": self.config.get("base_url")
                }
            )
        except Exception as e:
            logger.debug(f"Error in generic parser: {e}")
            return None
