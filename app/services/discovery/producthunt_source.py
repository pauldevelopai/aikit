"""Product Hunt discovery source."""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

import httpx

from app.services.discovery.sources import BaseDiscoverySource, RawToolData
from app.settings import settings

logger = logging.getLogger(__name__)


class ProductHuntSource(BaseDiscoverySource):
    """Discovers AI tools from Product Hunt."""

    GRAPHQL_ENDPOINT = "https://api.producthunt.com/v2/api/graphql"

    # Product Hunt topics/tags related to AI
    AI_TOPICS = [
        "artificial-intelligence",
        "machine-learning",
        "ai",
        "chatgpt",
        "generative-ai",
        "llm",
        "ai-tools",
        "automation",
        "no-code",
        "productivity",
        "developer-tools"
    ]

    def __init__(self):
        super().__init__(
            name="Product Hunt",
            source_type="producthunt"
        )
        self.api_key = getattr(settings, 'PRODUCTHUNT_API_KEY', None)
        self.api_secret = getattr(settings, 'PRODUCTHUNT_API_SECRET', None)
        self._access_token: str | None = None

    async def _get_access_token(self, client: httpx.AsyncClient) -> str | None:
        """Get OAuth access token for Product Hunt API."""
        if self._access_token:
            return self._access_token

        if not self.api_key or not self.api_secret:
            logger.warning("Product Hunt API credentials not configured")
            return None

        try:
            response = await client.post(
                "https://api.producthunt.com/v2/oauth/token",
                data={
                    "client_id": self.api_key,
                    "client_secret": self.api_secret,
                    "grant_type": "client_credentials"
                }
            )
            response.raise_for_status()
            data = response.json()
            self._access_token = data.get("access_token")
            return self._access_token
        except Exception as e:
            logger.error(f"Error getting Product Hunt access token: {e}")
            return None

    async def discover(self, config: dict | None = None) -> list[RawToolData]:
        """
        Discover AI tools from Product Hunt.

        Config options:
            min_votes: int - Minimum votes required (default: 50)
            days_back: int - How many days back to search (default: 30)
            topics: list[str] - Topics to search (default: AI_TOPICS)
            max_results: int - Maximum results (default: 100)
        """
        config = config or {}
        min_votes = config.get("min_votes", 50)
        days_back = config.get("days_back", 30)
        topics = config.get("topics", self.AI_TOPICS)
        max_results = config.get("max_results", 100)

        tools: list[RawToolData] = []
        seen_urls: set[str] = set()

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get access token
            token = await self._get_access_token(client)
            if not token:
                logger.warning("Could not get Product Hunt access token, skipping")
                return tools

            # Search each topic
            for topic in topics:
                try:
                    topic_tools = await self._search_topic(
                        client, token, topic, min_votes, days_back, max_results // len(topics)
                    )
                    for tool in topic_tools:
                        if tool.url not in seen_urls:
                            seen_urls.add(tool.url)
                            tools.append(tool)

                    # Rate limit
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"Error searching Product Hunt topic {topic}: {e}")
                    continue

        logger.info(f"Product Hunt: discovered {len(tools)} tools")
        return tools

    async def _search_topic(
        self,
        client: httpx.AsyncClient,
        token: str,
        topic: str,
        min_votes: int,
        days_back: int,
        max_results: int
    ) -> list[RawToolData]:
        """Search Product Hunt for posts with a specific topic."""
        tools: list[RawToolData] = []

        # GraphQL query to fetch posts
        query = """
        query($topic: String!, $first: Int!, $postedAfter: DateTime) {
            posts(
                topic: $topic,
                first: $first,
                postedAfter: $postedAfter,
                order: VOTES
            ) {
                edges {
                    node {
                        id
                        name
                        tagline
                        description
                        url
                        website
                        votesCount
                        commentsCount
                        createdAt
                        topics {
                            edges {
                                node {
                                    name
                                    slug
                                }
                            }
                        }
                        makers {
                            id
                            name
                        }
                        thumbnail {
                            url
                        }
                    }
                }
            }
        }
        """

        posted_after = (datetime.utcnow() - timedelta(days=days_back)).isoformat()

        try:
            response = await client.post(
                self.GRAPHQL_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                json={
                    "query": query,
                    "variables": {
                        "topic": topic,
                        "first": min(max_results, 50),
                        "postedAfter": posted_after
                    }
                }
            )
            response.raise_for_status()
            data = response.json()

            posts = data.get("data", {}).get("posts", {}).get("edges", [])

            for edge in posts:
                post = edge.get("node", {})
                if post.get("votesCount", 0) >= min_votes:
                    tool = self._post_to_tool(post)
                    if tool:
                        tools.append(tool)

        except httpx.HTTPStatusError as e:
            logger.error(f"Product Hunt API error: {e}")
            raise

        return tools

    def _post_to_tool(self, post: dict[str, Any]) -> RawToolData | None:
        """Convert Product Hunt post to RawToolData."""
        try:
            name = post.get("name", "")
            if not name:
                return None

            # Use website URL if available, otherwise Product Hunt URL
            url = post.get("website") or post.get("url", "")
            if not url:
                return None

            # Combine tagline and description
            tagline = post.get("tagline", "")
            description = post.get("description", "")
            full_description = f"{tagline}. {description}" if description else tagline

            # Extract categories from topics
            topics = post.get("topics", {}).get("edges", [])
            categories = [
                edge.get("node", {}).get("name", "")
                for edge in topics
                if edge.get("node", {}).get("name")
            ]

            # Build extra data
            makers = post.get("makers", [])
            maker_names = [m.get("name", "") for m in makers if m.get("name")]

            extra_data = {
                "producthunt_id": post.get("id"),
                "producthunt_url": post.get("url"),
                "votes": post.get("votesCount", 0),
                "comments": post.get("commentsCount", 0),
                "makers": maker_names,
                "thumbnail": post.get("thumbnail", {}).get("url") if post.get("thumbnail") else None,
                "topics": [edge.get("node", {}).get("slug", "") for edge in topics]
            }

            # Get launch date
            created_at = post.get("createdAt", "")
            last_updated = created_at[:10] if created_at else None

            # Extract tags
            tags = self._extract_tags(full_description, categories)

            return RawToolData(
                name=name,
                url=url,
                description=self._clean_description(full_description),
                source_url=post.get("url", ""),  # Product Hunt page for attribution
                categories=self._map_categories(categories),
                tags=tags,
                last_updated=last_updated,
                extra_data=extra_data
            )
        except Exception as e:
            logger.error(f"Error converting Product Hunt post to tool: {e}")
            return None

    def _map_categories(self, ph_categories: list[str]) -> list[str]:
        """Map Product Hunt categories to standard categories."""
        category_mapping = {
            "artificial intelligence": "AI & Machine Learning",
            "machine learning": "AI & Machine Learning",
            "developer tools": "Coding & Development",
            "productivity": "Productivity",
            "writing tools": "Writing & Content",
            "marketing": "Marketing & Sales",
            "design tools": "Design & Creative",
            "no-code": "No-Code & Automation",
            "automation": "No-Code & Automation",
            "analytics": "Data & Analytics",
            "chatbots": "Chat & Assistants",
            "education": "Research & Education",
            "open source": "Open Source",
            "saas": "SaaS",
            "api": "APIs & Integrations",
        }

        mapped = set()
        for cat in ph_categories:
            cat_lower = cat.lower()
            if cat_lower in category_mapping:
                mapped.add(category_mapping[cat_lower])
            else:
                # Keep original if no mapping
                mapped.add(cat)

        return list(mapped)
