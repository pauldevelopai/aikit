"""Kit data loader service.

Reads and caches structured JSON data from the /kit directory.
This is the single source of truth for all toolkit content.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from functools import lru_cache


# Resolve kit directory relative to project root
_KIT_DIR = Path(__file__).resolve().parent.parent.parent / "kit"


def _load_json(path: Path) -> Dict[str, Any]:
    """Load a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def get_manifest() -> Dict[str, Any]:
    """Load and cache the kit manifest."""
    return _load_json(_KIT_DIR / "manifest.json")


@lru_cache(maxsize=1)
def get_all_tools() -> List[Dict[str, Any]]:
    """Load all tool JSON files, sorted by number."""
    tools_dir = _KIT_DIR / "tools"
    if not tools_dir.exists():
        return []

    tools = []
    for path in sorted(tools_dir.glob("*.json")):
        tools.append(_load_json(path))

    tools.sort(key=lambda t: t.get("number", 0))
    return tools


def get_tool(slug: str) -> Optional[Dict[str, Any]]:
    """Get a single tool by slug."""
    path = _KIT_DIR / "tools" / f"{slug}.json"
    if path.exists():
        return _load_json(path)
    # Fallback: search all tools
    for tool in get_all_tools():
        if tool.get("slug") == slug:
            return tool
    return None


@lru_cache(maxsize=1)
def get_all_clusters() -> List[Dict[str, Any]]:
    """Load all cluster JSON files, sorted by number."""
    clusters_dir = _KIT_DIR / "clusters"
    if not clusters_dir.exists():
        return []

    clusters = []
    for path in sorted(clusters_dir.glob("*.json")):
        clusters.append(_load_json(path))

    clusters.sort(key=lambda c: c.get("number", 0))
    return clusters


def get_cluster(slug: str) -> Optional[Dict[str, Any]]:
    """Get a single cluster by slug."""
    path = _KIT_DIR / "clusters" / f"{slug}.json"
    if path.exists():
        return _load_json(path)
    return None


def get_cluster_tools(cluster_slug: str) -> List[Dict[str, Any]]:
    """Get all tools belonging to a cluster."""
    return [t for t in get_all_tools() if t.get("cluster_slug") == cluster_slug]


@lru_cache(maxsize=1)
def get_all_foundations() -> List[Dict[str, Any]]:
    """Load all foundational section JSON files."""
    foundations_dir = _KIT_DIR / "foundations"
    if not foundations_dir.exists():
        return []

    foundations = []
    for path in sorted(foundations_dir.glob("*.json")):
        foundations.append(_load_json(path))

    return foundations


def get_foundation(slug: str) -> Optional[Dict[str, Any]]:
    """Get a single foundational section by slug."""
    path = _KIT_DIR / "foundations" / f"{slug}.json"
    if path.exists():
        return _load_json(path)
    return None


@lru_cache(maxsize=1)
def get_all_sources() -> Dict[str, Any]:
    """Load all source citation data from the combined JSON."""
    sources_path = _KIT_DIR / "sources" / "all_sources.json"
    if not sources_path.exists():
        return {"total_entries": 0, "batch_count": 0, "batches": [], "entries": []}
    return _load_json(sources_path)


def get_source_batch(batch_num: int) -> Optional[Dict[str, Any]]:
    """Get a single batch of sources by number."""
    path = _KIT_DIR / "sources" / f"batch{batch_num}.json"
    if path.exists():
        return _load_json(path)
    return None


def get_sources_by_theme(theme_query: str) -> List[Dict[str, Any]]:
    """Get source entries matching a theme keyword."""
    data = get_all_sources()
    query = theme_query.lower()
    return [e for e in data.get("entries", []) if query in e.get("theme", "").lower()]


def search_sources(query: str) -> List[Dict[str, Any]]:
    """Search source entries by title, excerpt, or ai_extract."""
    data = get_all_sources()
    query_lower = query.lower().strip()
    if not query_lower:
        return data.get("entries", [])

    results = []
    for entry in data.get("entries", []):
        searchable = " ".join([
            entry.get("title", ""),
            entry.get("excerpt", ""),
            entry.get("ai_extract", ""),
            entry.get("why_it_matters", ""),
            entry.get("source", ""),
            entry.get("theme", ""),
        ]).lower()
        if query_lower in searchable:
            results.append(entry)
    return results


def search_tools(query: str, cluster_slug: Optional[str] = None,
                 max_cost: Optional[int] = None,
                 max_difficulty: Optional[int] = None,
                 max_invasiveness: Optional[int] = None) -> List[Dict[str, Any]]:
    """Search tools by text query and optional filters.

    Args:
        query: Text to search for in name, description, purpose, tags
        cluster_slug: Filter by cluster
        max_cost: Maximum CDI cost score (0-10)
        max_difficulty: Maximum CDI difficulty score (0-10)
        max_invasiveness: Maximum CDI invasiveness score (0-10)

    Returns:
        Matching tools sorted by relevance (name match first)
    """
    query_lower = query.lower().strip() if query else ""
    results = []

    for tool in get_all_tools():
        # Apply cluster filter
        if cluster_slug and tool.get("cluster_slug") != cluster_slug:
            continue

        # Apply CDI filters
        cdi = tool.get("cdi_scores", {})
        if max_cost is not None and cdi.get("cost", 0) > max_cost:
            continue
        if max_difficulty is not None and cdi.get("difficulty", 0) > max_difficulty:
            continue
        if max_invasiveness is not None and cdi.get("invasiveness", 0) > max_invasiveness:
            continue

        # Apply text search
        if query_lower:
            searchable = " ".join([
                tool.get("name", ""),
                tool.get("description", ""),
                tool.get("purpose", ""),
                tool.get("journalism_relevance", ""),
                tool.get("comments", ""),
                " ".join(tool.get("tags", [])),
            ]).lower()

            if query_lower not in searchable:
                continue

        results.append(tool)

    # Sort: name matches first, then by number
    if query_lower:
        results.sort(key=lambda t: (
            0 if query_lower in t.get("name", "").lower() else 1,
            t.get("number", 0)
        ))

    return results


def get_kit_stats() -> Dict[str, Any]:
    """Get summary statistics about the kit data."""
    manifest = get_manifest()
    tools = get_all_tools()
    clusters = get_all_clusters()

    # CDI averages
    if tools:
        avg_cost = sum(t.get("cdi_scores", {}).get("cost", 0) for t in tools) / len(tools)
        avg_diff = sum(t.get("cdi_scores", {}).get("difficulty", 0) for t in tools) / len(tools)
        avg_inv = sum(t.get("cdi_scores", {}).get("invasiveness", 0) for t in tools) / len(tools)
    else:
        avg_cost = avg_diff = avg_inv = 0

    sources = get_all_sources()

    return {
        "title": manifest.get("title", ""),
        "tool_count": len(tools),
        "cluster_count": len(clusters),
        "foundation_count": len(manifest.get("foundations", [])),
        "addenda_count": len(manifest.get("addenda", [])),
        "source_count": sources.get("total_entries", 0),
        "source_batch_count": sources.get("batch_count", 0),
        "avg_cdi": {
            "cost": round(avg_cost, 1),
            "difficulty": round(avg_diff, 1),
            "invasiveness": round(avg_inv, 1),
        },
    }


def clear_cache():
    """Clear all cached data. Call after re-extraction."""
    get_manifest.cache_clear()
    get_all_tools.cache_clear()
    get_all_clusters.cache_clear()
    get_all_foundations.cache_clear()
    get_all_sources.cache_clear()


# =============================================================================
# ADMIN-APPROVED TOOLS (from database)
# =============================================================================

ADMIN_APPROVED_CLUSTER_SLUG = "admin-approved"
ADMIN_APPROVED_CLUSTER = {
    "number": 8,  # Cluster 8 - part of the main clusters
    "slug": ADMIN_APPROVED_CLUSTER_SLUG,
    "name": "Admin Approved",
    "description": "Tools reviewed and approved by administrators. These tools have been vetted and added to the toolkit collection.",
    "icon": "check-badge",
    "color": "#10B981",  # Green
    "tool_count": 0,  # Will be updated dynamically
}


def get_approved_tools_from_db(db) -> List[Dict[str, Any]]:
    """
    Get admin-approved tools from the discovered_tools database table.
    Converts them to the same format as kit tools.

    Args:
        db: SQLAlchemy database session

    Returns:
        List of tool dictionaries in kit format
    """
    from app.models.discovery import DiscoveredTool

    approved = db.query(DiscoveredTool).filter(
        DiscoveredTool.status == "approved"
    ).order_by(DiscoveredTool.name).all()

    tools = []
    for i, tool in enumerate(approved):
        tools.append({
            "number": 1000 + i,  # High number to sort after kit tools
            "slug": tool.slug,
            "name": tool.name,
            "tagline": tool.description[:100] if tool.description else "",
            "description": tool.description or "",
            "purpose": tool.description or "",
            "url": tool.url,
            "cluster_slug": ADMIN_APPROVED_CLUSTER_SLUG,
            "cluster_name": "Admin Approved",
            "categories": tool.categories or [],
            "tags": ["admin-approved"] + (tool.categories or []),
            "cdi_scores": {
                "cost": 5,  # Default neutral scores
                "difficulty": 5,
                "invasiveness": 5
            },
            "time_dividend": {
                "time_saved": None,
                "reinvestment": None
            },
            "cross_references": {
                "use_cases": tool.categories or [],
                "similar_tools": [],
                "sovereign_alternative": None,
                "sovereign_alternative_for": []
            },
            "comments": None,
            "journalism_relevance": None,
            "is_admin_approved": True,
            "approved_at": tool.reviewed_at.isoformat() if tool.reviewed_at else None,
            "source_type": tool.source_type,
            "source_name": tool.source_name,
        })

    return tools


def get_admin_approved_cluster(db) -> Optional[Dict[str, Any]]:
    """
    Get the admin-approved cluster with updated tool count.

    Args:
        db: SQLAlchemy database session

    Returns:
        Cluster dictionary or None if no approved tools
    """
    from app.models.discovery import DiscoveredTool

    count = db.query(DiscoveredTool).filter(
        DiscoveredTool.status == "approved"
    ).count()

    if count == 0:
        return None

    cluster = ADMIN_APPROVED_CLUSTER.copy()
    cluster["tool_count"] = count
    return cluster


def get_all_clusters_with_approved(db) -> List[Dict[str, Any]]:
    """
    Get all clusters including the admin-approved cluster if it has tools.

    Args:
        db: SQLAlchemy database session

    Returns:
        List of all clusters
    """
    clusters = list(get_all_clusters())  # Copy to avoid modifying cached list

    approved_cluster = get_admin_approved_cluster(db)
    if approved_cluster:
        clusters.append(approved_cluster)

    return clusters


def get_all_tools_with_approved(db) -> List[Dict[str, Any]]:
    """
    Get all tools including admin-approved tools.

    Args:
        db: SQLAlchemy database session

    Returns:
        List of all tools (kit + approved)
    """
    tools = list(get_all_tools())  # Copy to avoid modifying cached list
    tools.extend(get_approved_tools_from_db(db))
    return tools


def get_kit_stats_with_approved(db) -> Dict[str, Any]:
    """
    Get summary statistics including admin-approved tools and clusters.

    This should be used instead of get_kit_stats() when you need
    accurate counts that include dynamically approved tools.

    Args:
        db: SQLAlchemy database session

    Returns:
        Statistics dictionary with accurate tool/cluster counts
    """
    manifest = get_manifest()
    tools = get_all_tools_with_approved(db)
    clusters = get_all_clusters_with_approved(db)

    # CDI averages
    if tools:
        avg_cost = sum(t.get("cdi_scores", {}).get("cost", 0) for t in tools) / len(tools)
        avg_diff = sum(t.get("cdi_scores", {}).get("difficulty", 0) for t in tools) / len(tools)
        avg_inv = sum(t.get("cdi_scores", {}).get("invasiveness", 0) for t in tools) / len(tools)
    else:
        avg_cost = avg_diff = avg_inv = 0

    sources = get_all_sources()

    return {
        "title": manifest.get("title", ""),
        "tool_count": len(tools),
        "cluster_count": len(clusters),
        "foundation_count": len(manifest.get("foundations", [])),
        "addenda_count": len(manifest.get("addenda", [])),
        "source_count": sources.get("total_entries", 0),
        "source_batch_count": sources.get("batch_count", 0),
        "avg_cdi": {
            "cost": round(avg_cost, 1),
            "difficulty": round(avg_diff, 1),
            "invasiveness": round(avg_inv, 1),
        },
    }
