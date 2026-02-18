"""Cluster listing and detail routes."""
import re
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.auth import User
from app.dependencies import get_current_user
from app.services.kit_loader import (
    get_all_clusters, get_cluster, get_cluster_tools,
    get_all_clusters_with_approved, get_approved_tools_from_db,
    ADMIN_APPROVED_CLUSTER_SLUG, get_admin_approved_cluster
)
from app.templates_engine import templates


def parse_where_to_start(text: str) -> List[Dict[str, Any]]:
    """Parse where_to_start text into structured recommendation blocks."""
    if not text:
        return []

    # Cut off at "Addendum" if present (misplaced content in some clusters)
    addendum_idx = text.find("Addendum")
    if addendum_idx > 0:
        text = text[:addendum_idx].strip()

    blocks = []

    # Split by main block markers using lookahead
    parts = re.split(
        r'(?=Start with:|Introduce next:|Avoid initially:)',
        text,
        flags=re.IGNORECASE,
    )
    parts = [p.strip() for p in parts if p.strip()]

    for part in parts:
        block: Dict[str, Any] = {}

        if part.lower().startswith("start with:"):
            block["type"] = "start"
            block["label"] = "Start with"
            remainder = part[len("Start with:"):].strip()
        elif part.lower().startswith("introduce next:"):
            block["type"] = "next"
            block["label"] = "Introduce next"
            remainder = part[len("Introduce next:"):].strip()
        elif part.lower().startswith("avoid initially:"):
            block["type"] = "avoid"
            block["label"] = "Avoid initially"
            remainder = part[len("Avoid initially:"):].strip()
        else:
            continue

        # Find first section marker to separate intro (tool name) from sections
        section_start = re.search(
            r'(?:Why\b|What\b|Best teaching use)',
            remainder,
            re.IGNORECASE,
        )

        if section_start:
            block["intro"] = remainder[:section_start.start()].strip().rstrip('.')
            section_text = remainder[section_start.start():]
        else:
            block["intro"] = remainder.strip().rstrip('.')
            section_text = ""

        block["sections"] = _parse_sections(section_text)
        blocks.append(block)

    return blocks


def _parse_sections(text: str) -> List[Dict[str, Any]]:
    """Parse sub-sections (Why, What, Best teaching use) from block text."""
    if not text:
        return []

    sections: List[Dict[str, Any]] = []

    heading_pattern = re.compile(
        r'(Why\s*:\s*|'
        r'Why\s+these\s+(?:first|next)\s*:?\s*|'
        r'Why\s+this\s+next\s*:?\s*|'
        r'What\s+(?:they|it)\s+teach(?:es)?\s+well\s*:?\s*|'
        r'Best\s+teaching\s+use\s*:?\s*)',
        re.IGNORECASE,
    )

    markers = list(heading_pattern.finditer(text))

    for i, match in enumerate(markers):
        heading = match.group().strip().rstrip(':').strip()
        heading = heading[0].upper() + heading[1:]

        start = match.end()
        end = markers[i + 1].start() if i + 1 < len(markers) else len(text)
        content = text[start:end].strip()

        if '•' in content:
            items = [item.strip() for item in content.split('•') if item.strip()]
            sections.append({"heading": heading, "list_items": items, "is_list": True})
        else:
            # Check for multiple sentence-like items separated by ". "
            sentences = re.split(r'\.\s+(?=[A-Z])', content)
            if len(sentences) > 1:
                items = [s.strip().rstrip('.') for s in sentences if s.strip()]
                sections.append({"heading": heading, "list_items": items, "is_list": True})
            else:
                sections.append({
                    "heading": heading,
                    "content": content,
                    "is_list": False,
                })

    return sections


router = APIRouter(prefix="/clusters", tags=["clusters"])


@router.get("", response_class=HTMLResponse)
async def clusters_index(
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all tool clusters including admin-approved tools."""
    clusters = get_all_clusters_with_approved(db)

    # Enrich each cluster with its tool count and tools
    enriched = []
    for c in clusters:
        if c["slug"] == ADMIN_APPROVED_CLUSTER_SLUG:
            # Admin-approved cluster - tools come from database
            tools = get_approved_tools_from_db(db)
            enriched.append({
                **c,
                "tools": tools,
                "tool_count": len(tools),
                "avg_cost": 5,  # Default neutral scores
                "avg_difficulty": 5,
                "avg_invasiveness": 5,
                "is_admin_approved": True,
            })
        else:
            # Standard kit cluster
            tools = get_cluster_tools(c["slug"])
            enriched.append({
                **c,
                "tools": tools,
                "tool_count": len(tools),
                "avg_cost": round(sum(t["cdi_scores"]["cost"] for t in tools) / len(tools), 1) if tools else 0,
                "avg_difficulty": round(sum(t["cdi_scores"]["difficulty"] for t in tools) / len(tools), 1) if tools else 0,
                "avg_invasiveness": round(sum(t["cdi_scores"]["invasiveness"] for t in tools) / len(tools), 1) if tools else 0,
            })

    return templates.TemplateResponse(
        "clusters/index.html",
        {
            "request": request,
            "user": user,
            "clusters": enriched,
        }
    )


@router.get("/{slug}", response_class=HTMLResponse)
async def cluster_detail(
    request: Request,
    slug: str,
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Show cluster detail with its tools."""
    # Handle admin-approved cluster separately
    if slug == ADMIN_APPROVED_CLUSTER_SLUG:
        cluster = get_admin_approved_cluster(db)
        if not cluster:
            raise HTTPException(status_code=404, detail="No approved tools yet")

        tools = get_approved_tools_from_db(db)

        return templates.TemplateResponse(
            "clusters/detail.html",
            {
                "request": request,
                "user": user,
                "cluster": cluster,
                "tools": tools,
                "wts_blocks": [],  # No where_to_start for admin-approved
                "is_admin_approved": True,
            }
        )

    # Standard kit cluster
    cluster = get_cluster(slug)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    tools = get_cluster_tools(slug)
    wts_blocks = parse_where_to_start(cluster.get("where_to_start", ""))

    return templates.TemplateResponse(
        "clusters/detail.html",
        {
            "request": request,
            "user": user,
            "cluster": cluster,
            "tools": tools,
            "wts_blocks": wts_blocks,
        }
    )
