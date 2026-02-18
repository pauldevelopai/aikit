#!/usr/bin/env python3
"""Extract structured data from toolkit.pdf into JSON files in /kit/.

Usage:
    python scripts/extract_toolkit.py

This reads kit/toolkit.pdf and produces:
    kit/manifest.json
    kit/tools/*.json       (one file per tool)
    kit/clusters/*.json    (one file per cluster)
    kit/foundations/*.json  (foundational sections)
"""
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

import pdfplumber


# Project root
ROOT = Path(__file__).resolve().parent.parent
KIT_DIR = ROOT / "kit"
PDF_PATH = KIT_DIR / "toolkit.pdf"


def slugify(text: str) -> str:
    """Convert text to a URL-friendly slug."""
    text = text.lower().strip()
    # Remove footnote numbers at end
    text = re.sub(r'\s*\d+\s*$', '', text)
    # Remove special chars
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text.strip('-')


def extract_full_text(pdf_path: str) -> str:
    """Extract all text from the PDF."""
    pages = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
    return "\n\n".join(pages)


def find_cluster_boundaries(text: str) -> List[Dict[str, Any]]:
    """Identify the 7 tool cluster sections and their boundaries in the text."""
    clusters = []
    cluster_names = {
        1: "Transcription & Translation",
        2: "Verification & Investigations",
        3: "Writing & Analysis",
        4: "Audio, Video & Social",
        5: "Security Challenges",
        6: "Building Your Own Tools",
        7: "AI Agents & Automated Workflows",
    }

    # Find cluster header positions - look for "Tool cluster N:" pattern
    pattern = r'Tool [Cc]luster (\d+):\s*(.+?)(?:\n|$)'
    matches = list(re.finditer(pattern, text))

    # We get duplicate matches from TOC and body - take the later ones (body)
    seen_nums = {}
    for m in matches:
        num = int(m.group(1))
        seen_nums.setdefault(num, []).append(m)

    body_matches = []
    for num in sorted(seen_nums.keys()):
        # Take the last occurrence (the body one, not the TOC one)
        body_matches.append(seen_nums[num][-1])

    for i, m in enumerate(body_matches):
        num = int(m.group(1))
        start = m.start()
        end = body_matches[i + 1].start() if i + 1 < len(body_matches) else len(text)
        cluster_text = text[start:end]
        clusters.append({
            "number": num,
            "name": cluster_names.get(num, m.group(2).strip()),
            "slug": slugify(cluster_names.get(num, m.group(2).strip())),
            "start": start,
            "end": end,
            "text": cluster_text,
        })

    return clusters


def extract_tool_entry(text: str, tool_number: int, next_tool_start: Optional[int] = None) -> Dict[str, Any]:
    """Parse a single tool entry from text."""
    if next_tool_start:
        entry_text = text[:next_tool_start]
    else:
        entry_text = text

    tool = {
        "number": tool_number,
        "name": "",
        "slug": "",
        "description": "",
        "purpose": "",
        "journalism_relevance": "",
        "cdi_scores": {"cost": 0, "difficulty": 0, "invasiveness": 0},
        "time_dividend": {"time_saved": "", "reinvestment": ""},
        "comments": "",
        "url": "",
        "tags": [],
    }

    # Extract name from first line
    first_line_match = re.match(r'^.*?(?:\d+\.\s+)?(?:THE SOVEREIGN ALTERNATIVE:\s*)?(.+?)(?:\s*\d+)?\s*\n', entry_text)
    if first_line_match:
        raw_name = first_line_match.group(1).strip()
        # Clean up name
        raw_name = re.sub(r'\s*\d+$', '', raw_name).strip()
        tool["name"] = raw_name

    # Check if sovereign alternative
    if "SOVEREIGN ALTERNATIVE" in entry_text[:200]:
        sovereign_match = re.search(r'THE SOVEREIGN ALTERNATIVE:\s*(.+?)(?:\s*\d+)?\s*\n', entry_text)
        if sovereign_match:
            tool["name"] = sovereign_match.group(1).strip()
            tool["name"] = re.sub(r'\s*\d+$', '', tool["name"]).strip()
        tool["tags"].append("sovereign-alternative")

    tool["slug"] = slugify(tool["name"])

    # Extract URL from footnotes
    urls = re.findall(r'https?://[^\s\)]+', entry_text)
    if urls:
        # First URL is usually the tool's main URL
        tool["url"] = urls[0]

    # Extract description - text between name and first bullet
    desc_match = re.search(r'\n(.+?)(?=●\s*(?:The Tool|CDI Score)|(?:The Tool.s Purpose))', entry_text, re.DOTALL)
    if desc_match:
        desc = desc_match.group(1).strip()
        # Clean up footnote numbers and URLs
        desc = re.sub(r'\s*\d+\s*https?://\S+', '', desc)
        desc = re.sub(r'\s*\d+$', '', desc, flags=re.MULTILINE)
        desc = re.sub(r'\n+', ' ', desc)
        desc = re.sub(r'\s+', ' ', desc).strip()
        # Remove trailing footnote refs
        desc = re.sub(r'\s*\d+\s*$', '', desc).strip()
        tool["description"] = desc

    # Extract purpose
    purpose_match = re.search(r"(?:The Tool.s Purpose|Tool.s Purpose):\s*(.+?)(?:\n|●|$)", entry_text, re.DOTALL)
    if purpose_match:
        tool["purpose"] = purpose_match.group(1).strip()

    # Extract journalism relevance
    relevance_match = re.search(r"Relevance to journalism:\s*(.+?)(?=\n●|\nCDI|\n\s*●)", entry_text, re.DOTALL)
    if relevance_match:
        rel = relevance_match.group(1).strip()
        rel = re.sub(r'\n+', ' ', rel)
        rel = re.sub(r'\s+', ' ', rel).strip()
        tool["journalism_relevance"] = rel

    # Extract CDI scores
    cdi_match = re.search(
        r'CDI Score:\s*Cost:\s*(\d+)/10\s*\|\s*Difficulty:\s*(\d+)/10\s*\|\s*Invasiveness:\s*(\d+)/10',
        entry_text
    )
    if cdi_match:
        tool["cdi_scores"] = {
            "cost": int(cdi_match.group(1)),
            "difficulty": int(cdi_match.group(2)),
            "invasiveness": int(cdi_match.group(3)),
        }

    # Extract comments (after CDI score line)
    comments_match = re.search(r'Comments?:\s*(.+?)(?=\n●|\nTime Dividend|\n\s*●)', entry_text, re.DOTALL)
    if comments_match:
        comments = comments_match.group(1).strip()
        comments = re.sub(r'\n+', ' ', comments)
        comments = re.sub(r'\s+', ' ', comments).strip()
        tool["comments"] = comments

    # Extract time dividend
    time_saved_match = re.search(r'How (?:is )?time (?:is )?saved:\s*(.+?)(?=\n○|\nWays|\n●|\n\d+\.)', entry_text, re.DOTALL)
    if time_saved_match:
        ts = time_saved_match.group(1).strip()
        ts = re.sub(r'\n+', ' ', ts)
        ts = re.sub(r'\s+', ' ', ts).strip()
        tool["time_dividend"]["time_saved"] = ts

    reinvest_match = re.search(r'Ways to reinvest the time:\s*(.+?)(?=\n\d+\.|\nTeaching|\nWhere|\nExercise|\nTool [Cc]luster|\nAddendum|\Z)', entry_text, re.DOTALL)
    if reinvest_match:
        ri = reinvest_match.group(1).strip()
        ri = re.sub(r'\n+', ' ', ri)
        ri = re.sub(r'\s+', ' ', ri).strip()
        # Clean trailing footnotes
        ri = re.sub(r'\s*\d+\s*https?://\S+', '', ri)
        ri = re.sub(r'\s*\d+\s*$', '', ri).strip()
        tool["time_dividend"]["reinvestment"] = ri

    # Generate tags from content
    tags = list(tool["tags"])  # keep existing (like sovereign-alternative)
    name_lower = tool["name"].lower()
    if tool["cdi_scores"]["cost"] == 0:
        tags.append("free")
    if tool["cdi_scores"]["invasiveness"] == 0:
        tags.append("local-processing")
    if tool["cdi_scores"]["invasiveness"] <= 2:
        tags.append("privacy-friendly")
    if tool["cdi_scores"]["difficulty"] <= 2:
        tags.append("beginner-friendly")
    if tool["cdi_scores"]["difficulty"] >= 7:
        tags.append("advanced")
    if "open-source" in entry_text.lower() or "open source" in entry_text.lower():
        tags.append("open-source")

    tool["tags"] = sorted(set(tags))

    return tool


def extract_tools_from_cluster(cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all tool entries from a cluster's text."""
    text = cluster["text"]
    tools = []

    # Find all numbered tool entries within this cluster text
    # Pattern: number. ToolName (possibly with footnote)
    tool_starts = list(re.finditer(r'^(\d+)\.\s+(?:THE SOVEREIGN ALTERNATIVE:\s*)?(.+?)(?:\s*\d+)?\s*$', text, re.MULTILINE))

    # Filter to only actual tool entries (not lists within descriptions)
    # Tool entries have CDI scores, so verify
    valid_starts = []
    for j, ts in enumerate(tool_starts):
        num = int(ts.group(1))
        # Check if there's a CDI Score after this position
        next_pos = tool_starts[j + 1].start() if j + 1 < len(tool_starts) else len(text)
        segment = text[ts.start():next_pos]
        if 'CDI Score' in segment:
            valid_starts.append(ts)

    for j, ts in enumerate(valid_starts):
        tool_num = int(ts.group(1))
        start = ts.start()
        end = valid_starts[j + 1].start() if j + 1 < len(valid_starts) else len(text)

        tool_text = text[start:end]
        tool = extract_tool_entry(tool_text, tool_num)
        tool["cluster_name"] = cluster["name"]
        tool["cluster_slug"] = cluster["slug"]
        tool["cluster_number"] = cluster["number"]

        # Override name if extraction was poor
        if not tool["name"] or len(tool["name"]) < 2:
            raw = ts.group(2).strip()
            raw = re.sub(r'\s*\d+$', '', raw).strip()
            tool["name"] = raw
            tool["slug"] = slugify(raw)

        tools.append(tool)

    return tools


def extract_cluster_meta(cluster: Dict[str, Any]) -> Dict[str, Any]:
    """Extract cluster-level metadata (teaching guidance, exercises, where to start)."""
    text = cluster["text"]
    meta = {
        "number": cluster["number"],
        "name": cluster["name"],
        "slug": cluster["slug"],
        "description": "",
        "teaching_guidance": "",
        "exercises": [],
        "where_to_start": "",
        "tool_slugs": [],
    }

    # Extract cluster intro (text before first numbered tool)
    first_tool = re.search(r'^\d+\.\s+', text, re.MULTILINE)
    if first_tool:
        intro = text[:first_tool.start()].strip()
        # Remove the cluster header line
        intro = re.sub(r'^Tool [Cc]luster \d+:.*?\n', '', intro, count=1).strip()
        intro = re.sub(r'\n+', ' ', intro)
        intro = re.sub(r'\s+', ' ', intro).strip()
        meta["description"] = intro

    # Extract teaching guidance
    tg_match = re.search(r'Teaching guidance\s*\n(.+?)(?=Exercise \d+:|Where should you start|Tool [Cc]luster \d+|\Z)', text, re.DOTALL)
    if tg_match:
        tg = tg_match.group(1).strip()
        tg = re.sub(r'\n+', ' ', tg)
        tg = re.sub(r'\s+', ' ', tg).strip()
        meta["teaching_guidance"] = tg

    # Extract exercises
    exercise_matches = re.finditer(r'Exercise (\d+):\s*(.+?)\n(.+?)(?=Exercise \d+:|Where should you start|Teaching guidance|Tool [Cc]luster|\Z)', text, re.DOTALL)
    for em in exercise_matches:
        exercise = {
            "number": int(em.group(1)),
            "title": em.group(2).strip(),
            "description": em.group(3).strip(),
        }
        exercise["description"] = re.sub(r'\n+', ' ', exercise["description"])
        exercise["description"] = re.sub(r'\s+', ' ', exercise["description"]).strip()
        # Clean trailing footnotes
        exercise["description"] = re.sub(r'\s*\d+https?://\S+', '', exercise["description"])
        meta["exercises"].append(exercise)

    # Extract "where to start"
    wts_match = re.search(r'Where should you start\?.*?\n(.+?)(?=Tool [Cc]luster \d+|\Z)', text, re.DOTALL)
    if wts_match:
        wts = wts_match.group(1).strip()
        wts = re.sub(r'\n+', ' ', wts)
        wts = re.sub(r'\s+', ' ', wts).strip()
        meta["where_to_start"] = wts

    return meta


def extract_foundations(text: str) -> List[Dict[str, Any]]:
    """Extract foundational sections (before tool clusters)."""
    foundations = []

    # Find where the first tool cluster starts (body, not TOC)
    # The body cluster header starts with "Tool cluster 1:" (lowercase c)
    cluster1_pos = text.find("Tool cluster 1:")
    if cluster1_pos == -1:
        return foundations

    # Work with the full pre-cluster text
    pre_cluster = text[:cluster1_pos]

    # Define sections by their start markers and extract text between them.
    # Each tuple: (slug, title, start_marker, end_marker)
    section_defs = [
        ("introduction", "Introduction",
         "Introduction\nWe are", "How to Use This Toolkit"),
        ("how-to-use", "How to Use This Toolkit",
         "How to Use This Toolkit", "Three Core Pillars"),
        ("three-core-pillars", "Three Core Pillars of the Curriculum",
         "Three Core Pillars", "Each tool in this toolkit is rated"),
        ("cdi-scores", "CDI Scoring System",
         "Each tool in this toolkit is rated", "Ethical Guidelines for"),
        ("ethical-guidelines", "Ethical Guidelines for the Sustainable Newsroom",
         "Ethical Guidelines for", "AI Audit Rubric"),
        ("ai-audit-rubric", "The AI Audit Rubric",
         "AI Audit Rubric\nInstructors", "Glossary of AI in journalism"),
        ("glossary", "Glossary of AI in Journalism",
         "Glossary of AI in journalism", "Top 10 AI Use Cases"),
        ("top-10-use-cases", "Top 10 AI Use Cases in Journalism",
         "Top 10 AI Use Cases", "Tool cluster 1:"),
    ]

    for slug, title, start_marker, end_marker in section_defs:
        start_pos = pre_cluster.find(start_marker)
        if start_pos == -1:
            # Try in full text (for sections that span past pre_cluster boundary)
            start_pos = text.find(start_marker)
            if start_pos == -1:
                continue
            end_pos = text.find(end_marker, start_pos + len(start_marker))
            if end_pos == -1:
                end_pos = cluster1_pos
            content = text[start_pos:end_pos].strip()
        else:
            end_pos = pre_cluster.find(end_marker, start_pos + len(start_marker))
            if end_pos == -1:
                end_pos = len(pre_cluster)
            content = pre_cluster[start_pos:end_pos].strip()

        # Clean up footnote URLs
        content = re.sub(r'\s*\d+\s*https?://\S+', '', content)

        if content:
            foundations.append({
                "slug": slug,
                "title": title,
                "content": content,
            })

    return foundations


def extract_addenda(text: str) -> List[Dict[str, Any]]:
    """Extract addenda sections."""
    addenda = []
    addendum_patterns = [
        ("addendum-a", "Caution List: Tools with Significant Risks", r'Addendum A:.*?\n(.+?)(?=Addendum B:)'),
        ("addendum-b", "Strategic Reinvestment of Time", r'Addendum B:.*?\n(.+?)(?=Addendum C:)'),
        ("addendum-c", "Resources & Research", r'Addendum C:.*?\n(.+?)(?=Addendum D:)'),
        ("addendum-d", "Resources & Research Database", r'Addendum D:.*?\n(.+?)(?=Addendum E:)'),
        ("addendum-e", "Who to Follow Online", r'Addendum E:.*?\n(.+?)(?=Copyright|\Z)'),
    ]

    for slug, title, pattern in addendum_patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            content = match.group(1).strip()
            addenda.append({
                "slug": slug,
                "title": title,
                "content": content,
            })

    return addenda


def main():
    """Main extraction pipeline."""
    if not PDF_PATH.exists():
        print(f"Error: {PDF_PATH} not found")
        sys.exit(1)

    print(f"Extracting from {PDF_PATH}...")
    full_text = extract_full_text(str(PDF_PATH))
    print(f"Extracted {len(full_text)} characters from PDF")

    # Create output directories
    for subdir in ["tools", "clusters", "foundations"]:
        (KIT_DIR / subdir).mkdir(parents=True, exist_ok=True)

    # 1. Extract clusters
    print("\n--- Extracting clusters ---")
    clusters = find_cluster_boundaries(full_text)
    print(f"Found {len(clusters)} clusters")

    # 2. Extract tools from each cluster
    all_tools = []
    for cluster in clusters:
        tools = extract_tools_from_cluster(cluster)
        print(f"  Cluster {cluster['number']}: {cluster['name']} -> {len(tools)} tools")

        # Extract cluster metadata
        cluster_meta = extract_cluster_meta(cluster)
        cluster_meta["tool_slugs"] = [t["slug"] for t in tools]
        cluster_meta["tool_count"] = len(tools)

        # Save cluster JSON
        cluster_path = KIT_DIR / "clusters" / f"{cluster['slug']}.json"
        with open(cluster_path, "w", encoding="utf-8") as f:
            json.dump(cluster_meta, f, indent=2, ensure_ascii=False)
        print(f"    -> Saved {cluster_path.name}")

        all_tools.extend(tools)

    # 3. Deduplicate slugs (e.g., Dangerzone appears in two clusters)
    seen_slugs = set()
    for tool in all_tools:
        if tool["slug"] in seen_slugs:
            tool["slug"] = f"{tool['slug']}-{tool['cluster_slug']}"
        seen_slugs.add(tool["slug"])

    # Update cluster tool_slugs with deduplicated slugs
    cluster_slug_map = {}
    for tool in all_tools:
        cluster_slug_map.setdefault(tool["cluster_slug"], []).append(tool["slug"])

    for cluster in clusters:
        cluster_meta = extract_cluster_meta(cluster)
        cluster_meta["tool_slugs"] = cluster_slug_map.get(cluster["slug"], [])
        cluster_meta["tool_count"] = len(cluster_meta["tool_slugs"])
        cluster_path = KIT_DIR / "clusters" / f"{cluster['slug']}.json"
        with open(cluster_path, "w", encoding="utf-8") as f:
            json.dump(cluster_meta, f, indent=2, ensure_ascii=False)

    # Save individual tool JSONs
    print(f"\n--- Saving {len(all_tools)} tool files ---")
    for tool in all_tools:
        tool_path = KIT_DIR / "tools" / f"{tool['slug']}.json"

        # Build the tool output (without internal fields)
        tool_out = {
            "slug": tool["slug"],
            "name": tool["name"],
            "number": tool["number"],
            "cluster_name": tool["cluster_name"],
            "cluster_slug": tool["cluster_slug"],
            "cluster_number": tool["cluster_number"],
            "description": tool["description"],
            "purpose": tool["purpose"],
            "journalism_relevance": tool["journalism_relevance"],
            "cdi_scores": tool["cdi_scores"],
            "time_dividend": tool["time_dividend"],
            "comments": tool["comments"],
            "url": tool["url"],
            "tags": tool["tags"],
        }

        with open(tool_path, "w", encoding="utf-8") as f:
            json.dump(tool_out, f, indent=2, ensure_ascii=False)
        print(f"  {tool['number']:2d}. {tool['name']:<40s} -> {tool_path.name}")

    # 4. Extract and save foundations
    print("\n--- Extracting foundational sections ---")
    foundations = extract_foundations(full_text)
    print(f"Found {len(foundations)} foundational sections")
    for section in foundations:
        path = KIT_DIR / "foundations" / f"{section['slug']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(section, f, indent=2, ensure_ascii=False)
        print(f"  -> {section['title']}")

    # 5. Extract and save addenda (into foundations dir)
    print("\n--- Extracting addenda ---")
    addenda = extract_addenda(full_text)
    print(f"Found {len(addenda)} addenda")
    for addendum in addenda:
        path = KIT_DIR / "foundations" / f"{addendum['slug']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(addendum, f, indent=2, ensure_ascii=False)
        print(f"  -> {addendum['title']}")

    # 6. Generate manifest
    print("\n--- Generating manifest ---")
    manifest = {
        "title": "The CEE Journalism Lecturer's Advanced AI Toolkit (2026 Edition)",
        "source": "toolkit.pdf",
        "tool_count": len(all_tools),
        "cluster_count": len(clusters),
        "clusters": [
            {
                "number": c["number"],
                "name": c["name"],
                "slug": c["slug"],
            }
            for c in clusters
        ],
        "tools": [
            {
                "number": t["number"],
                "name": t["name"],
                "slug": t["slug"],
                "cluster_slug": t["cluster_slug"],
                "cdi_scores": t["cdi_scores"],
            }
            for t in all_tools
        ],
        "foundations": [
            {"slug": f["slug"], "title": f["title"]}
            for f in foundations
        ],
        "addenda": [
            {"slug": a["slug"], "title": a["title"]}
            for a in addenda
        ],
    }

    manifest_path = KIT_DIR / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"Saved manifest to {manifest_path}")

    print(f"\nExtraction complete!")
    print(f"  Tools:       {len(all_tools)}")
    print(f"  Clusters:    {len(clusters)}")
    print(f"  Foundations: {len(foundations)}")
    print(f"  Addenda:     {len(addenda)}")


if __name__ == "__main__":
    main()
