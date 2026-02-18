"""Extract grounded citation sources from batch PDFs.

Parses batch1.pdf through batch12.pdf into structured JSON files
stored at kit/sources/batch{N}.json plus a combined kit/sources/all_sources.json.
"""
import json
import re
import os
import pdfplumber
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent.parent / "kit"
SOURCES_DIR = KIT_DIR / "sources"


# Batch themes (extracted from PDF titles)
BATCH_THEMES = {
    1: "Toolkit Footnotes & Core References",
    2: "Central European & Case Study Evidence",
    3: "Newsroom Chatbots, Transcription & Translation Tools",
    4: "Research Tools & Verification Plugins",
    5: "AI Literacy & Model Limitations",
    6: "Safety, Security & Privacy",
    7: "Business, Revenue & Sustainability",
    8: "Global South & Regional Case Studies",
    9: "Practice-Led Case Studies & Africa-Focused Evidence",
    10: "Claim Verification & LLM Surveys",
    11: "Datasets & Benchmarks for Fact Checking",
    12: "Open-source Tools & Infrastructure",
}


def extract_batch_text(batch_num: int) -> str:
    """Extract full text from a batch PDF."""
    path = KIT_DIR / f"batch{batch_num}.pdf"
    if not path.exists():
        return ""
    with pdfplumber.open(str(path)) as pdf:
        text = ""
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text += t + "\n"
    return text


def clean_text(text: str) -> str:
    """Clean extracted text."""
    # Remove (cid:NNN) artifacts
    text = re.sub(r'\(cid:\d+\)', '', text)
    # Normalize whitespace
    text = re.sub(r'[ \t]+', ' ', text)
    # Clean up line breaks within sentences
    text = re.sub(r'(?<=[a-z,;])\n(?=[a-z])', ' ', text)
    return text.strip()


def parse_batch1(text: str) -> list:
    """Parse batch 1 which uses 'Footnote N:' format."""
    entries = []
    # Split on "Footnote N:" pattern
    parts = re.split(r'Footnote\s+(\d+):\s*', text)
    # parts[0] is header, then alternating: number, content
    for i in range(1, len(parts), 2):
        fn_num = parts[i]
        content = parts[i + 1] if i + 1 < len(parts) else ""

        title_match = re.match(r'(.+?)(?:\n|Source URL:|$)', content)
        title = title_match.group(1).strip() if title_match else f"Footnote {fn_num}"

        url_match = re.search(r'Source URL:\s*(https?://\S+)', content)
        url = url_match.group(1).strip() if url_match else ""
        # Fix broken URLs (line-wrapped)
        if url and '\n' in content:
            url_start = content.find(url)
            if url_start >= 0:
                next_line_end = content.find('\n', url_start + len(url))
                if next_line_end > 0:
                    next_part = content[url_start + len(url):next_line_end].strip()
                    if next_part and not any(next_part.startswith(k) for k in ['Relevant', 'Toolkit', 'Why', 'Key', 'AI-']):
                        url = url + next_part

        extract_match = re.search(r'Relevant extract.*?:\s*(.+?)(?:Toolkit nearby context|$)', content, re.DOTALL)
        excerpt = clean_text(extract_match.group(1)) if extract_match else ""

        context_match = re.search(r'Toolkit nearby context.*?:\s*(.+?)$', content, re.DOTALL)
        context = clean_text(context_match.group(1)) if context_match else ""

        entries.append({
            "entry_id": f"fn{fn_num}",
            "title": clean_text(title),
            "url": url.rstrip('/'),
            "source": "",
            "date": "",
            "excerpt": excerpt,
            "why_it_matters": "",
            "ai_extract": context if context else excerpt,
        })
    return entries


def parse_numbered_entries(text: str) -> list:
    """Parse batches 2-12 which use numbered entries (1. Title\\nURL:...)."""
    entries = []

    # Split on numbered entries: "N. Title" at start of line
    parts = re.split(r'\n(?=\d+\.\s+[A-Z])', text)

    for part in parts:
        part = part.strip()
        if not part or not re.match(r'^\d+\.', part):
            continue

        # Entry number
        num_match = re.match(r'^(\d+)\.\s*', part)
        entry_num = num_match.group(1) if num_match else "0"

        # Title: everything until URL/Link line
        title_match = re.match(r'^\d+\.\s*(.+?)(?:\n(?:URL|Link|Source URL):|\n)', part, re.DOTALL)
        title = clean_text(title_match.group(1)) if title_match else ""

        # URL/Link
        url_match = re.search(r'(?:URL|Link|Source URL):\s*(https?://\S+)', part)
        url = url_match.group(1).strip() if url_match else ""

        # Source
        source_match = re.search(r'Source:\s*(.+?)(?:\n|$)', part)
        source = clean_text(source_match.group(1)) if source_match else ""
        # Remove date from source if embedded
        source = re.sub(r'\s*Date:.*$', '', source).strip()

        # Date
        date_match = re.search(r'Date:\s*(.+?)(?:\n|$)', part)
        date = clean_text(date_match.group(1)) if date_match else ""
        # Clean up date
        date = re.sub(r'\s*Type:.*$', '', date).strip()
        date = re.sub(r'[\(\)]', '', date).strip()

        # Key excerpt
        excerpt_match = re.search(
            r'(?:Key excerpt.*?|Relevant extract.*?)(?::\s*\n?|:\s*)((?:"[^"]*"|.+?))'
            r'(?:\nWhy|\nAI|\nToolkit|\nNotes|$)',
            part, re.DOTALL
        )
        excerpt = ""
        if excerpt_match:
            excerpt = clean_text(excerpt_match.group(1))
            excerpt = excerpt.strip('"').strip()

        # Why it matters
        why_match = re.search(r'Why this matters.*?:\s*(.+?)(?:\nAI[\-\s]?n?ingestible|$)', part, re.DOTALL)
        why_it_matters = clean_text(why_match.group(1)) if why_match else ""

        # AI-ingestible extract (handles AI-ingestible, AI ingestible, AIningestible variants)
        ai_match = re.search(r'AI[\-\s]?n?ingestible extract:\s*(.+?)(?:\n\d+\.|$)', part, re.DOTALL)
        ai_extract = clean_text(ai_match.group(1)) if ai_match else ""

        if not ai_extract and excerpt:
            ai_extract = excerpt
        if not ai_extract and why_it_matters:
            ai_extract = why_it_matters

        entries.append({
            "entry_id": entry_num,
            "title": title,
            "url": url.rstrip('/'),
            "source": source,
            "date": date,
            "excerpt": excerpt,
            "why_it_matters": why_it_matters,
            "ai_extract": ai_extract,
        })

    return entries


def extract_all_batches():
    """Extract all 12 batch PDFs into structured JSON."""
    os.makedirs(SOURCES_DIR, exist_ok=True)

    all_sources = []
    batch_summaries = []

    for batch_num in range(1, 13):
        print(f"\n--- Batch {batch_num}: {BATCH_THEMES.get(batch_num, '')} ---")
        text = extract_batch_text(batch_num)
        if not text:
            print(f"  SKIPPED: No text extracted")
            continue

        # Parse based on batch format
        if batch_num == 1:
            entries = parse_batch1(text)
        else:
            entries = parse_numbered_entries(text)

        print(f"  Extracted {len(entries)} entries")

        # Build batch data
        batch_data = {
            "batch": batch_num,
            "theme": BATCH_THEMES.get(batch_num, ""),
            "entry_count": len(entries),
            "entries": [],
        }

        for entry in entries:
            source_entry = {
                "batch": batch_num,
                "entry_id": f"batch{batch_num}-{entry['entry_id']}",
                "title": entry["title"],
                "url": entry["url"],
                "source": entry["source"],
                "date": entry["date"],
                "excerpt": entry["excerpt"],
                "why_it_matters": entry["why_it_matters"],
                "ai_extract": entry["ai_extract"],
                "theme": BATCH_THEMES.get(batch_num, ""),
            }
            batch_data["entries"].append(source_entry)
            all_sources.append(source_entry)

            # Show preview
            print(f"  [{entry['entry_id']}] {entry['title'][:60]}")
            if entry["url"]:
                print(f"       URL: {entry['url'][:80]}")

        # Save individual batch JSON
        batch_path = SOURCES_DIR / f"batch{batch_num}.json"
        with open(batch_path, "w", encoding="utf-8") as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)

        batch_summaries.append({
            "batch": batch_num,
            "theme": BATCH_THEMES.get(batch_num, ""),
            "entry_count": len(entries),
        })

    # Save combined sources
    combined = {
        "total_entries": len(all_sources),
        "batch_count": 12,
        "batches": batch_summaries,
        "entries": all_sources,
    }
    combined_path = SOURCES_DIR / "all_sources.json"
    with open(combined_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"TOTAL: {len(all_sources)} source entries across 12 batches")
    print(f"Saved to: {SOURCES_DIR}/")
    print(f"Files: 12 batch JSONs + all_sources.json")

    # Update manifest
    manifest_path = KIT_DIR / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["sources"] = {
            "total_entries": len(all_sources),
            "batch_count": 12,
            "batches": batch_summaries,
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        print("Updated manifest.json with sources metadata")


if __name__ == "__main__":
    extract_all_batches()
