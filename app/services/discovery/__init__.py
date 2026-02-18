"""Discovery service package for automated tool discovery pipeline."""
from app.services.discovery.sources import DiscoverySource, RawToolData
from app.services.discovery.pipeline import run_discovery_pipeline, process_discovered_tool
from app.services.discovery.dedup import deduplicate_tool, normalize_name, extract_domain

__all__ = [
    "DiscoverySource",
    "RawToolData",
    "run_discovery_pipeline",
    "process_discovered_tool",
    "deduplicate_tool",
    "normalize_name",
    "extract_domain",
]
