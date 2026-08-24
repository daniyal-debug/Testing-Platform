"""Extended remediation knowledge base.

Each finding ``id`` maps to a long-form fix guide (summary, why it matters,
ordered fix steps, a copy-pasteable code example, how to verify, references).
The report generator merges this with the short remediation carried on each
:class:`~apk_sentinel.models.Finding` to produce the "complete guide" a
developer can follow to fix every issue.

The data lives in ``knowledge_data.py`` (generated / curated separately) so this
module stays small and stable.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from .knowledge_data import KNOWLEDGE  # type: ignore
except Exception:  # pragma: no cover - data file optional
    KNOWLEDGE: Dict[str, Dict[str, Any]] = {}


def get_guide(finding_id: str) -> Optional[Dict[str, Any]]:
    return KNOWLEDGE.get(finding_id)


def has_guide(finding_id: str) -> bool:
    return finding_id in KNOWLEDGE


def all_ids() -> List[str]:
    return sorted(KNOWLEDGE.keys())
