"""GitHub Actions integration: workflow-command annotations and the job summary."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def annotations(report: Dict[str, Any]) -> List[str]:
    """One workflow command per finding, e.g. `::error title=AgentSec CRITICAL::...`."""
    out = []
    for f in report["findings"]:
        title = "AgentSec %s" % f["severity"].upper()
        message = "%s%s (%s)" % (f["title"], " [irreversible]" if f.get("irreversible") else "", f["scenario_id"])
        out.append("::%s title=%s::%s" % (_LEVEL[f["severity"]], _escape_prop(title), _escape_data(message)))
    return out


def in_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def step_summary_path() -> Optional[str]:
    return os.environ.get("GITHUB_STEP_SUMMARY") or None


def append_step_summary(markdown: str) -> Optional[str]:
    path = step_summary_path()
    if not path:
        return None
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(markdown + "\n")
    return path
