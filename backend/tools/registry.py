"""
Tool registry — loads and validates tools.yaml.

One source of truth for the whole app. If the YAML is malformed or a tool is
missing a required field, we fail loudly HERE (at load time) instead of
halfway through a scan. This is what prevented v2's catalog/executor drift.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from ..safety import NOISE_ORDER

TOOLS_FILE = Path(__file__).with_name("tools.yaml")
VALID_CATEGORIES = {"recon", "exploit", "defensive", "analysis"}
VALID_EXEC_MODES = {"local", "docker", "python"}
REQUIRED_FIELDS = ("id", "name", "category", "input_type", "noise", "exec")


class ToolSpecError(Exception):
    """Raised when a tool definition in tools.yaml is invalid."""


def _validate(tool: dict) -> None:
    tid = tool.get("id", "<no id>")
    for field in REQUIRED_FIELDS:
        if field not in tool:
            raise ToolSpecError(f"Tool '{tid}' is missing required field '{field}'")
    if tool["category"] not in VALID_CATEGORIES:
        raise ToolSpecError(f"Tool '{tid}' has invalid category '{tool['category']}'")
    if tool["noise"] not in NOISE_ORDER:
        raise ToolSpecError(f"Tool '{tid}' has invalid noise '{tool['noise']}'")
    exec_spec = tool.get("exec") or {}
    if not exec_spec:
        raise ToolSpecError(f"Tool '{tid}' has no exec modes")
    unknown = set(exec_spec) - VALID_EXEC_MODES
    if unknown:
        raise ToolSpecError(f"Tool '{tid}' has unknown exec mode(s): {unknown}")
    tool.setdefault("parser", "generic")


@lru_cache(maxsize=1)
def load_tools() -> dict[str, dict]:
    """Return {tool_id: tool_dict}. Cached; raises on any invalid tool."""
    raw = yaml.safe_load(TOOLS_FILE.read_text(encoding="utf-8")) or []
    tools: dict[str, dict] = {}
    for tool in raw:
        _validate(tool)
        if tool["id"] in tools:
            raise ToolSpecError(f"Duplicate tool id '{tool['id']}'")
        tools[tool["id"]] = tool
    return tools


def get_tool(tool_id: str) -> dict | None:
    return load_tools().get(tool_id)


def list_tools(category: str | None = None) -> list[dict]:
    tools = list(load_tools().values())
    if category and category != "all":
        tools = [t for t in tools if t["category"] == category]
    return tools
