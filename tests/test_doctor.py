"""
Unit tests for Werracle EVM Guard plugin manifest (`plugin.yaml`) and `register(ctx)` lifecycle.
Verifies strict compliance with `hermes_cli/plugin_validate.py` top-level field rules.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR.parent))

from hermes_werracle_guard import register  # noqa: E402
from hermes_werracle_guard.radar_client import get_engine  # noqa: E402


class DummyPluginContext:
    def __init__(self, custom_config: Dict[str, Any] | None = None) -> None:
        self.tools: List[str] = []
        self.hooks: List[str] = []
        self.cli_commands: List[str] = []
        self._config: Dict[str, Any] = custom_config or {}

    def get_config(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def register_tool(
        self,
        name: str,
        toolset: str,
        schema: Dict[str, Any],
        handler: Callable[..., Any],
        **kwargs: Any,
    ) -> None:
        self.tools.append(name)

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
        self.hooks.append(hook_name)

    def register_command(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str = "",
        args_hint: str = "",
        argument_mode: str | None = None,
    ) -> None:
        self.cli_commands.append(name)

    def register_cli_command(self, name: str, help_text: str = "", handler: Callable[..., Any] | None = None) -> None:
        self.cli_commands.append(name)


def test_plugin_yaml_manifest_top_level_schema() -> None:
    """
    Verify plugin.yaml declares provides_tools, provides_hooks, requires_env, and config_schema
    at the top level (as required by hermes_cli/plugin_validate.py).
    """
    manifest_path = ROOT_DIR / "plugin.yaml"
    assert manifest_path.exists(), "plugin.yaml must exist"
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    assert data["name"] == "werracle-evm-guard"
    assert "version" in data
    assert "description" in data
    assert "api.werracle.com" in data["description"]
    assert "known drainers" not in data["description"].lower()
    assert "web3 rpc calls" not in data["description"].lower()

    # Must be at top level, NOT nested under capabilities
    assert "capabilities" not in data
    assert isinstance(data.get("provides_tools"), list)
    assert len(data["provides_tools"]) == 4
    assert isinstance(data.get("provides_hooks"), list)
    assert "pre_tool_call" in data["provides_hooks"]
    assert "post_tool_call" in data["provides_hooks"]
    assert data.get("requires_env") == ["WERRACLE_API_KEY"]
    assert "config_schema" in data and "api_url" in data["config_schema"]


def test_register_matches_manifest_declarations() -> None:
    """Ensure every tool and hook registered in register(ctx) matches top-level plugin.yaml."""
    manifest = yaml.safe_load((ROOT_DIR / "plugin.yaml").read_text(encoding="utf-8"))
    ctx = DummyPluginContext(custom_config={"api_url": "https://api.werracle.com/v1/radar"})
    register(ctx)

    assert set(ctx.tools) == set(manifest["provides_tools"])
    assert set(ctx.hooks) == set(manifest["provides_hooks"])
    assert "werracle" in ctx.cli_commands
    assert get_engine().api_url == "https://api.werracle.com/v1/radar"


def test_catalog_entry_schema_compliance() -> None:
    """Ensure hermes-catalog-entry.yaml strictly complies with scripts/validate_plugin_catalog.py."""
    catalog_path = ROOT_DIR / "hermes-catalog-entry.yaml"
    assert catalog_path.exists()
    data = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))

    required_keys = {"name", "repo", "sha", "description", "maintainer"}
    known_keys = {
        "name",
        "repo",
        "sha",
        "subdir",
        "description",
        "maintainer",
        "tier",
        "category",
        "requires_hermes",
        "docs_url",
        "version",
        "image",
        "screenshots",
        "readme",
        "platforms",
        "capabilities",
        "title",
        "onboarding",
        "known_issues",
        "attested_binaries",
    }
    capability_keys = {"provides_tools", "provides_hooks", "provides_middleware", "requires_env"}

    assert required_keys.issubset(data.keys())
    assert set(data.keys()).issubset(known_keys)
    assert set(data["capabilities"].keys()).issubset(capability_keys)
    assert data["maintainer"] == "pCwOrM"
    assert data["category"] == "tools"
    assert data["tier"] == "community"
