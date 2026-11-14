"""Hermes Agent plugin specification compliance tests for werracle-evm-guard."""

from __future__ import annotations

import importlib.util
import inspect
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List

import yaml

PLUGIN_DIR = Path(__file__).resolve().parent.parent

KNOWN_MANIFEST_KEYS = frozenset(
    {
        "name",
        "version",
        "description",
        "author",
        "requires_env",
        "provides_tools",
        "provides_hooks",
        "hooks",
        "provides_middleware",
        "kind",
        "requires_hermes",
        "capabilities",
        "manifest_version",
        "api_version",
        "requires_plugins",
        "python_dependencies",
        "pip_dependencies",
        "python_runtime",
        "config_schema",
        "license",
        "homepage",
        "tags",
        "emits",
        "listens",
        "provides_locales",
        "config_keys",
        "oauth",
        "requires_auth",
        "mcp_servers",
        "runtime",
    }
)


class _RecordingCtx:
    plugin_config: Dict[str, Any] = {}

    def __init__(self) -> None:
        self.tools: List[Dict[str, Any]] = []
        self.hooks: Dict[str, Any] = {}
        self.commands: Dict[str, Any] = {}

    def register_tool(self, name: str, toolset: str, schema: Dict[str, Any], handler: Any, **kwargs: Any) -> None:
        self.tools.append({"name": name, "toolset": toolset, "schema": schema, "handler": handler, "kwargs": kwargs})

    def register_hook(self, hook_name: str, callback: Any, **kwargs: Any) -> None:
        self.hooks[hook_name] = callback

    def register_command(self, name: str, handler: Any, **kwargs: Any) -> None:
        self.commands[name] = handler

    def register_cli_command(self, name: str, *args: Any, **kwargs: Any) -> None:
        pass


def _load_plugin():
    mod_name = "hermes_weg_compliance_probe"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_openai_tool_schemas_and_kwargs() -> None:
    mod = _load_plugin()
    ctx = _RecordingCtx()
    mod.register(ctx)

    assert len(ctx.tools) == 4
    for entry in ctx.tools:
        schema = entry["schema"]
        assert schema.get("name") == entry["name"]
        assert isinstance(schema.get("description"), str) and schema["description"].strip()
        params = schema.get("parameters")
        assert isinstance(params, dict) and params.get("type") == "object"
        sig = inspect.signature(entry["handler"])
        assert any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())


def test_manifest_and_zero_dep_pyproject_compliance() -> None:
    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8-sig"))
    unknown = set(manifest.keys()) - KNOWN_MANIFEST_KEYS
    assert not unknown, f"Unexpected keys in plugin.yaml: {sorted(unknown)}"
    assert manifest.get("requires_hermes") == ">=0.21.0"
    assert "tags" in manifest and "categories" not in manifest

    assert not (PLUGIN_DIR / "schemas.py").exists()

    pyproj = tomllib.loads((PLUGIN_DIR / "pyproject.toml").read_text(encoding="utf-8-sig"))
    assert "build-system" not in pyproj
    assert pyproj["project"].get("dependencies") == []
    assert "optional-dependencies" not in pyproj["project"]
