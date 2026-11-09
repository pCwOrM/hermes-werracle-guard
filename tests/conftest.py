"""
Pytest configuration that registers the plugin repository root as the
`hermes_werracle_guard` package and provides a standalone `agent.secret_scope`
test stub when running outside the Hermes runtime.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

if "agent.secret_scope" not in sys.modules:
    try:
        import agent.secret_scope  # type: ignore  # noqa: F401
    except ImportError:
        fake_agent = types.ModuleType("agent")
        fake_secret_scope = types.ModuleType("agent.secret_scope")

        class UnscopedSecretError(RuntimeError):
            pass

        def get_secret(name: str, default: str | None = None) -> str | None:
            return os.environ.get(name, default)

        def get_secret_str(name: str, default: str = "") -> str:
            val = get_secret(name, default)
            return default if val is None else val

        fake_secret_scope.UnscopedSecretError = UnscopedSecretError  # type: ignore
        fake_secret_scope.get_secret = get_secret  # type: ignore
        fake_secret_scope.get_secret_str = get_secret_str  # type: ignore
        fake_agent.secret_scope = fake_secret_scope  # type: ignore
        sys.modules["agent"] = fake_agent
        sys.modules["agent.secret_scope"] = fake_secret_scope

if "hermes_werracle_guard" not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        "hermes_werracle_guard",
        ROOT_DIR / "__init__.py",
        submodule_search_locations=[str(ROOT_DIR)],
    )
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules["hermes_werracle_guard"] = module
        spec.loader.exec_module(module)
