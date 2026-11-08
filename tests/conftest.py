"""
Pytest configuration that registers the plugin repository root as the
`hermes_werracle_guard` package regardless of how the repository directory is named.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

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
