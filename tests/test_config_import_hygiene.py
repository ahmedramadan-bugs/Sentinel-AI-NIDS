"""
tests/test_config_import_hygiene.py
====================================
Guard: no bare-value config imports that silently freeze on import.

The bug pattern:
    from .config import WHITELIST_FILE      # freezes at import time
    import response_engine.config as _re_config  # safe, always live

configure_runtime() reassigns module-level names (WHITELIST_FILE, DATA_DIR,
TEMP_BLOCKS_FILE, ACTION_HISTORY_FILE) AFTER the rest of the codebase is
imported.  Any module that imported those bare values will silently keep using
the stale pre-configure_runtime() snapshot.

This test scans the source tree and FAILS immediately if such an import is
found, preventing the bug from being reintroduced silently.
"""

import ast
import os
import unittest
from pathlib import Path

# ── Names that are SAFE to import bare (classes, singletons, functions) ───────
_SAFE_NAMES = frozenset({
    "EngineConfig", "CiscoConfig", "LoggerConfig", "Messages", "Settings",
    "configure_runtime",
    "CiscoBackend", "EngineLogger", "ActionResult", "BlockedIP", "EngineStats",
    "ResponseEngine",
    # LOG_DIR and LOG_FILE are computed from PROJECT_ROOT and are never changed
    # by configure_runtime() — safe to import bare.
    "LOG_DIR", "LOG_FILE", "LoggerConfig",
})

# ── Names that are DANGEROUS: mutated by configure_runtime() with `global` ────
_DANGEROUS_NAMES = frozenset({
    "DATA_DIR",
    "WHITELIST_FILE",
    "ACTION_HISTORY_FILE",
    "TEMP_BLOCKS_FILE",
})

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCAN_ROOTS = [
    _PROJECT_ROOT / "response_engine",
    _PROJECT_ROOT / "nids",
    _PROJECT_ROOT / "collectors",
]
_SCAN_EXTRA = [_PROJECT_ROOT / "run_nids.py"]

_SKIP_FILENAMES = frozenset({"config.py"})
_SKIP_DIRS = frozenset({"__pycache__", ".venv", "tests", ".git"})


def _scan_file(path: Path) -> list:
    violations = []
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=str(path))
    except (SyntaxError, OSError):
        return violations
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        mod = node.module or ""
        if "config" not in mod:
            continue
        for alias in node.names:
            name = alias.name
            if name in _SAFE_NAMES:
                continue
            if name in _DANGEROUS_NAMES:
                rel = path.relative_to(_PROJECT_ROOT)
                violations.append(
                    f"  {rel}:{node.lineno}  from {mod} import {name}  "
                    f"(bare-value import — freezes at import time)"
                )
    return violations


class TestConfigImportHygiene(unittest.TestCase):
    """Structural guard: detect bare-value config imports that freeze on import."""

    def test_no_bare_value_config_imports(self):
        """Any 'from .config import WHITELIST_FILE' style import of the
        names mutated by configure_runtime() must not exist in the codebase.
        Use 'import response_engine.config as _re_config' and access
        '_re_config.WHITELIST_FILE' dynamically at the point of use instead.
        """
        all_violations = []
        files = []
        for root in _SCAN_ROOTS:
            if not root.exists():
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for fname in filenames:
                    if fname.endswith(".py") and fname not in _SKIP_FILENAMES:
                        files.append(Path(dirpath) / fname)
        for extra in _SCAN_EXTRA:
            if extra.exists():
                files.append(extra)

        for path in files:
            all_violations.extend(_scan_file(path))

        if all_violations:
            self.fail(
                "Bare-value config imports found — these freeze when "
                "configure_runtime() runs:\n\n"
                + "\n".join(all_violations)
                + "\n\nFix: use 'import response_engine.config as _re_config' "
                "and reference '_re_config.<NAME>' at call time."
            )


if __name__ == "__main__":
    unittest.main()
