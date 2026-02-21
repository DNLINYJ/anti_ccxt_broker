"""
sitecustomize.py — Mode A: automatic CCXT safety bootstrap
===========================================================
Place this file on your PYTHONPATH (or in site-packages) and Python will
auto-import it on every interpreter startup.

Usage::

    # Option 1: Copy to site-packages
    cp sitecustomize.py $(python -c "import site; print(site.getsitepackages()[0])")/

    # Option 2: Set PYTHONPATH
    export PYTHONPATH=/path/to/dir/containing/this/file:$PYTHONPATH

    # Then just run your strategy — no code changes needed:
    python my_strategy.py

Disable without removing the file::

    CCXT_SAFE_ENABLE=0 python my_strategy.py
"""

import os

def _safe_bootstrap():
    """Guard: only bootstrap when master switch is on (default: on)."""
    enable = os.environ.get("CCXT_SAFE_ENABLE", "1").strip().lower()
    if enable in ("0", "false", "no"):
        return
    try:
        import ccxt_safe_bootstrap
        ccxt_safe_bootstrap.bootstrap()
    except ImportError:
        # ccxt_safe_bootstrap not on path — silently skip
        import sys
        print(
            "[sitecustomize] WARNING: ccxt_safe_bootstrap not found on path. "
            "CCXT safety patch NOT applied.",
            file=sys.stderr,
        )
    except Exception as exc:
        import sys
        print(
            f"[sitecustomize] ERROR during CCXT safety bootstrap: {exc}",
            file=sys.stderr,
        )

_safe_bootstrap()
