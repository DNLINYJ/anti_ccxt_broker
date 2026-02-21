"""
ccxt_safe_bootstrap.py — Zero-change CCXT safety bootstrapper
=============================================================
Monkey-patch ccxt so that *any* ``ccxt.<exchange>(config)`` call returns a
safety-hardened instance — without touching a single line of strategy code.

Two modes of activation:

  Mode A (sitecustomize — fully automatic)::

      # Place the provided sitecustomize.py on PYTHONPATH.
      # Python will auto-import it on startup.

  Mode B (explicit one-liner)::

      import ccxt_safe_bootstrap; ccxt_safe_bootstrap.enable()  # at entry-point top

Environment variables
---------------------
CCXT_SAFE_ENABLE   1|0         Master switch (default 1)
CCXT_SAFE_STRICT   1|0         Strict mode — raise on findings (default 1)
CCXT_SAFE_DRY_RUN  1|0         Block all network I/O (default 0)
CCXT_SAFE_AUDIT    raise|warn  Action on suspect field (default raise)
CCXT_SAFE_OPT_IN   1|0         Allow user's own brokerId (default 0)
CCXT_SAFE_LOG      /path       Evidence JSON log file (default stderr)

All heavy lifting is delegated to the existing ``ccxt_safe`` module.
"""

from __future__ import annotations

__all__ = [
    "enable", "disable", "is_enabled", "bootstrap",
    "get_original_class", "status",
]
__version__ = "1.0.0"

import os
import sys
import json
import logging
import datetime
import functools
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------
_patched: bool = False
_original_classes: Dict[str, type] = {}   # exchange_id -> original class

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes")


def _env_str(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(key, "")
    return v if v else default


# ---------------------------------------------------------------------------
# Structured evidence logger
# ---------------------------------------------------------------------------
_evidence_logger: Optional[logging.Logger] = None


def _get_evidence_logger() -> logging.Logger:
    global _evidence_logger
    if _evidence_logger is not None:
        return _evidence_logger
    _evidence_logger = logging.getLogger("ccxt_safe.evidence")
    _evidence_logger.propagate = False
    log_path = _env_str("CCXT_SAFE_LOG")
    if log_path:
        handler: logging.Handler = logging.FileHandler(log_path, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _evidence_logger.addHandler(handler)
    _evidence_logger.setLevel(logging.INFO)
    return _evidence_logger


def _emit(evidence: dict) -> None:
    """Write a structured JSON evidence record."""
    evidence.setdefault("ts", datetime.datetime.utcnow().isoformat() + "Z")
    _get_evidence_logger().info(json.dumps(evidence, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Build SafetyPolicy from environment
# ---------------------------------------------------------------------------

def _build_policy():
    """Return (SafetyPolicy, dry_run_bool) from environment variables."""
    from ccxt_safe import SafetyPolicy
    strict = _env_bool("CCXT_SAFE_STRICT", True)
    opt_in = _env_bool("CCXT_SAFE_OPT_IN", False)
    audit_mode = _env_str("CCXT_SAFE_AUDIT", "raise")
    if audit_mode not in ("raise", "warn"):
        audit_mode = "raise"
    dry_run = _env_bool("CCXT_SAFE_DRY_RUN", False)
    policy = SafetyPolicy(
        strict=strict,
        allow_broker_opt_in=opt_in,
        block_onchain=True,                 # always block onchain ops
        audit_on_findings=audit_mode,
    )
    return policy, dry_run


# ---------------------------------------------------------------------------
# Method-level proxy: create_order / create_orders
# ---------------------------------------------------------------------------

def _wrap_order_methods(exchange, exchange_id: str) -> None:
    """Transparently inject a clean clientOrderId so hardcoded fallbacks
    in ccxt's create_order / sign never trigger a broker-prefixed OID."""
    from ccxt_safe import _CLIENT_OID_KEY, _gen_clean_oid

    oid_key = _CLIENT_OID_KEY.get(exchange_id)
    if not oid_key:
        return

    # ---- create_order ----
    _orig_create_order = exchange.create_order

    @functools.wraps(_orig_create_order)
    def _safe_create_order(symbol, type, side, amount,
                           price=None, params=None):
        params = dict(params or {})
        if oid_key not in params:
            params[oid_key] = _gen_clean_oid()
        return _orig_create_order(symbol, type, side, amount, price, params)

    exchange.create_order = _safe_create_order

    # ---- create_orders (batch) ----
    if hasattr(exchange, "create_orders"):
        _orig_create_orders = exchange.create_orders

        @functools.wraps(_orig_create_orders)
        def _safe_create_orders(orders, *args, **kwargs):
            for o in orders:
                p = o.get("params") or {}
                if oid_key not in p:
                    p[oid_key] = _gen_clean_oid()
                    o["params"] = p
            return _orig_create_orders(orders, *args, **kwargs)

        exchange.create_orders = _safe_create_orders

    # ---- edit_order (same OID logic) ----
    if hasattr(exchange, "edit_order"):
        _orig_edit_order = exchange.edit_order

        @functools.wraps(_orig_edit_order)
        def _safe_edit_order(id, symbol, type, side, amount=None,
                             price=None, params=None):
            params = dict(params or {})
            if oid_key not in params:
                params[oid_key] = _gen_clean_oid()
            return _orig_edit_order(id, symbol, type, side, amount,
                                    price, params)

        exchange.edit_order = _safe_edit_order


# ---------------------------------------------------------------------------
# Install audit + scrubber hooks (with evidence output)
# ---------------------------------------------------------------------------

def _install_audit(exchange, exchange_id: str, policy, dry_run: bool) -> None:
    """Wrap ``sign()`` for scrubbing + audit and ``fetch()`` for dry-run."""
    import ccxt_safe as cs

    original_sign = exchange.sign

    def audited_sign(path, api="public", method="GET",
                     params=None, headers=None, body=None):
        result = original_sign(path, api, method, params, headers, body)

        # 1. Scrub
        if policy.scrub_empty_fields:
            cs._scrub_sign_result(result, exchange_id, policy)

        # 2. Scan for suspects
        r_headers = result.get("headers") or {}
        r_body = result.get("body") or ""
        findings = cs._scan_for_suspects(r_headers, r_body, exchange_id)

        for f in findings:
            f["url"] = result.get("url", "")
            f["method"] = method
            _emit(f)
            if policy.audit_on_findings == "raise":
                raise cs.SafeBlockedError(
                    f"[AUDIT][{exchange_id}] suspect field: "
                    f"{json.dumps(f, ensure_ascii=False)}"
                )
        return result

    exchange.sign = audited_sign

    if dry_run:
        def blocked_fetch(url, method="GET", headers=None, body=None):
            raise cs.AuditInterceptError(method, url, headers, body)
        exchange.fetch = blocked_fetch


# ---------------------------------------------------------------------------
# Core: apply all safety measures to a live exchange instance
# ---------------------------------------------------------------------------

def _apply_safety(exchange, exchange_id: str,
                  user_options: Optional[Dict[str, Any]] = None) -> None:
    """Post-construction safety hardening — called automatically by wrapper."""
    import ccxt_safe as cs

    policy, dry_run = _build_policy()
    user_options = user_options or {}

    # --- 1. Apply SAFE_OVERRIDES, respecting opt-in ---
    safe_opts = dict(cs.SAFE_OVERRIDES.get(exchange_id, {}))

    for k, v in safe_opts.items():
        user_set = k in user_options
        user_val = user_options.get(k)

        if user_set and k in cs.PROTECTED_KEYS and user_val != v:
            if policy.allow_broker_opt_in:
                # Reject CCXT default values even in opt-in
                if isinstance(user_val, str) and user_val in cs.KNOWN_BROKER_VALUES:
                    _emit({"exchange": exchange_id, "type": "blocked",
                           "key": k, "value": str(user_val),
                           "reason": "known_ccxt_default"})
                    # fall through → override with safe value
                else:
                    _emit({"exchange": exchange_id, "type": "opt_in",
                           "key": k, "value": str(user_val)})
                    # keep user's custom value, do NOT override
                    continue
            else:
                _emit({"exchange": exchange_id, "type": "override",
                       "key": k, "value": str(user_val),
                       "reason": "protected_key_forced"})
                # fall through → override

        exchange.options[k] = v

    # --- 2. Store policy ---
    exchange._ccxt_safe_policy = policy

    # --- 3. Hyperliquid on-chain blocking ---
    if exchange_id == "hyperliquid":
        cs._patch_hyperliquid(exchange, policy)

    # --- 4. Fail-closed verification ---
    if exchange_id in cs.HIGH_RISK_EXCHANGES:
        cs._verify_overrides(exchange, exchange_id, policy)

    # --- 5. Audit + scrubber hooks (with evidence output) ---
    _install_audit(exchange, exchange_id, policy, dry_run)

    # --- 6. Method-level transparent proxy ---
    _wrap_order_methods(exchange, exchange_id)

    # --- 7. Stamp ---
    exchange._ccxt_safe_bootstrap = True


# ---------------------------------------------------------------------------
# Dynamic safe-wrapper class factory
# ---------------------------------------------------------------------------

def _make_safe_class(original_class: type, exchange_id: str) -> type:
    """Create a subclass that auto-applies safety in ``__init__``.

    The subclass inherits from the original so that:
      - ``isinstance(ex, ccxt.Exchange)``  → True
      - ``isinstance(ex, original_class)`` → True
      - All methods, descriptors, and class attributes are preserved.
    """

    class _SafeWrapper(original_class):
        def __init__(self, config=None):
            if config is None:
                config = {}
            # Snapshot user-supplied options BEFORE super().__init__ merges them
            _user_opts = dict(config.get("options") or {}) if isinstance(config, dict) else {}
            super().__init__(config)
            # If bootstrap is disabled at runtime, skip patching
            if not _env_bool("CCXT_SAFE_ENABLE", True):
                return
            _apply_safety(self, exchange_id, _user_opts)

    # Preserve class identity for debugging / logging
    _SafeWrapper.__name__ = original_class.__name__
    _SafeWrapper.__qualname__ = original_class.__qualname__
    _SafeWrapper.__module__ = original_class.__module__
    _SafeWrapper.__doc__ = original_class.__doc__
    _SafeWrapper._ccxt_safe_original = original_class

    return _SafeWrapper


# ===================================================================
# Public API
# ===================================================================

def enable() -> None:
    """Monkey-patch ``ccxt`` so every exchange constructor returns a safe
    instance.  Idempotent — safe to call multiple times.

    **Mode B entry point.**
    """
    global _patched
    if _patched:
        return
    if not _env_bool("CCXT_SAFE_ENABLE", True):
        return

    import ccxt  # noqa: E402  — must import here (lazy)

    patched_count = 0
    for eid in list(ccxt.exchanges):
        orig = getattr(ccxt, eid, None)
        if orig is None or not isinstance(orig, type):
            continue
        if hasattr(orig, "_ccxt_safe_original"):
            continue  # already wrapped (should not happen)
        _original_classes[eid] = orig
        setattr(ccxt, eid, _make_safe_class(orig, eid))
        patched_count += 1

    _patched = True
    _emit({"type": "bootstrap", "action": "enabled",
           "exchanges_patched": patched_count,
           "version": __version__})


def disable() -> None:
    """Restore all original ccxt exchange classes (un-patch).

    Existing exchange instances that were already created remain safe —
    only *new* instances will be unprotected.
    """
    global _patched
    if not _patched:
        return
    import ccxt

    for eid, orig in _original_classes.items():
        setattr(ccxt, eid, orig)
    count = len(_original_classes)
    _original_classes.clear()
    _patched = False
    _emit({"type": "bootstrap", "action": "disabled",
           "exchanges_restored": count})


def is_enabled() -> bool:
    """Return ``True`` if the monkey-patch is currently active."""
    return _patched


def get_original_class(exchange_id: str):
    """Return the original (un-patched) class for *exchange_id*, or None."""
    return _original_classes.get(exchange_id)


def status() -> dict:
    """Return a dict summarising current bootstrap status."""
    return {
        "enabled": _patched,
        "version": __version__,
        "exchanges_patched": len(_original_classes),
        "env": {
            "CCXT_SAFE_ENABLE": _env_bool("CCXT_SAFE_ENABLE", True),
            "CCXT_SAFE_STRICT": _env_bool("CCXT_SAFE_STRICT", True),
            "CCXT_SAFE_DRY_RUN": _env_bool("CCXT_SAFE_DRY_RUN", False),
            "CCXT_SAFE_AUDIT": _env_str("CCXT_SAFE_AUDIT", "raise"),
            "CCXT_SAFE_OPT_IN": _env_bool("CCXT_SAFE_OPT_IN", False),
            "CCXT_SAFE_LOG": _env_str("CCXT_SAFE_LOG"),
        },
    }


def bootstrap() -> None:
    """Entry point for ``sitecustomize.py`` — identical to :func:`enable`."""
    enable()
