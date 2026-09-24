"""Deterministic crash injection for real kill-process testing.

A crash point is a labelled place in the storage/chain code. The harness
enables exactly one point through the environment::

    AUDIT_CHAIN_FAULT=<point-id>
    AUDIT_CHAIN_FAULT_SIGNAL=<signal>   (optional, default SIGKILL)

Point ids themselves contain colons (``migrate:publish``), so the optional
signal override is a separate variable rather than a suffix.

The mapping is read once at first touch and cached; a point that has already
fired cannot fire twice in the same (hypothetically continued) process.
"""

from __future__ import annotations

import os
import signal
from typing import Optional

_ENV_VAR = "AUDIT_CHAIN_FAULT"
_SIGNAL_VAR = "AUDIT_CHAIN_FAULT_SIGNAL"
_DEFAULT_SIGNAL = signal.SIGKILL
_fired = False
_loaded = False
_point: Optional[str] = None
_signal: int = _DEFAULT_SIGNAL


def _load() -> None:
    global _loaded, _point, _signal
    if _loaded:
        return
    _loaded = True
    raw = os.environ.get(_ENV_VAR, "")
    if not raw:
        return
    _point = raw
    signame = os.environ.get(_SIGNAL_VAR, "")
    if signame:
        try:
            _signal = int(signame)
        except ValueError:
            _signal = getattr(signal, signame, _DEFAULT_SIGNAL)


def reset() -> None:
    """Forget the configured point (tests only)."""
    global _fired, _loaded, _point, _signal
    _fired = False
    _loaded = False
    _point = None
    _signal = _DEFAULT_SIGNAL


def crash_point(point_id: str) -> None:
    """Kill this process immediately when ``point_id`` is the armed point."""
    global _fired
    _load()
    if _fired or _point != point_id:
        return
    _fired = True
    os.kill(os.getpid(), _signal)
    # Signals such as SIGKILL cannot be handled; if a platform delivered a
    # catchable signal and execution somehow continued, stop hard anyway.
    os._exit(137)
