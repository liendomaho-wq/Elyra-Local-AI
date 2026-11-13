"""Motor de politicas: autorizacion, alcance, acciones y rate limit."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .scope import Scope, split_target


class PolicyDenied(Exception):
    """La accion solicitada no cumple el alcance o la autorizacion."""


@dataclass
class Decision:
    allowed: bool
    reason: str


class PolicyEngine:
    def __init__(self, scope: Scope, audit: AuditLog, workspace: str = ""):
        self.scope = scope
        self.audit = audit
        self.workspace = workspace
        self._window: dict[str, deque[float]] = {}

    def _rate_ok(self, action: str) -> bool:
        now = time.monotonic()
        bucket = self._window.setdefault(action, deque())
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= self.scope.rate_limit:
            return False
        bucket.append(now)
        return True

    def check(
        self,
        action: str,
        target: str,
        port: int | None = None,
        details: dict | None = None,
        record: bool = True,
    ) -> Decision:
        reason = "ok"
        allowed = True
        if not self.scope.authorized:
            allowed, reason = False, "falta autorizacion explicita"
        elif action not in self.scope.actions:
            allowed, reason = False, f"accion no permitida en el alcance: {action}"
        else:
            try:
                host, target_port, _ = split_target(target)
            except ValueError as exc:
                allowed, reason = False, str(exc)
            else:
                if not self.scope.host_allowed(host):
                    allowed, reason = False, f"host fuera de alcance: {host}"
                elif action != "dns":
                    effective = int(port if port is not None else target_port)
                    if effective not in self.scope.ports_set:
                        allowed, reason = False, f"puerto fuera de alcance: {effective}"
                if allowed and action == "port_scan" and port is not None:
                    if int(port) not in self.scope.ports_set:
                        allowed, reason = False, f"puerto fuera de alcance: {port}"
                if allowed and not self._rate_ok(action):
                    allowed, reason = False, f"rate limit alcanzado para {action}"
        if record:
            self.audit.record(
                action=action,
                target=target,
                decision="allow" if allowed else "deny",
                reason=reason,
                details=details or ({"port": port} if port is not None else {}),
                workspace=self.workspace,
            )
        return Decision(allowed, reason)

    def require(self, action: str, target: str, port: int | None = None) -> None:
        decision = self.check(action, target, port=port)
        if not decision.allowed:
            raise PolicyDenied(decision.reason)
