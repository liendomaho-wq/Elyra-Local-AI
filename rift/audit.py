"""Audit log append-only con cadena SHA-256 de decisiones y acciones."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .util import canonical_json, sha256_hex, utcnow

GENESIS = "0" * 64
_LOCK = threading.Lock()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)

    def entries(self) -> list[dict]:
        return self._read()[0]

    def _read(self) -> tuple[list[dict], list[str]]:
        items: list[dict] = []
        errors: list[str] = []
        if not self.path.exists():
            return items, errors
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    item = json.loads(text)
                except ValueError:
                    errors.append(f"linea {line_number}: JSON invalido")
                    continue
                if not isinstance(item, dict):
                    errors.append(f"linea {line_number}: entrada invalida")
                    continue
                items.append(item)
        return items, errors

    def record(
        self,
        action: str,
        target: str,
        decision: str,
        reason: str,
        details: dict | None = None,
        workspace: str = "",
    ) -> dict:
        with _LOCK:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            entries = self.entries()
            previous = entries[-1].get("hash") if entries else GENESIS
            entry = {
                "seq": len(entries) + 1,
                "ts": utcnow(),
                "workspace": workspace,
                "action": action,
                "target": target,
                "decision": decision,
                "reason": reason,
                "details": details or {},
                "prev_hash": previous,
            }
            entry["hash"] = sha256_hex(previous + canonical_json(entry))
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(entry) + "\n")
            return entry

    def verify(self) -> dict:
        entries, parse_errors = self._read()
        errors = list(parse_errors)
        previous = GENESIS
        for index, entry in enumerate(entries, start=1):
            if entry.get("seq") != index:
                errors.append(f"entrada {index}: secuencia inesperada")
            if entry.get("prev_hash") != previous:
                errors.append(f"entrada {index}: prev_hash no coincide")
            payload = {key: value for key, value in entry.items() if key != "hash"}
            if entry.get("hash") != sha256_hex(previous + canonical_json(payload)):
                errors.append(f"entrada {index}: hash invalido")
            previous = str(entry.get("hash") or previous)
        return {
            "ok": not errors,
            "entries": len(entries),
            "root": previous,
            "errors": errors,
        }
