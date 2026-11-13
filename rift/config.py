"""Rutas de datos y resolucion de workspaces."""

from __future__ import annotations

import os
from pathlib import Path

from .util import slugify


def home() -> Path:
    return Path(os.environ.get("RIFT_HOME", "~/.rift")).expanduser()


def workspaces_dir() -> Path:
    path = home() / "workspaces"
    path.mkdir(parents=True, exist_ok=True)
    return path


def workspace_dir(name: str) -> Path:
    return workspaces_dir() / slugify(name)


def list_workspaces() -> list[str]:
    base = workspaces_dir()
    return sorted(
        item.name
        for item in base.iterdir()
        if item.is_dir() and (item / "scope.json").exists()
    )


def resolve_workspace(name: str | None = None) -> Path:
    if name:
        path = workspace_dir(name)
        if not (path / "scope.json").exists():
            raise FileNotFoundError(f"Workspace no encontrado: {name}")
        return path
    env_name = os.environ.get("RIFT_WORKSPACE")
    if env_name:
        return resolve_workspace(env_name)
    names = list_workspaces()
    if len(names) == 1:
        return workspace_dir(names[0])
    if not names:
        raise FileNotFoundError("No hay workspaces. Crea uno con: rift init --name lab --authorized")
    raise FileNotFoundError(
        "Hay varios workspaces; usa --workspace. Disponibles: " + ", ".join(names)
    )
