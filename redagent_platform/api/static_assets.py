from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
import re
from redagent_platform.api.contracts import ApiError


def _static_root(configured: Path | None) -> Path | None:
    if configured is None:
        return None
    root = configured.resolve()
    if not root.is_dir() or not (root / "index.html").is_file():
        raise ValueError("static_index_required")
    return root


def _install_static_routes(app: FastAPI, root: Path) -> None:
    async def serve_frontend(spa_path: str) -> FileResponse:
        normalized = spa_path.lstrip("/")
        if (
            normalized == "api"
            or normalized.startswith("api/")
            or normalized == "auth"
            or normalized.startswith("auth/")
        ):
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        candidate = (root / normalized).resolve()
        if not candidate.is_relative_to(root):
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        if candidate.is_file():
            return FileResponse(candidate)
        # IMPORTANT: missing assets and extension-bearing paths must never receive the SPA document.
        if normalized.startswith("assets/") or Path(normalized).suffix:
            raise ApiError(404, "resource_not_found", "The requested resource was not found.")
        return FileResponse(root / "index.html", media_type="text/html")

    app.add_api_route(
        "/{spa_path:path}",
        serve_frontend,
        methods=["GET", "HEAD"],
        include_in_schema=False,
        name="serve_operational_console",
    )


def _is_hashed_asset(path: str) -> bool:
    return bool(re.fullmatch(r"/assets/.+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+", path))
