from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from redagent_platform.api.app import create_app


def test_hardened_spa_serving_never_shadows_api_or_auth(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text("<main>compat_095 console</main>", encoding="utf-8")
    (assets / "index-AbCd1234.js").write_text("export {};", encoding="utf-8")

    async def scenario() -> None:
        app = create_app(test_issuer_enabled=True, static_directory=dist)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            root = await client.get("/")
            assert root.status_code == 200
            assert "compat_095 console" in root.text
            assert root.headers["cache-control"] == "no-store"
            assert "script-src 'self'" in root.headers["content-security-policy"]

            route = await client.get("/engagements")
            assert route.status_code == 200
            assert route.headers["content-type"].startswith("text/html")

            asset = await client.get("/assets/index-AbCd1234.js")
            assert asset.status_code == 200
            assert "immutable" in asset.headers["cache-control"]
            assert asset.headers["x-content-type-options"] == "nosniff"

            unknown_api = await client.get("/api/v1/not-a-route")
            assert unknown_api.status_code == 404
            assert unknown_api.headers["content-type"].startswith("application/json")
            assert "compat_095 console" not in unknown_api.text

            unknown_auth = await client.get("/auth/not-a-route")
            assert unknown_auth.status_code == 404
            assert "compat_095 console" not in unknown_auth.text

            missing_asset = await client.get("/assets/missing.js")
            assert missing_asset.status_code == 404
            assert "compat_095 console" not in missing_asset.text

    asyncio.run(scenario())


def test_static_root_requires_a_real_built_index(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="static_index_required"):
        create_app(test_issuer_enabled=True, static_directory=tmp_path)
