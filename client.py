"""Pi-hole v6 API client with session management."""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

# Known public DNS resolvers — used by bypass detection
PUBLIC_DNS_IPS = {
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare
    "9.9.9.9",       # Quad9
    "149.112.112.112",  # Quad9
    "208.67.222.222",   # OpenDNS
    "208.67.220.220",   # OpenDNS
    "64.6.64.6",     # Verisign
    "64.6.65.6",     # Verisign
}


class PiholeClient:
    """Context manager that handles Pi-hole v6 session auth and logout.

    Usage:
        async with PiholeClient() as client:
            data = await client.get("/api/stats/summary")
    """

    def __init__(
        self,
        base_url: str | None = None,
        password: str | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ["PIHOLE_URL"]).rstrip("/")
        self._password = password or os.environ["PIHOLE_APP_PASSWORD"]
        self._sid: str | None = None
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "PiholeClient":
        self._http = httpx.AsyncClient(base_url=self.base_url, timeout=30)
        await self._login()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            await self._logout()
        finally:
            if self._http:
                await self._http.aclose()
                self._http = None

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _login(self) -> None:
        assert self._http is not None
        resp = await self._http.post(
            "/api/auth",
            json={"password": self._password},
        )
        resp.raise_for_status()
        body = resp.json()
        # v6 returns {"session": {"sid": "...", "valid": true, ...}}
        session = body.get("session", {})
        if not session.get("valid"):
            raise RuntimeError(
                f"Pi-hole login failed — check your app password. Response: {body}"
            )
        self._sid = session["sid"]

    async def _logout(self) -> None:
        if not self._sid or not self._http:
            return
        try:
            resp = await self._http.delete(
                "/api/auth",
                headers=self._auth_headers(),
            )
            # 204 = success; ignore other codes on logout
            _ = resp
        except Exception:
            pass  # best-effort logout — never raise here
        finally:
            self._sid = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        if not self._sid:
            raise RuntimeError("Not authenticated — use 'async with PiholeClient()'")
        return {"X-FTL-SID": self._sid}

    async def get(self, path: str, **params: Any) -> Any:
        """GET /api/<path> and return parsed JSON body."""
        assert self._http is not None
        resp = await self._http.get(
            path,
            params={k: v for k, v in params.items() if v is not None},
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        return resp.json()
