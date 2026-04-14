"""Pi-hole v6 API client with session management."""

from __future__ import annotations

import asyncio
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

# ---------------------------------------------------------------------------
# MAC OUI vendor lookup (bundled — no external service needed)
# First 3 bytes of MAC (uppercase, no separators) → manufacturer name
# Covers the most common consumer device vendors in home networks.
# ---------------------------------------------------------------------------

_OUI_VENDORS: dict[str, str] = {
    # Apple
    "000A27": "Apple", "000D93": "Apple", "0010FA": "Apple", "001124": "Apple",
    "001451": "Apple", "0016CB": "Apple", "001731": "Apple", "001B63": "Apple",
    "001CF0": "Apple", "001E52": "Apple", "001EC2": "Apple", "0021E9": "Apple",
    "002241": "Apple", "002312": "Apple", "002436": "Apple", "0025BC": "Apple",
    "002608": "Apple", "003065": "Apple", "0050E4": "Apple", "0017F2": "Apple",
    "3C0754": "Apple", "3C15C2": "Apple", "5C8D4E": "Apple", "A8BE27": "Apple",
    "D89695": "Apple", "F0DBE2": "Apple", "F4F15A": "Apple",
    # Samsung
    "000DB9": "Samsung", "0007AB": "Samsung", "001632": "Samsung",
    "002119": "Samsung", "0024E9": "Samsung", "002566": "Samsung",
    "0026E2": "Samsung", "00E3B2": "Samsung", "083D88": "Samsung",
    "1C232C": "Samsung", "286C07": "Samsung", "2C0E3D": "Samsung",
    "2CAE2B": "Samsung", "38AA3C": "Samsung", "3CB87A": "Samsung",
    "4098AD": "Samsung", "445006": "Samsung", "5C3C27": "Samsung",
    "6006A0": "Samsung", "6C2F2C": "Samsung", "6CB7F4": "Samsung",
    "84A466": "Samsung", "8C7712": "Samsung", "980CD4": "Samsung",
    "A02195": "Samsung", "A4EB75": "Samsung", "CC07AB": "Samsung",
    # Amazon
    "0C4785": "Amazon", "34D270": "Amazon", "40B4CD": "Amazon",
    "44650D": "Amazon", "68370E": "Amazon", "74C246": "Amazon",
    "789C85": "Amazon", "84D6D0": "Amazon", "A002DC": "Amazon",
    "B47C9C": "Amazon", "FC65DE": "Amazon",
    # Google / Nest
    "1C9AD2": "Google", "3851B6": "Google", "54604A": "Google",
    "6C4008": "Google", "94EB2C": "Google", "A47733": "Google",
    "C819F7": "Google", "DC4F22": "Google", "E4F0AF": "Google",
    "F88FCA": "Google", "000F66": "Google", "5CF370": "Google",
    # Microsoft
    "001DD8": "Microsoft", "0025AE": "Microsoft", "0050F2": "Microsoft",
    "28184D": "Microsoft", "485073": "Microsoft", "60456C": "Microsoft",
    "7825AD": "Microsoft", "A0999B": "Microsoft",
    # Sony
    "001A80": "Sony", "001D0D": "Sony", "001EBE": "Sony", "0022A9": "Sony",
    "002618": "Sony", "0050F1": "Sony", "18002D": "Sony", "28FDEB": "Sony",
    "30F9ED": "Sony", "40B834": "Sony", "FCF152": "Sony",
    # LG Electronics
    "001C62": "LG", "001E75": "LG", "002483": "LG", "002659": "LG",
    "0025E5": "LG", "0026E7": "LG", "34DF2A": "LG", "3851B6": "LG",
    "480F6E": "LG", "5C4974": "LG", "A87740": "LG", "CC2D8C": "LG",
    # Roku
    "B0A737": "Roku", "CC6EB0": "Roku", "D8316B": "Roku",
    "DCA96A": "Roku", "E87750": "Roku",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    # Nintendo
    "001656": "Nintendo", "001FC5": "Nintendo", "002459": "Nintendo",
    "0009BF": "Nintendo", "00191D": "Nintendo", "00224C": "Nintendo",
    "7CBB8A": "Nintendo", "98B6E9": "Nintendo", "9CEE18": "Nintendo",
    # Sony PlayStation
    "000D3A": "Sony PlayStation", "001315": "Sony PlayStation",
    "0019C5": "Sony PlayStation", "001FA7": "Sony PlayStation",
    "F8461C": "Sony PlayStation",
    # Sonos
    "000E58": "Sonos", "349754": "Sonos", "5CAAFE": "Sonos",
    "78288C": "Sonos", "94901C": "Sonos", "B8E937": "Sonos",
    # Philips Hue / Signify
    "001788": "Philips Hue", "ECB5FA": "Philips Hue",
    # TP-Link
    "0C8268": "TP-Link", "14CC20": "TP-Link", "18D61C": "TP-Link",
    "1C3BF3": "TP-Link", "28EE52": "TP-Link", "3460F9": "TP-Link",
    "50BD5F": "TP-Link", "54AF97": "TP-Link", "5C628B": "TP-Link",
    "64709E": "TP-Link", "688FF7": "TP-Link", "74DA38": "TP-Link",
    "8CAABB": "TP-Link", "9C5322": "TP-Link", "A0F3C1": "TP-Link",
    "B0487A": "TP-Link", "C46E1F": "TP-Link", "E848B8": "TP-Link",
    "F4F26D": "TP-Link",
    # Netgear
    "001B2F": "Netgear", "001E2A": "Netgear", "001F33": "Netgear",
    "002143": "Netgear", "002275": "Netgear", "00235A": "Netgear",
    "0026F2": "Netgear", "20E52A": "Netgear", "28C68E": "Netgear",
    "44944B": "Netgear", "4C60DE": "Netgear", "84189F": "Netgear",
    "A021B7": "Netgear", "C03F0E": "Netgear",
    # Ubiquiti
    "00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti",
    "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "687250": "Ubiquiti",
    "788A20": "Ubiquiti", "802AA8": "Ubiquiti", "DC9FDB": "Ubiquiti",
    "F09FC2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    # Intel (PC/laptop Wi-Fi)
    "001560": "Intel", "003048": "Intel", "0050F2": "Intel",
    "006188": "Intel", "00AA00": "Intel", "001B21": "Intel",
    "38BA45": "Intel", "40A893": "Intel", "64D4DA": "Intel",
    "8C8D28": "Intel", "AC7BA1": "Intel",
    # Dell
    "001372": "Dell", "001A4B": "Dell", "001E4F": "Dell",
    "002170": "Dell", "002564": "Dell", "0026B9": "Dell",
    "14B31F": "Dell", "18A994": "Dell", "28F10E": "Dell",
    "5CF9DD": "Dell", "78452C": "Dell", "B083FE": "Dell",
    # HP
    "001083": "HP", "001560": "HP", "001A4B": "HP",
    "001E0B": "HP", "002264": "HP", "0024E8": "HP",
    "14DAE9": "HP", "1C98EC": "HP", "28924A": "HP",
    "38EAA7": "HP", "3C4A92": "HP", "9CB654": "HP",
    # ASUS
    "001731": "ASUS", "001FC6": "ASUS", "0022B0": "ASUS",
    "00259C": "ASUS", "1062E5": "ASUS", "10BF48": "ASUS",
    "2C4D54": "ASUS", "2C56DC": "ASUS", "38D547": "ASUS",
    "40167E": "ASUS", "5404A6": "ASUS", "705681": "ASUS",
    "74D02B": "ASUS", "BC9746": "ASUS", "E03F49": "ASUS",
    # Espressif (ESP8266/ESP32 — IoT)
    "24D7EB": "Espressif IoT", "30AEA4": "Espressif IoT",
    "3C71BF": "Espressif IoT", "48E72A": "Espressif IoT",
    "5CCF7F": "Espressif IoT", "60019F": "Espressif IoT",
    "7C9EBD": "Espressif IoT", "80864F": "Espressif IoT",
    "84CCA8": "Espressif IoT", "8CAAB5": "Espressif IoT",
    "A020A6": "Espressif IoT", "A4CF12": "Espressif IoT",
    "B4E62D": "Espressif IoT", "BCDDC2": "Espressif IoT",
    "C44F33": "Espressif IoT", "E868E7": "Espressif IoT",
    "F4CFA2": "Espressif IoT", "FCCCEC": "Espressif IoT",
}


def oui_vendor(mac: str) -> str | None:
    """Look up a manufacturer name from a MAC address OUI prefix.

    Accepts any common MAC format (AA:BB:CC:DD:EE:FF, AA-BB-CC etc.).
    Returns None if the OUI is not in the bundled table.
    """
    normalized = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(normalized) < 6:
        return None
    oui = normalized[:6]
    return _OUI_VENDORS.get(oui)


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

    async def get_client_names(self) -> dict[str, str]:
        """Build an IP -> label map by joining two Pi-hole endpoints.

        /api/clients        — MAC -> comment (the human label you set in Pi-hole)
        /api/network/devices — MAC -> [IPs]

        Best-effort: returns {} on any error. Never raises.
        """
        try:
            clients_raw, devices_raw = await asyncio.gather(
                self.get("/api/clients"),
                self.get("/api/network/devices"),
            )

            # MAC (uppercase) -> label from the comment field
            mac_to_label: dict[str, str] = {}
            for c in clients_raw.get("clients", []):
                mac = c.get("client", "").upper()
                label = c.get("comment") or c.get("name") or ""
                if mac and label:
                    mac_to_label[mac] = label

            if not mac_to_label:
                return {}

            # IP -> label via MAC join
            ip_to_label: dict[str, str] = {}
            for device in devices_raw.get("devices", []):
                hwaddr = device.get("hwaddr", "").upper()
                label = mac_to_label.get(hwaddr)
                if label:
                    for ip_entry in device.get("ips", []):
                        ip = ip_entry.get("ip", "")
                        if ip:
                            ip_to_label[ip] = label

            return ip_to_label
        except Exception:
            return {}

    async def get_mac_vendors(self) -> dict[str, str]:
        """Return an IP -> vendor string map using bundled OUI lookup.

        Pulls /api/network/devices for MAC addresses, then does a local OUI
        lookup. Best-effort — returns {} on any error.
        """
        try:
            devices_raw = await self.get("/api/network/devices")
            ip_to_vendor: dict[str, str] = {}
            for device in devices_raw.get("devices", []):
                mac = device.get("hwaddr", "")
                vendor = oui_vendor(mac)
                if vendor:
                    for ip_entry in device.get("ips", []):
                        ip = ip_entry.get("ip", "")
                        if ip:
                            ip_to_vendor[ip] = vendor
            return ip_to_vendor
        except Exception:
            return {}

    async def block_domain(self, domain: str, comment: str = "blocked via LiquidSystem") -> dict:
        """Add a domain to Pi-hole's gravity blocklist (exact match).

        Returns the API response dict. Raises on HTTP error.
        """
        assert self._http is not None
        resp = await self._http.post(
            "/api/domains/gravity/exact",
            json={"domain": domain, "comment": comment, "enabled": True},
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    async def post(self, path: str, **kwargs: Any) -> Any:
        """POST /api/<path> and return parsed JSON body."""
        assert self._http is not None
        resp = await self._http.post(
            path,
            headers=self._auth_headers(),
            **kwargs,
        )
        resp.raise_for_status()
        return resp.json()
