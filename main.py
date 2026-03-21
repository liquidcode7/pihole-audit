"""pihole-audit — entry point."""

from __future__ import annotations

import asyncio

from rich.console import Console

from client import PiholeClient

console = Console()


async def _auth_test() -> None:
    """Quick smoke-test: log in, fetch /api/stats/summary, log out."""
    console.print("[bold cyan]pihole-audit[/] — auth test")
    async with PiholeClient() as client:
        summary = await client.get("/api/stats/summary")
        console.print("[green]✓ Authenticated and connected[/]")
        console.print(summary)


def main() -> None:
    asyncio.run(_auth_test())


if __name__ == "__main__":
    main()
