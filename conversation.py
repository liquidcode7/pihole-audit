"""Interactive follow-up conversation mode for pihole-audit.

After the initial AI assessment streams in, this module drops into a chat
loop where the user can ask questions or request actions. Claude retains
full context of the audit data and the assessment throughout.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from assessment import MODEL, build_audit_context
from bypass import BypassData
from correlate import CorrelationReport
from device_identifier import DeviceInfo
from fail2ban import Fail2banData
from firewall import FirewallData
from metrics import MetricsData
from recommender import RecommenderData
from traffic import TrafficData

load_dotenv()

_SEP = "─" * 60

_SYSTEM_PROMPT = """\
You are a network security and privacy analyst who has just completed a full DNS \
audit of the user's home network. The complete audit data is embedded at the end \
of this prompt — reference it directly in every answer.

The user's setup:
  - OPNsense firewall/router
  - Pi-hole v6 DNS filter
  - Proxmox hypervisor
  - Various self-hosted services on a home LAN

Conversation rules:
1. Always reference actual IPs, domains, and counts from the audit data. \
Never give generic advice when real data is available.
2. When generating configs, firewall rules, blocklists, or CLI commands, \
wrap them in fenced code blocks (e.g. ```bash, ```yaml, ```xml).
3. If the user says "do it", "apply that", "make that change", or similar: \
state clearly that OPNsense/Pi-hole API integration is not yet implemented, \
then show exactly what the change would be — the full command, config snippet, \
or API call — so they can copy-paste it themselves.
4. Format output for a terminal: use short section headers, concise prose. \
Avoid deep markdown nesting or excessive bullet lists.
5. You already gave an initial assessment. Build on it rather than repeating it.

--- AUDIT DATA ---
{audit_context}
"""


def _stream(client: anthropic.Anthropic, system: str, messages: list[dict]) -> str:
    """Stream a Claude response, printing each token. Returns full text."""
    chunks: list[str] = []
    with client.messages.stream(
        model=MODEL,
        max_tokens=4096,
        system=system,
        messages=messages,
    ) as stream:
        for chunk in stream.text_stream:
            print(chunk, end="", flush=True)
            chunks.append(chunk)
    print()
    return "".join(chunks)


def _save_transcript(history: list[dict]) -> Path:
    """Write the conversation to a timestamped .txt file."""
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = Path(f"pihole-audit-chat-{ts}.txt")
    lines: list[str] = [
        "Pi-hole Audit — Conversation Transcript",
        f"Saved: {ts}",
        "=" * 60,
        "",
    ]
    for msg in history:
        label = "You" if msg["role"] == "user" else "Claude"
        lines.append(f"{label}:")
        lines.append(msg["content"])
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def start_conversation(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
    device_map: dict[str, DeviceInfo],
    initial_assessment: str,
    metrics_data: MetricsData | None = None,
    firewall_data: FirewallData | None = None,
    fail2ban_data: Fail2banData | None = None,
    correlation_report: CorrelationReport | None = None,
    bans_delta: dict[str, int] | None = None,
) -> list[dict]:
    """Run the interactive conversation loop after the AI assessment.

    Returns the full message history (skipping the seed messages) if the user
    typed 'report' during the session, otherwise returns an empty list.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n[Conversation mode unavailable — ANTHROPIC_API_KEY not set]\n")
        return []

    audit_context = build_audit_context(
        traffic_data,
        bypass_data,
        rec_data,
        device_map,
        metrics_data=metrics_data,
        firewall_data=firewall_data,
        fail2ban_data=fail2ban_data,
        correlation_report=correlation_report,
        bans_delta=bans_delta,
    )
    system = _SYSTEM_PROMPT.format(audit_context=audit_context)
    client = anthropic.Anthropic(api_key=api_key)

    # Seed with the initial assessment so Claude knows what it already said.
    # These two entries are not shown in the HTML report (already in AI Assessment section).
    seed: list[dict] = [
        {
            "role": "user",
            "content": (
                "I just ran a Pi-hole DNS audit on my network. "
                "Please give me a complete security and privacy assessment."
            ),
        },
        {"role": "assistant", "content": initial_assessment},
    ]
    history: list[dict] = []  # real conversation turns only (no seed)
    include_in_report = False

    print()
    print(_SEP)
    print("Ask a follow-up question, request a specific fix, or type 'quit' to exit.")
    print("The AI has full context of your network data.")
    print(_SEP)

    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n[Session ended]")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ("quit", "exit"):
            print("\n[Session ended]")
            break

        if cmd == "clear":
            os.system("clear")
            turns = len(history) // 2
            print(f"[{turns} exchange(s) in history — context preserved]\n")
            continue

        if cmd == "save":
            path = _save_transcript(seed + history)
            print(f"[Transcript saved → {path}]")
            continue

        if cmd == "report":
            include_in_report = True
            print("[Conversation will be included in the HTML report]")
            continue

        history.append({"role": "user", "content": user_input})

        print("\nClaude: ", end="", flush=True)
        response = _stream(client, system, seed + history)
        history.append({"role": "assistant", "content": response})

    return history if include_in_report else []
