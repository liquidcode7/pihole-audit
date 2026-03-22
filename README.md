# pihole-audit

A DNS audit tool for Pi-hole v6. Connects to your Pi-hole, analyzes the query log, and produces a rich terminal report plus a self-contained HTML file.

## What it does

**Traffic Review**
Summary stats (total queries, block rate, cache rate), top allowed domains, top blocked domains, and top clients by query volume.

**DNS Bypass Detection**
- Scans the query log for lookups to DoH/DoT provider hostnames (`dns.google`, `cloudflare-dns.com`, etc.) — devices querying these may be routing DNS around Pi-hole
- Flags clients with suspiciously low query counts compared to the network average, which can indicate hardcoded DNS usage

**Blocklist Recommendations**
Scans allowed queries against patterns for known tracking, telemetry, ad network, data broker, fingerprinting, and smart TV / IoT phone-home domains — surfaces what's getting through that you should consider blocking.

## Requirements

- Pi-hole v6
- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

## Setup

**1. Create an app password in Pi-hole**

Go to **Settings → API** in your Pi-hole web interface and generate an app password. Do not use your main admin password.

**2. Configure `.env`**

```bash
cp .env.example .env  # or just edit .env directly
```

```env
PIHOLE_URL=http://192.168.1.x
PIHOLE_APP_PASSWORD=your_app_password_here

# Optional: comma-separated IPs to exclude from low-query-count bypass flagging
# (192.168.1.1 and 127.0.0.1 are excluded by default)
# PIHOLE_BYPASS_IGNORE_IPS=10.0.0.1,172.16.0.1
```

**3. Install dependencies**

```bash
uv sync
```

**4. Run**

```bash
uv run python main.py
```

A timestamped HTML report (`pihole-audit-YYYYMMDD-HHMMSS.html`) is saved to the current directory.

## Client labels

Pi-hole doesn't always resolve hostnames for DHCP clients. To get human-readable names in the report, register your devices in Pi-hole under **Groups → Clients** and set the **Comment** field to whatever you want the label to be (e.g. `LGTV`, `LiquidArch`, `TrueNAS`).

Labels are resolved at runtime by joining Pi-hole's MAC-based client registry with its current device→IP table, so they stay correct across DHCP lease renewals.

## Project structure

```
pihole-audit/
├── main.py          # Entry point, orchestrates everything
├── client.py        # Pi-hole v6 session manager (context manager, always logs out)
├── traffic.py       # Module 1: traffic review
├── bypass.py        # Module 2: DNS bypass detection
├── recommender.py   # Module 3: blocklist recommendations
├── report.py        # HTML report renderer
└── templates/
    └── report.html  # Jinja2 template (dark-themed, self-contained)
```

## Notes

- All Pi-hole API calls are read-only. The tool never modifies any Pi-hole configuration.
- Pi-hole v6 has a limited number of API session "seats". The client uses a context manager to guarantee logout even on crash.
- The recommender scans up to 15,000 raw queries from the log on each run. The bypass detector scans up to 5,000.
