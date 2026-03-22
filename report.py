"""Renders the HTML report from collected audit data."""

from __future__ import annotations

import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from bypass import BypassData
from recommender import RecommenderData
from traffic import TrafficData

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
    client_names: dict[str, str] | None = None,
    output_path: Path | None = None,
) -> Path:
    """Render a self-contained HTML report and write it to disk.

    Returns the path to the written file.
    """
    if output_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = Path(f"pihole-audit-{ts}.html")

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    names = client_names or {}

    html = template.render(
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        traffic=traffic_data,
        bypass=bypass_data,
        rec=rec_data,
        client_names=names,
        bypass_doh=[f for f in bypass_data.findings if f.method == "doh_lookup"],
        bypass_ptr=[f for f in bypass_data.findings if f.method == "ptr_lookup"],
        bypass_low=[f for f in bypass_data.findings if f.method == "low_query_count"],
    )

    output_path.write_text(html, encoding="utf-8")
    return output_path
