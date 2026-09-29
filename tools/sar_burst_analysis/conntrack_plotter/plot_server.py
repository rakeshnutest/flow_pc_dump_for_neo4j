#!/usr/bin/env python3
"""Plot conntrack NEW/DESTROY rate CSVs for 60–90 hosts.

CSV columns (header optional):
  timestamp_utc,new_per_sec,destroy_per_sec,avg_new_per_sec,avg_destroy_per_sec
  e.g. 2026-09-29T16:22:44Z,189,11,318.623,318.677

Mapping:
  - Auto: discover data/conntrack_rates_<host>.csv (and plain *.csv)
  - Or mapping.json: {"hosts": {"hostA": "fileA.csv", ...}} / {"hostA": "fileA.csv"}

Modes:
  server (default): Flask + Plotly dashboard on :8080
  --generate-only: write static HTML (+ optional PNGs) to --out-dir
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from flask import Flask, jsonify, render_template_string, request, send_from_directory

COLUMNS = [
    "timestamp_utc",
    "new_per_sec",
    "destroy_per_sec",
    "avg_new_per_sec",
    "avg_destroy_per_sec",
]
METRICS = [
    ("new_per_sec", "new / s"),
    ("destroy_per_sec", "destroy / s"),
    ("avg_new_per_sec", "avg_new / s"),
    ("avg_destroy_per_sec", "avg_destroy / s"),
]
HOST_FROM_NAME = re.compile(r"conntrack_rates_(.+)\.csv$", re.I)

class Config:
    data_dir: Path = Path(os.environ.get("DATA_DIR", "/data"))
    out_dir: Path = Path(os.environ.get("OUT_DIR", "/out"))
    mapping_path: Path = Path(os.environ.get("MAPPING_PATH", "/data/mapping.json"))
    max_points: int = int(os.environ.get("MAX_POINTS", "4000"))


CFG = Config()

app = Flask(__name__)
_mapping_cache: Optional[Dict[str, Path]] = None
_df_cache: Dict[str, pd.DataFrame] = {}


def _label_from_path(path: Path) -> str:
    m = HOST_FROM_NAME.search(path.name)
    return m.group(1) if m else path.stem


def build_mapping(
    data_dir: Optional[Path] = None,
    mapping_path: Optional[Path] = None,
) -> Dict[str, Path]:
    """Return host_label -> absolute CSV path."""
    data_dir = data_dir or CFG.data_dir
    mapping_path = mapping_path or CFG.mapping_path
    result: Dict[str, Path] = {}

    if mapping_path.is_file():
        raw = json.loads(mapping_path.read_text())
        hosts = raw.get("hosts", raw)
        if not isinstance(hosts, dict):
            raise ValueError("mapping.json must be {host: file} or {hosts: {...}}")
        for label, rel in hosts.items():
            p = Path(rel)
            if not p.is_absolute():
                p = data_dir / p
            if p.is_file():
                result[str(label)] = p.resolve()
            else:
                print(f"warning: mapping entry missing: {label} -> {p}", flush=True)
        if result:
            return dict(sorted(result.items()))

    # Auto-discover: prefer conntrack_rates_*.csv, else any *.csv
    preferred = sorted(data_dir.rglob("conntrack_rates_*.csv"))
    files = preferred if preferred else sorted(data_dir.rglob("*.csv"))
    for p in files:
        if p.name == "mapping.json":
            continue
        label = _label_from_path(p)
        # Prefer first match; skip duplicates
        if label not in result:
            result[label] = p.resolve()
    return dict(sorted(result.items()))


def get_mapping(force: bool = False) -> Dict[str, Path]:
    global _mapping_cache
    if force or _mapping_cache is None:
        _mapping_cache = build_mapping()
        _df_cache.clear()
    return _mapping_cache


def load_csv(path: Path) -> pd.DataFrame:
    """Load one CSV; tolerate missing header."""
    try:
        df = pd.read_csv(path)
        cols_l = {c.lower().strip(): c for c in df.columns}
        if "timestamp_utc" in cols_l or "time" in cols_l:
            rename = {}
            aliases = {
                "time": "timestamp_utc",
                "timestamp": "timestamp_utc",
                "timestamp_utc": "timestamp_utc",
                "new": "new_per_sec",
                "new_per_sec": "new_per_sec",
                "destroy": "destroy_per_sec",
                "destroy_per_sec": "destroy_per_sec",
                "avg_new": "avg_new_per_sec",
                "avg_new_per_sec": "avg_new_per_sec",
                "avg_destroy": "avg_destroy_per_sec",
                "avg_destroy_per_sec": "avg_destroy_per_sec",
            }
            for low, canon in aliases.items():
                if low in cols_l:
                    rename[cols_l[low]] = canon
            df = df.rename(columns=rename)
        else:
            raise ValueError("no header")
    except Exception:
        df = pd.read_csv(path, header=None, names=COLUMNS)

    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{path.name}: missing columns {missing}")

    df = df[COLUMNS].copy()
    df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp_utc"])
    for c in COLUMNS[1:]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna().sort_values("timestamp_utc").reset_index(drop=True)
    return df


def get_df(host: str) -> pd.DataFrame:
    mapping = get_mapping()
    if host not in mapping:
        raise KeyError(host)
    if host not in _df_cache:
        _df_cache[host] = load_csv(mapping[host])
    return _df_cache[host]


def downsample(df: pd.DataFrame, max_points: Optional[int] = None) -> pd.DataFrame:
    max_points = CFG.max_points if max_points is None else max_points
    if len(df) <= max_points:
        return df
    step = max(1, len(df) // max_points)
    return df.iloc[::step].copy()


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Conntrack rates — {{ n_hosts }} hosts</title>
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    :root { --bg:#0f1419; --panel:#1a2332; --text:#e7ecf3; --muted:#8b9bb4; --accent:#3d9cf0; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--text); }
    header { padding:16px 20px; border-bottom:1px solid #2a3548; display:flex; flex-wrap:wrap; gap:12px; align-items:center; }
    h1 { margin:0; font-size:1.15rem; font-weight:600; }
    .meta { color:var(--muted); font-size:0.85rem; }
    .controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-left:auto; }
    select, button, input { background:var(--panel); color:var(--text); border:1px solid #334155; border-radius:6px; padding:6px 10px; font-size:0.85rem; }
    select[multiple] { min-width:260px; min-height:120px; }
    button { cursor:pointer; background:var(--accent); border-color:transparent; color:#041018; font-weight:600; }
    button.secondary { background:#243044; color:var(--text); }
    main { padding:12px 16px 32px; }
    #chart { width:100%; height:calc(100vh - 180px); min-height:640px; }
    .hint { color:var(--muted); font-size:0.8rem; width:100%; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Conntrack NEW / DESTROY rates</h1>
      <div class="meta">{{ n_hosts }} hosts mapped · columns: time, new, destroy, avg_new, avg_destroy</div>
    </div>
    <div class="controls">
      <label class="meta">Hosts<br/>
        <select id="hosts" multiple size="6"></select>
      </label>
      <div>
        <button type="button" onclick="selectAll()">All</button>
        <button type="button" class="secondary" onclick="selectNone()">None</button>
        <button type="button" onclick="reload()">Plot</button>
        <button type="button" class="secondary" onclick="refreshMapping()">Rescan</button>
      </div>
    </div>
    <div class="hint">Tip: Ctrl/Cmd-click to multi-select. Large series are downsampled for the browser; open one host for denser detail.</div>
  </header>
  <main><div id="chart"></div></main>
  <script>
    const METRICS = {{ metrics_json|safe }};
    let HOSTS = {{ hosts_json|safe }};

    function fillHostSelect() {
      const sel = document.getElementById('hosts');
      sel.innerHTML = '';
      HOSTS.forEach((h, i) => {
        const o = document.createElement('option');
        o.value = h; o.textContent = h;
        if (i < 8) o.selected = true;
        sel.appendChild(o);
      });
    }
    function selectedHosts() {
      return Array.from(document.getElementById('hosts').selectedOptions).map(o => o.value);
    }
    function selectAll() {
      Array.from(document.getElementById('hosts').options).forEach(o => o.selected = true);
    }
    function selectNone() {
      Array.from(document.getElementById('hosts').options).forEach(o => o.selected = false);
    }
    async function refreshMapping() {
      const r = await fetch('/api/mapping?refresh=1');
      const j = await r.json();
      HOSTS = j.hosts;
      fillHostSelect();
      reload();
    }
    async function reload() {
      const hosts = selectedHosts();
      if (!hosts.length) { Plotly.purge('chart'); return; }
      const r = await fetch('/api/plot', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({hosts})
      });
      const fig = await r.json();
      Plotly.react('chart', fig.data, fig.layout, {responsive: true});
    }
    fillHostSelect();
    reload();
  </script>
</body>
</html>
"""


def make_figure(hosts: List[str]) -> go.Figure:
    fig = make_subplots(
        rows=4,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.04,
        subplot_titles=[title for _, title in METRICS],
    )
    for host in hosts:
        df = downsample(get_df(host))
        x = df["timestamp_utc"]
        for i, (col, _title) in enumerate(METRICS, start=1):
            fig.add_trace(
                go.Scattergl(
                    x=x,
                    y=df[col],
                    name=host,
                    legendgroup=host,
                    showlegend=(i == 1),
                    mode="lines",
                    line=dict(width=1.2),
                    hovertemplate="%{x}<br>" + host + ": %{y}<extra></extra>",
                ),
                row=i,
                col=1,
            )
    fig.update_layout(
        height=900,
        template="plotly_dark",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
        margin=dict(l=60, r=20, t=60, b=40),
        hovermode="x unified",
    )
    fig.update_xaxes(title_text="time (UTC)", row=4, col=1)
    for i, (col, title) in enumerate(METRICS, start=1):
        fig.update_yaxes(title_text=title, row=i, col=1)
    return fig


@app.get("/")
def index():
    hosts = list(get_mapping().keys())
    return render_template_string(
        DASHBOARD_HTML,
        n_hosts=len(hosts),
        hosts_json=json.dumps(hosts),
        metrics_json=json.dumps([{"col": c, "title": t} for c, t in METRICS]),
    )


@app.get("/api/mapping")
def api_mapping():
    force = request.args.get("refresh") in ("1", "true", "yes")
    mapping = get_mapping(force=force)
    return jsonify(
        {
            "hosts": list(mapping.keys()),
            "files": {h: str(p) for h, p in mapping.items()},
            "count": len(mapping),
        }
    )


@app.get("/api/hosts")
def api_hosts():
    return jsonify(list(get_mapping().keys()))


@app.get("/api/series/<host>")
def api_series(host: str):
    try:
        df = downsample(get_df(host))
    except KeyError:
        return jsonify({"error": f"unknown host: {host}"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    out = {
        "host": host,
        "time": df["timestamp_utc"].dt.strftime("%Y-%m-%dT%H:%M:%SZ").tolist(),
        "new": df["new_per_sec"].tolist(),
        "destroy": df["destroy_per_sec"].tolist(),
        "avg_new": df["avg_new_per_sec"].tolist(),
        "avg_destroy": df["avg_destroy_per_sec"].tolist(),
        "points": len(df),
    }
    return jsonify(out)


@app.post("/api/plot")
def api_plot():
    body = request.get_json(force=True, silent=True) or {}
    hosts = body.get("hosts") or list(get_mapping().keys())
    known = get_mapping()
    hosts = [h for h in hosts if h in known]
    if not hosts:
        return jsonify({"error": "no hosts"}), 400
    fig = make_figure(hosts)
    return jsonify(json.loads(fig.to_json()))


@app.get("/out/<path:filename>")
def serve_out(filename: str):
    return send_from_directory(CFG.out_dir, filename)


def generate_static(
    out_dir: Optional[Path] = None,
    hosts: Optional[List[str]] = None,
    write_png: bool = False,
) -> Tuple[Path, List[Path]]:
    out_dir = out_dir or CFG.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    mapping = get_mapping(force=True)
    hosts = hosts or list(mapping.keys())
    hosts = [h for h in hosts if h in mapping]
    if not hosts:
        raise SystemExit("no CSV hosts found under DATA_DIR / mapping.json")

    fig = make_figure(hosts)
    html_path = out_dir / "conntrack_rates_all.html"
    fig.write_html(str(html_path), include_plotlyjs="cdn")
    print(f"wrote {html_path} ({len(hosts)} hosts)", flush=True)

    pngs: List[Path] = []
    if write_png:
        per_host = out_dir / "per_host"
        per_host.mkdir(exist_ok=True)
        for host in hosts:
            hfig = make_figure([host])
            p = per_host / f"{host}.png"
            try:
                hfig.write_image(str(p), width=1400, height=900, scale=1)
                pngs.append(p)
            except Exception as exc:
                print(f"warning: PNG for {host} skipped ({exc})", flush=True)
        print(f"wrote {len(pngs)} PNGs under {per_host}", flush=True)

    # Persist mapping used for this run
    map_out = out_dir / "mapping.resolved.json"
    map_out.write_text(
        json.dumps({"hosts": {h: str(mapping[h]) for h in hosts}}, indent=2) + "\n"
    )
    return html_path, pngs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=str(CFG.data_dir))
    parser.add_argument("--out-dir", default=str(CFG.out_dir))
    parser.add_argument("--mapping", default=str(CFG.mapping_path))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="Write static HTML to out-dir and exit (no server)",
    )
    parser.add_argument(
        "--png",
        action="store_true",
        help="Also write per-host PNGs (needs kaleido)",
    )
    args = parser.parse_args()

    CFG.data_dir = Path(args.data_dir)
    CFG.out_dir = Path(args.out_dir)
    CFG.mapping_path = Path(args.mapping)

    mapping = get_mapping(force=True)
    print(f"mapped {len(mapping)} CSV file(s) from {CFG.data_dir}", flush=True)
    for h, p in list(mapping.items())[:5]:
        print(f"  {h} -> {p.name}", flush=True)
    if len(mapping) > 5:
        print(f"  ... +{len(mapping) - 5} more", flush=True)

    if args.generate_only:
        generate_static(CFG.out_dir, write_png=args.png)
        return 0

    # Always drop a full static HTML on startup for offline sharing
    try:
        generate_static(CFG.out_dir, write_png=args.png)
    except SystemExit as exc:
        print(f"warning: {exc}", flush=True)

    print(f"serving dashboard on http://{args.host}:{args.port}/", flush=True)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
