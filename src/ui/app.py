"""
Neuro-Symbolic Fuzzer  ·  Professional RE Tool UI
app.py — Dash application factory.

Styled to feel like Ghidra / IDA Pro:
  - IDA-inspired theme with Dark/Light mode toggle utilizing CSS variables
  - Keyboard shortcuts via clientside event listeners
  - High-performance Cytoscape visualization with animated highlighting
  - Layout selector (Dagre, CoSE, Concentric, Circular, Breadthfirst)
  - Interactive search panel by address, name, or symbol
  - Graph Legend and node inspector details (including binary section, recursion, size)
  - Synchronized SMT & Symbolic Execution explanations
  - Printable HTML-to-PDF ready reports
"""
from __future__ import annotations

import base64, json, os, tempfile, time
from datetime import datetime
from typing import Any, Dict, List, Optional

import dash
import dash_cytoscape as cyto
import networkx as nx
from dash import Input, Output, State, ctx, dcc, html, no_update, ALL
from dash.exceptions import PreventUpdate
from dataclasses import asdict

from core.binary_loader import BinaryLoader
from graph.graph_builder import GraphBuilder
from core.interfaces import AnalysisBackendProvider

try:
    cyto.load_extra_layouts()
except Exception:
    pass

# ── Theme styles ──────────────────────────────────────────────────────────────
# CSS styles injection for Light/Dark toggling, Keyboard shortcuts, Legend, and Print
THEME_CSS = """
:root {
    --bg: #0d1117;
    --panel: #161b22;
    --card: #1c2128;
    --border: #21262d;
    --bhi: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --dim: #484f58;
    --blue: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #e3b341;
    --purple: #8957e5;
    --cyan: #39d353;
    --orange: #db6d28;
    --pink: #f78166;
}

.theme-light {
    --bg: #f6f8fa;
    --panel: #ffffff;
    --card: #eaeef2;
    --border: #d0d7de;
    --bhi: #d8dee4;
    --text: #24292f;
    --muted: #57606a;
    --dim: #8c959f;
    --blue: #0969da;
    --green: #1a7f37;
    --red: #cf222e;
    --yellow: #9a6700;
    --purple: #8250df;
    --cyan: #11a277;
    --orange: #bc4c00;
    --pink: #d1573f;
}

body {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    transition: background-color 0.2s, color 0.2s;
    margin: 0;
    font-family: 'Inter', sans-serif;
}

/* Legend Styling */
.legend-overlay {
    position: absolute;
    bottom: 60px;
    left: 15px;
    background-color: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    z-index: 100;
    font-size: 11px;
    width: 170px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.legend-item {
    display: flex;
    align-items: center;
    margin-bottom: 5px;
}

.legend-color {
    width: 12px;
    height: 12px;
    border-radius: 2px;
    margin-right: 8px;
    border: 1px solid var(--border);
}

/* Tooltip overlay styling */
.tooltip-stat {
    position: relative;
    display: inline-block;
    cursor: help;
}

.tooltip-stat .tooltip-text {
    visibility: hidden;
    width: 180px;
    background-color: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    text-align: center;
    border-radius: 6px;
    padding: 6px 8px;
    position: absolute;
    z-index: 9999;
    bottom: 125%;
    left: 50%;
    margin-left: -90px;
    opacity: 0;
    transition: opacity 0.2s;
    font-size: 11px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
}

.tooltip-stat:hover .tooltip-text {
    visibility: visible;
    opacity: 1;
}

/* Fullscreen mode classes */
.fullscreen-active {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 1000 !important;
    background-color: var(--bg) !important;
}

/* Dropdown styling overrides */
.Select-control {
    background-color: var(--card) !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
}
.Select-menu-outer {
    background-color: var(--card) !important;
    border-color: var(--border) !important;
    z-index: 1000 !important;
}
.Select-option {
    background-color: var(--card) !important;
    color: var(--text) !important;
}
.Select-option.is-focused {
    background-color: var(--bhi) !important;
}
.Select-value-label {
    color: var(--text) !important;
}
.VirtualizedSelectFocusedOption {
    background-color: var(--bhi) !important;
    color: var(--text) !important;
}

/* Scrollbar tweaks */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: var(--bg);
}
::-webkit-scrollbar-thumb {
    background: var(--bhi);
    border-radius: 3px;
}

/* Table styling */
table.sym-table-styled {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    font-size: 11px;
    color: var(--text);
}
table.sym-table-styled th {
    border-bottom: 1px solid var(--border);
    padding: 6px;
    text-align: left;
    color: var(--muted);
    font-weight: 600;
}
table.sym-table-styled td {
    padding: 6px;
    border-bottom: 1px solid var(--border);
}

/* Print CSS variables & formatting */
@media print {
    body {
        background: white !important;
        color: black !important;
    }
    .no-print {
        display: none !important;
    }
}
"""

# (icon, label, bg, fg) for each event type
EVENT_META: Dict[str, tuple] = {
    "ENTRY":        ("▶",  "ENTRY",    "#1a4731", "#3fb950"),
    "RETURN":       ("↩",  "RETURN",   "#2d1a05", "#db6d28"),
    "BRANCH":       ("⑂",  "BRANCH",   "#2d2409", "#e3b341"),
    "LOOP":         ("↻",  "LOOP",     "#063535", "#39d353"),
    "LIBRARY_CALL": ("📚", "LIB CALL", "#1a0f3d", "#8957e5"),
    "SYSCALL":      ("⚙",  "SYSCALL",  "#2d2009", "#d29922"),
    "CRASH":        ("💥", "CRASH",    "#3d0d0d", "#f85149"),
    "NORMAL":       ("→",  "NORMAL",   "#21262d", "#8b949e"),
}

LAYOUTS = [
    {"label": "⬡ Hierarchical (Dagre)",  "value": "dagre"},
    {"label": "✦ Force-Directed (CoSE)",   "value": "cose"},
    {"label": "◎ Concentric Circle",       "value": "concentric"},
    {"label": "◉ Circular Ring",           "value": "circle"},
    {"label": "⟶ Breadth-First Tree",     "value": "breadthfirst"},
]

# ── Style helpers ─────────────────────────────────────────────────────────────

def _merge(*dicts: dict) -> dict:
    out: dict = {}
    for d in dicts:
        out.update(d)
    return out


def _section(text: str, color_var: str = "--blue") -> html.Div:
    return html.Div(text, style={
        "fontSize": "10px", "fontWeight": "700", "letterSpacing": "0.10em",
        "textTransform": "uppercase", "color": f"var({color_var})",
        "marginBottom": "8px", "fontFamily": "Inter, sans-serif",
    })


def _badge(text: str, bg: str, fg: str, extra: Optional[dict] = None) -> html.Span:
    s = {
        "backgroundColor": bg, "color": fg, "borderRadius": "4px",
        "padding": "2px 9px", "fontSize": "11px", "fontWeight": "600",
        "fontFamily": "JetBrains Mono, monospace", "display": "inline-block",
    }
    if extra:
        s.update(extra)
    return html.Span(text, style=s)


def _event_badge(event_type: str) -> html.Span:
    icon, label, bg, fg = EVENT_META.get(event_type, EVENT_META["NORMAL"])
    return _badge(f"{icon} {label}", bg, fg, {"marginRight": "4px"})


def _kv(key: str, val: Any, val_color_var: str = "--text") -> html.Div:
    return html.Div([
        html.Span(key + ": ", style={"color": "var(--muted)", "fontSize": "12px"}),
        html.Span(str(val), style={
            "color": f"var({val_color_var})",
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "12px",
        }),
    ], style={"marginBottom": "4px"})


def _metric(label: str, value: Any, color_var: str = "--blue", tooltip_text: str = "") -> html.Div:
    card_content = html.Div([
        html.Div(str(value), style={
            "fontSize": "16px", "fontWeight": "700",
            "color": f"var({color_var})",
            "fontFamily": "JetBrains Mono, monospace", "lineHeight": "1.2",
        }),
        html.Div(label, style={
            "fontSize": "9px", "color": "var(--muted)",
            "textTransform": "uppercase", "letterSpacing": "0.06em",
        }),
    ], style={
        "backgroundColor": "var(--card)", "border": "1px solid var(--border)",
        "borderRadius": "6px", "padding": "8px 10px",
        "flex": "1", "minWidth": "78px",
    })
    
    if tooltip_text:
        return html.Div(className="tooltip-stat", children=[
            card_content,
            html.Span(className="tooltip-text", children=tooltip_text)
        ])
    return card_content


def _play_btn(color_var: str = "--muted") -> dict:
    return {
        "backgroundColor": "var(--card)",
        "color": f"var({color_var})",
        "border": "1px solid var(--border)",
        "borderRadius": "6px", "padding": "6px 0",
        "cursor": "pointer", "fontSize": "14px",
        "fontFamily": "monospace", "flex": "1",
        "transition": "background-color 0.15s, color 0.15s",
    }


def _btn(label: str, bg: str, fg: str, extra: Optional[dict] = None) -> dict:
    s = {
        "backgroundColor": bg, "color": fg,
        "border": f"1px solid {fg}", "borderRadius": "6px",
        "padding": "5px 14px", "cursor": "pointer",
        "fontFamily": "Inter, sans-serif", "fontSize": "12px",
        "fontWeight": "500",
    }
    if extra:
        s.update(extra)
    return s

# ── Graph helpers ─────────────────────────────────────────────────────────────

def nx_to_cyto(G: nx.DiGraph) -> List[dict]:
    """Convert NetworkX graph to Cytoscape element list."""
    elements: List[dict] = []
    for node, data in G.nodes(data=True):
        classes = data.get("node_class", "internal")
        if data.get("is_loop_header"):
            classes += " loop-header"
        d = {
            k: (json.dumps(v) if isinstance(v, list) else v)
            for k, v in data.items()
        }
        elements.append({"data": {"id": str(node), **d}, "classes": classes})
    for src, dst in G.edges():
        elements.append({"data": {"source": str(src), "target": str(dst)}})
    return elements


def _next_vis(trace: List[dict], idx: int, direction: int, hide_lib: bool) -> int:
    n = len(trace)
    while True:
        idx += direction
        if idx < 0:
            return 0
        if idx >= n:
            return n - 1
        if not hide_lib or not trace[idx].get("is_library", False):
            return idx


def _build_layout(name: str) -> dict:
    base = {"name": name, "animate": True, "animationDuration": 250}
    extras: dict = {
        "dagre":        {"rankDir": "TB", "nodeSep": 50, "rankSep": 80, "padding": 30},
        "cose":         {"nodeRepulsion": 400000, "idealEdgeLength": 90, "gravity": 75,
                         "padding": 40, "randomize": False},
        "concentric":   {"minNodeSpacing": 60, "padding": 40},
        "circle":       {"padding": 40, "startAngle": 0},
    }
    return _merge(base, extras.get(name, {}))


def _cyto_stylesheet() -> List[dict]:
    return [
        {"selector": "node", "style": {
            "label": "data(label)",
            "text-valign": "center", "text-halign": "center",
            "color": "var(--text)",
            "font-family": "JetBrains Mono, monospace",
            "font-size": "10px", "text-wrap": "wrap", "text-max-width": "110px",
            "width": "label", "height": "label", "padding": "7px",
            "shape": "rectangle",
            "background-color": "var(--card)",
            "border-width": 1, "border-color": "var(--border)",
        }},
        {"selector": ".entry", "style": {
            "background-color": "var(--panel)", "border-color": "var(--green)",
            "border-width": 2, "shape": "diamond",
            "color": "var(--green)", "font-weight": "bold",
        }},
        {"selector": ".library", "style": {
            "background-color": "var(--panel)", "border-color": "var(--purple)",
            "shape": "round-rectangle", "color": "var(--purple)",
        }},
        {"selector": ".syscall", "style": {
            "background-color": "var(--panel)", "border-color": "var(--yellow)",
            "color": "var(--yellow)",
        }},
        {"selector": ".internal", "style": {
            "background-color": "var(--card)", "border-color": "var(--blue)", "color": "var(--blue)",
        }},
        {"selector": ".loop-header", "style": {
            "border-color": "var(--cyan)", "border-width": 2, "border-style": "dashed",
        }},
        {"selector": ".active-execution-node", "style": {
            "background-color": "var(--card)", "border-color": "var(--red)",
            "border-width": 3, "color": "var(--red)",
            "font-weight": "bold", "z-index": 999,
        }},
        {"selector": ".visited-execution-node", "style": {
            "background-color": "var(--panel)", "border-color": "var(--purple)", "color": "var(--pink)",
            "opacity": 0.8
        }},
        {"selector": ".branch-node", "style": {
            "border-style": "dashed", "border-color": "var(--yellow)", "border-width": 3,
        }},
        {"selector": "edge", "style": {
            "curve-style": "bezier", "target-arrow-shape": "triangle",
            "line-color": "var(--border)", "target-arrow-color": "var(--border)",
            "width": 1.5, "opacity": 0.6,
        }},
        {"selector": ".active-edge", "style": {
            "line-color": "var(--red)", "target-arrow-color": "var(--red)",
            "width": 3, "line-style": "dashed", "opacity": 1,
        }},
        {"selector": ".visited-edge", "style": {
            "line-color": "var(--purple)", "target-arrow-color": "var(--purple)",
            "width": 2, "opacity": 0.7,
        }},
        {"selector": "node:selected", "style": {
            "border-color": "var(--blue)", "border-width": 3,
        }},
    ]

# ── Report generator ──────────────────────────────────────────────────────────

def _make_report(filename: str, trace: List[dict], metrics: dict, ts: str) -> str:
    rows = ""
    for i, s in enumerate(trace):
        evt = s.get("event_type", "NORMAL")
        icon, label, bg, fg = EVENT_META.get(evt, EVENT_META["NORMAL"])
        smt = s.get("smt_diagnostics", {})
        sat = smt.get("status", "N/A")
        sc = "#3fb950" if sat == "SAT" else "#f85149" if sat == "UNSAT" else "#8b949e"
        rows += (
            f"<tr><td>{i}</td>"
            f"<td style='color:#58a6ff;font-family:monospace'>{s.get('instruction_address','')}</td>"
            f"<td>{s.get('function_name','')}</td>"
            f"<td><span style='background:{bg};color:{fg};padding:2px 8px;border-radius:3px;"
            f"font-size:11px'>{icon} {label}</span></td>"
            f"<td style='font-size:11px'>{str(s.get('explanation',''))[:110]}…</td>"
            f"<td style='color:{sc};font-family:monospace'>{sat}</td></tr>"
        )

    mc = "".join(
        f"<div class='mc'><div class='mv'>{v}</div>"
        f"<div class='ml'>{k.replace('_',' ').title()}</div></div>"
        for k, v in (metrics or {}).items() if k != "filename"
    )

    crash_states = [s for s in trace if s.get("event_type") == "CRASH"]

    findings = [
        ("Total execution states",   len(trace)),
        ("Branch points",            sum(1 for s in trace if s.get("is_branch"))),
        ("Crash points found",       len(crash_states)),
        ("Library calls",            sum(1 for s in trace if s.get("event_type") == "LIBRARY_CALL")),
        ("Loop back-edges",          sum(1 for s in trace if s.get("event_type") == "LOOP")),
        ("Return events",            sum(1 for s in trace if s.get("event_type") == "RETURN")),
        ("SAT paths",                sum(1 for s in trace if s.get("smt_diagnostics", {}).get("status") == "SAT")),
        ("UNSAT paths",              sum(1 for s in trace if s.get("smt_diagnostics", {}).get("status") == "UNSAT")),
        ("Unique functions visited", len(set(s.get("function_name", "") for s in trace))),
    ]
    fr = "".join(f"<tr><td>{k}</td><td><strong>{v}</strong></td></tr>" for k, v in findings)

    if crash_states:
        crash_rows = ""
        for s in crash_states:
            smt = s.get("smt_diagnostics", {})
            model = (smt.get("model") or "No concrete model computed.").replace("\n", "<br>")
            crash_rows += (
                f"<div style='background:#1a0d0d;border:1px solid #f85149;border-radius:6px;"
                f"padding:14px;margin-top:10px'>"
                f"<div style='color:#f85149;font-weight:700;font-family:monospace'>"
                f"💥 Crash at {s.get('instruction_address','')} — {s.get('function_name','')}</div>"
                f"<div style='font-size:12px;color:#8b949e;margin-top:6px'>{s.get('explanation','')}</div>"
                f"<div style='font-size:12px;color:#e6edf3;margin-top:8px;font-family:monospace;"
                f"white-space:pre-wrap'><strong>Breaking input:</strong><br>{model}</div>"
                f"</div>"
            )
        crash_section = f"<h2>🎯 Crash Analysis — Exact Breaking Input</h2>{crash_rows}"
    else:
        crash_section = (
            "<h2>🎯 Crash Analysis</h2><p style='color:#8b949e'>"
            "No crash states (symbolic/unconstrained instruction pointer or execution errors) "
            "were encountered on the explored paths.</p>"
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Analysis Report — {filename}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
h1{{color:#58a6ff;font-size:22px;border-bottom:1px solid #21262d;padding-bottom:12px;margin-top:0}}
h2{{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:28px}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}}
th{{background:#161b22;color:#8b949e;padding:7px 10px;text-align:left;border:1px solid #21262d;font-weight:600}}
td{{padding:6px 10px;border:1px solid #21262d;vertical-align:top}}
tr:nth-child(even)td{{background:#0d1117}}tr:nth-child(odd)td{{background:#161b22}}
.mg{{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px}}
.mc{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 14px;min-width:130px}}
.mv{{font-size:20px;font-weight:700;color:#58a6ff;font-family:monospace}}
.ml{{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em}}
.footer{{margin-top:40px;color:#484f58;font-size:11px;border-top:1px solid #21262d;padding-top:14px}}
@media print {{
    body {{ background: white !important; color: black !important; font-size: 11px; }}
    table {{ border: 1px solid #ddd; }}
    th, td {{ border: 1px solid #ddd; padding: 4px; }}
    tr {{ page-break-inside: avoid; }}
}}
</style></head><body>
<h1>🔬 Neuro-Symbolic Fuzzer — Analysis Report</h1>
<p style="color:#8b949e">Binary: <code style="color:#58a6ff">{filename}</code>
&nbsp;·&nbsp;Generated: {ts}</p>
<h2>Analysis Metrics</h2><div class="mg">{mc}</div>
{crash_section}
<h2>Execution Trace ({len(trace)} states)</h2>
<table><thead><tr>
  <th>#</th><th>Address</th><th>Function</th><th>Event</th><th>Explanation</th><th>SMT</th>
</tr></thead><tbody>{rows}</tbody></table>
<h2>Findings</h2>
<table><thead><tr><th>Finding</th><th>Value</th></tr></thead><tbody>{fr}</tbody></table>
<div class="footer">
  Neuro-Symbolic Fuzzer &nbsp;·&nbsp; angr symbolic execution + Z3 SMT solver
  &nbsp;·&nbsp; {ts}
</div></body></html>"""


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> dash.Dash:
    app = dash.Dash(
        __name__,
        external_stylesheets=[
            "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600"
            "&family=Inter:wght@300;400;500;600;700&display=swap",
        ],
        suppress_callback_exceptions=True,
    )
    app.title = "Neuro-Symbolic Fuzzer"

    # Define Stylesheet & Keyboard shortcut client listener
    app.index_string = f"""
    <!DOCTYPE html>
    <html>
        <head>
            {{%metas%}}
            <title>{{%title%}}</title>
            {{%favicon%}}
            {{%css%}}
            <style>{THEME_CSS}</style>
        </head>
        <body class="theme-dark">
            {{%app_entry%}}
            <footer>
                {{%config%}}
                {{%scripts%}}
                {{%renderer%}}
            </footer>
        </body>
    </html>
    """

    # ── Shared panel style snippets ───────────────────────────────────────────
    _left_style = {
        "width": "300px", "flexShrink": "0",
        "backgroundColor": "var(--panel)",
        "borderRight": "1px solid var(--border)",
        "padding": "16px", "overflowY": "auto",
        "fontFamily": "Inter, sans-serif",
    }
    _right_style = {
        "width": "390px", "flexShrink": "0",
        "backgroundColor": "var(--panel)",
        "borderLeft": "1px solid var(--border)",
        "padding": "16px", "overflowY": "auto",
        "fontFamily": "Inter, sans-serif",
    }
    _card_s = {
        "backgroundColor": "var(--card)",
        "border": "1px solid var(--border)",
        "borderRadius": "6px", "padding": "12px",
        "marginBottom": "12px",
    }
    _hr = html.Hr(style={"borderColor": "var(--border)", "margin": "14px 0"})

    # ── Layout definition ─────────────────────────────────────────────────────

    header = html.Div([
        # Logo
        html.Div([
            html.Span("🔬", style={"fontSize": "18px", "marginRight": "8px"}),
            html.Span("NEURO-SYMBOLIC FUZZER", style={
                "fontFamily": "JetBrains Mono, monospace", "fontWeight": "700",
                "fontSize": "13px", "letterSpacing": "0.12em", "color": "var(--blue)",
            }),
            html.Span("  //  re-tool", style={
                "fontFamily": "JetBrains Mono, monospace", "fontWeight": "400",
                "fontSize": "11px", "color": "var(--dim)",
            }),
        ], style={"display": "flex", "alignItems": "center"}),

        # Binary badge
        html.Div(id="header-binary-info", children="No binary loaded", style={
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "12px", "color": "var(--muted)",
        }),

        # Controls
        html.Div([
            html.Button("☀️/🌙 Toggle Theme", id="btn-theme", n_clicks=0,
                        style=_btn("Theme", "transparent", "var(--text)", {"marginRight": "10px"})),
            html.Button("📄 Export Report", id="btn-export", n_clicks=0,
                        style=_btn("export", "#1a2d1a", "var(--green)", {"marginRight": "10px"})),
            dcc.Download(id="download-report"),
        ], style={"display": "flex", "alignItems": "center"}),

    ], style={
        "display": "flex", "alignItems": "center",
        "justifyContent": "space-between",
        "backgroundColor": "var(--panel)",
        "borderBottom": "1px solid var(--border)",
        "padding": "0 20px", "height": "50px", "flexShrink": "0",
    })

    # ── Left panel ────────────────────────────────────────────────────────────
    left_panel = html.Div([

        _section("01  ·  Binary Upload", "--blue"),
        dcc.Upload(id="upload-binary", multiple=False,
                   children=html.Div([
                       html.Div("⬆", style={"fontSize": "22px", "marginBottom": "3px"}),
                       html.Div("Drag & Drop or Click to Upload",
                                style={"fontSize": "12px", "fontWeight": "500"}),
                       html.Div("ELF · Mach-O · PE",
                                style={"fontSize": "10px", "color": "var(--dim)", "marginTop": "2px"}),
                   ], style={"textAlign": "center"}),
                   style={
                       "border": "2px dashed var(--bhi)", "borderRadius": "8px",
                       "padding": "14px", "cursor": "pointer",
                       "backgroundColor": "var(--card)", "marginBottom": "8px",
                   }),
        dcc.Loading(type="dot", color="var(--blue)",
                    children=html.Div(id="upload-status", style={
                        "fontSize": "12px", "marginBottom": "14px", "color": "var(--green)",
                    })),

        _hr,
        _section("02  ·  Graph View & Search", "--blue"),
        dcc.Dropdown(id="graph-selector", clearable=False,
                     options=[
                         {"label": "⬡  Control Flow Graph (CFG)", "value": "cfg"},
                         {"label": "☎  Call Graph (CG)",          "value": "cg"},
                     ],
                     value="cfg", style={"marginBottom": "8px", "fontSize": "12px"}),
        dcc.Dropdown(id="layout-selector", clearable=False,
                     options=LAYOUTS, value="dagre",
                     style={"marginBottom": "8px", "fontSize": "12px"}),
        
        # Search panel
        dcc.Input(id="search-input", placeholder="Search function, address, section...",
                  type="text", style={
                      "width": "100%", "backgroundColor": "var(--card)",
                      "border": "1px solid var(--border)", "borderRadius": "6px",
                      "padding": "6px 8px", "color": "var(--text)", "fontSize": "12px",
                      "marginBottom": "6px", "boxSizing": "border-box"
                  }),
        html.Div(id="search-results", style={"fontSize": "11px", "color": "var(--muted)"}),

        _hr,
        _section("03  ·  Analysis Metrics", "--blue"),
        html.Div(id="dashboard-metrics", children=[
            html.Div("Upload a binary to begin.",
                     style={"color": "var(--muted)", "fontSize": "12px"}),
        ], style={"marginBottom": "14px"}),

        _hr,
        _section("04  ·  Node Inspector", "--blue"),
        html.Div(id="node-inspector",
                 children=html.Div("Hover over a node to inspect.",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"marginBottom": "0"})),

    ], style=_left_style)

    # ── Center panel (graph) ──────────────────────────────────────────────────
    center_panel = html.Div(id="center-graph-panel", children=[
        # Active-node floating badge
        html.Div(id="active-node-badge", style={
            "position": "absolute", "top": "10px", "left": "10px",
            "zIndex": "100", "pointerEvents": "none",
            "display": "flex", "gap": "6px", "alignItems": "center",
        }),

        # Cytoscape graph
        cyto.Cytoscape(
            id="cytoscape-graph",
            layout=_build_layout("dagre"),
            style={"width": "100%", "height": "100%"},
            elements=[],
            stylesheet=_cyto_stylesheet(),
            minZoom=0.04, maxZoom=4.0,
            boxSelectionEnabled=True,
            autoRefreshLayout=False,
        ),

        # Floating Graph Legend
        html.Div(className="legend-overlay", children=[
            html.Div("Legend", style={"fontWeight": "bold", "marginBottom": "6px", "borderBottom": "1px solid var(--border)", "paddingBottom": "3px"}),
            html.Div([html.Div(className="legend-color", style={"backgroundColor": "#3fb950"}), "Entry Block (Diamond)"], className="legend-item"),
            html.Div([html.Div(className="legend-color", style={"backgroundColor": "#58a6ff"}), "Internal Block (Rect)"], className="legend-item"),
            html.Div([html.Div(className="legend-color", style={"backgroundColor": "#8957e5"}), "Library Call (Round-rect)"], className="legend-item"),
            html.Div([html.Div(className="legend-color", style={"backgroundColor": "#e3b341"}), "Syscall Block"], className="legend-item"),
            html.Div([html.Div(className="legend-color", style={"borderColor": "#39d353", "borderStyle": "dashed", "borderWidth": "2px", "backgroundColor": "transparent"}), "Loop Header"], className="legend-item"),
            html.Div([html.Div(className="legend-color", style={"backgroundColor": "#f85149"}), "Active Execution State"], className="legend-item"),
            html.Div([html.Div(className="legend-color", style={"backgroundColor": "#7c3aed"}), "Visited Node / Path"], className="legend-item"),
        ]),

        # Floating Zoom & Fullscreen controls
        html.Div([
            html.Button("＋", id="btn-zoom-in",  title="Zoom In",
                        style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                               "border": "1px solid var(--border)", "borderRadius": "6px",
                               "width": "34px", "height": "34px", "cursor": "pointer",
                               "fontSize": "18px", "lineHeight": "34px", "textAlign": "center",
                               "padding": "0"}),
            html.Button("−", id="btn-zoom-out", title="Zoom Out",
                        style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                               "border": "1px solid var(--border)", "borderRadius": "6px",
                               "width": "34px", "height": "34px", "cursor": "pointer",
                               "fontSize": "20px", "lineHeight": "34px", "textAlign": "center",
                               "padding": "0"}),
            html.Button("⛶ Fit", id="btn-fit", title="Fit Graph",
                        style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                               "border": "1px solid var(--border)", "borderRadius": "6px",
                               "width": "54px", "height": "34px", "cursor": "pointer",
                               "fontSize": "11px", "lineHeight": "34px", "textAlign": "center",
                               "padding": "0", "marginTop": "4px"}),
            html.Button("⛶ Full", id="btn-fullscreen", title="Toggle Fullscreen",
                        style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                               "border": "1px solid var(--border)", "borderRadius": "6px",
                               "width": "54px", "height": "34px", "cursor": "pointer",
                               "fontSize": "11px", "lineHeight": "34px", "textAlign": "center",
                               "padding": "0", "marginTop": "4px"}),
        ], style={
            "position": "absolute", "bottom": "16px", "right": "16px",
            "display": "flex", "flexDirection": "column", "gap": "4px", "zIndex": "100",
        }),

    ], style={"flex": "1", "position": "relative", "backgroundColor": "var(--bg)"})

    # ── Right panel (trace + SMT) ─────────────────────────────────────────────
    right_panel = html.Div([

        _section("Execution Trace", "--green"),

        # Playback controls
        html.Div([
            html.Button("⏮ First", id="btn-first", n_clicks=0, title="First State", style=_play_btn()),
            html.Button("◀",  id="btn-prev",  n_clicks=0, title="Previous",  style=_play_btn()),
            html.Button("▶",  id="btn-next",  n_clicks=0, title="Next",      style=_play_btn()),
            html.Button("⏭ Last",  id="btn-last",  n_clicks=0, title="Last State", style=_play_btn()),
            html.Button("⏯ Play",  id="btn-play",  n_clicks=0, title="Play/Pause",style=_play_btn("--green")),
        ], style={"display": "flex", "gap": "4px", "marginBottom": "8px"}),

        # Hide-library toggle
        dcc.Checklist(id="hide-library-toggle",
                      options=[{"label": "  Hide library calls", "value": "hide"}],
                      value=["hide"],
                      style={"fontSize": "11px", "color": "var(--muted)", "marginBottom": "8px"},
                      inputStyle={"marginRight": "5px"}),

        # Progress bar
        html.Div(id="trace-progress-label",
                 style={"fontSize": "11px", "color": "var(--muted)", "marginBottom": "4px"}),
        html.Div([
            html.Div(id="trace-progress-bar", style={
                "height": "3px", "backgroundColor": "var(--blue)",
                "borderRadius": "2px", "width": "0%",
                "transition": "width 0.3s ease",
            }),
        ], style={"backgroundColor": "var(--card)", "borderRadius": "2px", "marginBottom": "12px"}),

        # State viewer
        html.Div(id="state-viewer",
                 children=html.Div("Upload a binary and step through the trace.",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"minHeight": "140px"})),

        _hr,

        # SMT header
        html.Div([
            _section("SMT Constraint Diagnostics", "--purple"),
            html.Button("⚙ Advanced", id="btn-toggle-advanced", n_clicks=0, style={
                "backgroundColor": "transparent", "color": "var(--muted)",
                "border": "1px solid var(--border)", "borderRadius": "4px",
                "padding": "3px 10px", "cursor": "pointer",
                "fontSize": "11px", "fontFamily": "Inter, sans-serif",
            }),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "alignItems": "center", "marginBottom": "10px"}),

        html.Div(id="smt-viewer",
                 children=html.Div("Waiting for SMT solver analysis details...",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"borderLeft": "3px solid var(--purple)",
                                        "marginBottom": "0"})),

        _hr,

        # Vulnerability findings header
        html.Div([
            _section("Vulnerability Findings", "--red"),
            html.Button("🔻 Collapse", id="btn-toggle-findings", n_clicks=0, style={
                "backgroundColor": "transparent", "color": "var(--muted)",
                "border": "1px solid var(--border)", "borderRadius": "4px",
                "padding": "3px 10px", "cursor": "pointer",
                "fontSize": "11px", "fontFamily": "Inter, sans-serif",
            }),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "alignItems": "center", "marginBottom": "10px"}),

        html.Div(id="findings-viewer",
                 children=html.Div("Upload a binary to run the vulnerability scan.",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"borderLeft": "3px solid var(--red)",
                                        "marginBottom": "0"})),

        # Stores + interval
        dcc.Interval(id="play-interval", interval=900, n_intervals=0, disabled=True),
        dcc.Store(id="cfg-store"),
        dcc.Store(id="cg-store"),
        dcc.Store(id="trace-store",      data=[]),
        dcc.Store(id="trace-index",      data=0),
        dcc.Store(id="play-state",       data=False),
        dcc.Store(id="advanced-visible",   data=False),
        dcc.Store(id="findings-store",   data=[]),
        dcc.Store(id="findings-visible", data=True),
        dcc.Store(id="metrics-store",    data={}),
        dcc.Store(id="binary-info-store", data={}),
        dcc.Store(id="theme-store",      data="dark"),
        dcc.Store(id="shortcut-dummy",   data=""),

    ], style=_right_style)

    app.layout = html.Div([
        header,
        html.Div([left_panel, center_panel, right_panel],
                 style={"display": "flex", "flex": "1", "overflow": "hidden",
                        "minHeight": "0"}),
    ], id="main-container", style={
        "display": "flex", "flexDirection": "column",
        "height": "100vh", "overflow": "hidden",
        "backgroundColor": "var(--bg)",
        "fontFamily": "Inter, sans-serif",
    })

    # ── Callbacks ─────────────────────────────────────────────────────────────

    # Clientside keyboard shortcut handler (safe undefined guard)
    app.clientside_callback(
        """
        function(n_int) {
            if (!window.shortcut_listener_added) {
                window.shortcut_listener_added = true;
                document.addEventListener('keydown', function(e) {
                    if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) {
                        return;
                    }
                    var key = e.key || '';
                    if (key === 'ArrowRight') {
                        var btn = document.getElementById('btn-next');
                        if (btn) btn.click();
                    } else if (key === 'ArrowLeft') {
                        var btn = document.getElementById('btn-prev');
                        if (btn) btn.click();
                    } else if (key === ' ' || key === 'Spacebar') {
                        e.preventDefault();
                        var btn = document.getElementById('btn-play');
                        if (btn) btn.click();
                    } else if (key.toLowerCase() === 'r') {
                        var btn = document.getElementById('btn-reset');
                        if (btn) btn.click();
                    }
                });
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("shortcut-dummy", "data"),
        Input("play-interval", "n_intervals")
    )

    # Theme store: pure Python — toggles "dark"/"light" string in dcc.Store
    @app.callback(
        Output("theme-store", "data"),
        Input("btn-theme", "n_clicks"),
        State("theme-store", "data"),
        prevent_initial_call=True,
    )
    def toggle_theme_store(n, current):
        return "light" if (current or "dark") == "dark" else "dark"

    # Theme className: clientside reads the store and applies body class
    app.clientside_callback(
        """
        function(theme) {
            var t = theme || 'dark';
            var cls = t === 'dark' ? 'theme-dark' : 'theme-light';
            if (document.body.className !== cls) {
                document.body.className = cls;
            }
            return cls;
        }
        """,
        Output("main-container", "className"),
        Input("theme-store", "data"),
    )

    # Toggle fullscreen clientside callback (safe, no undefined)
    app.clientside_callback(
        """
        function(n_clicks) {
            if (!n_clicks) return window.dash_clientside.no_update;
            var panel = document.getElementById('center-graph-panel');
            if (panel) {
                panel.classList.toggle('fullscreen-active');
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("btn-fullscreen", "className"),
        Input("btn-fullscreen", "n_clicks")
    )

    # Binary upload → analysis pipeline
    @app.callback(
        Output("upload-status",    "children"),
        Output("cfg-store",        "data"),
        Output("cg-store",         "data"),
        Output("trace-store",      "data"),
        Output("metrics-store",    "data"),
        Output("binary-info-store","data"),
        Output("findings-store",   "data"),
        Input("upload-binary",     "contents"),
        State("upload-binary",     "filename"),
        prevent_initial_call=True,
    )
    def handle_upload(contents, filename):
        if not contents:
            raise PreventUpdate

        t0 = time.perf_counter()
        try:
            _, b64 = contents.split(",", 1)
            decoded = base64.b64decode(b64)

            fd, tmp = tempfile.mkstemp(prefix="angr_target_")
            with open(tmp, "wb") as f:
                f.write(decoded)
            os.close(fd)

            loader = BinaryLoader(tmp)
            loader.analyze()

            builder = GraphBuilder(loader)
            nx_cfg = builder.build_networkx_cfg()
            nx_cg  = builder.build_networkx_cg()
            cfg_elements = nx_to_cyto(nx_cfg)
            cg_elements  = nx_to_cyto(nx_cg)

            backend   = AnalysisBackendProvider(tmp)
            raw_trace = backend.get_execution_trace()

            trace: List[dict] = []
            sat_n = unsat_n = total_constraints = total_solver_time = 0
            for state_obj in raw_trace:
                d: Dict[str, Any] = asdict(state_obj)
                smt_obj = backend.get_constraint_result(state_obj)
                sd = asdict(smt_obj)
                d["smt_diagnostics"] = sd
                s = sd.get("status", "N/A")
                if s == "SAT":   sat_n += 1
                elif s == "UNSAT": unsat_n += 1
                total_constraints += len(sd.get("constraint_annotations", []))
                total_solver_time += sd.get("solver_time_ms", 0.0)
                trace.append(d)

            try:
                os.remove(tmp)
            except Exception:
                pass

            lib_funcs = sum(1 for _, d in nx_cg.nodes(data=True) if d.get("is_library_call"))
            elapsed   = round(time.perf_counter() - t0, 2)
            
            # Calculate dynamic branch coverage using CFG edges
            discovered_branches = [node for node in nx_cfg.nodes() if nx_cfg.out_degree(node) > 1]
            visited_nodes = set()
            for s in trace:
                addr_str = s.get("instruction_address")
                if not addr_str or not addr_str.startswith("0x"):
                    continue  # skip non-address markers like CRASH's 'SYMBOLIC (unconstrained IP)'
                try:
                    visited_nodes.add(int(addr_str, 16))
                except ValueError:
                    continue
            total_branch_edges = sum(nx_cfg.out_degree(node) for node in discovered_branches)
            visited_branch_edges = 0
            
            visited_edges = set()
            for i in range(len(trace) - 1):
                src_str = trace[i].get("instruction_address", "")
                dst_str = trace[i+1].get("instruction_address", "")
                if src_str and dst_str:
                    try:
                        src = int(src_str, 16)
                        dst = int(dst_str, 16)
                        if nx_cfg.has_edge(src, dst):
                            visited_edges.add((src, dst))
                    except ValueError:
                        pass
            
            for node in discovered_branches:
                if node in visited_nodes:
                    for succ in nx_cfg.successors(node):
                        if (node, succ) in visited_edges:
                            visited_branch_edges += 1
            
            branch_cov_val = (visited_branch_edges / max(total_branch_edges, 1)) * 100
            branch_cov = f"{branch_cov_val:.1f}%"
            
            # Real stashes and statistics from SimulationManager
            active_paths = len(backend.engine.simgr.active)
            deadended_paths = len(backend.engine.simgr.deadended)
            unsat_paths = len(backend.engine.simgr.unsat)
            errored_paths = len(backend.engine.simgr.errored)
            explored_paths = active_paths + deadended_paths + unsat_paths + errored_paths
            
            max_depth = max((s.get("execution_depth", 0) for s in trace), default=0)
            max_solver = max((s.get("smt_diagnostics", {}).get("solver_time_ms", 0.0) for s in trace), default=0.0)
            
            all_sym_vars = set()
            for s in trace:
                sym_list = s.get("smt_diagnostics", {}).get("symbolic_variables_list", [])
                for v in sym_list:
                    all_sym_vars.add(v.get("name"))
            total_sym_vars = len(all_sym_vars)
            
            avg_c = round(total_constraints / max(len(trace), 1), 1)

            # cyclomatic statistics
            cc_list = [d.get("cyclomatic_complexity", 1) for _, d in nx_cg.nodes(data=True) if d.get("cyclomatic_complexity") is not None]
            avg_cc = round(sum(cc_list) / max(len(cc_list), 1), 1)

            metrics = {
                "total_functions":    nx_cg.number_of_nodes(),
                "library_functions":  lib_funcs,
                "user_functions":     nx_cg.number_of_nodes() - lib_funcs,
                "total_basic_blocks": nx_cfg.number_of_nodes(),
                "cfg_edges":          nx_cfg.number_of_edges(),
                "execution_states":   len(trace),
                "sat_paths":          sat_n,
                "unsat_paths":        unsat_paths,
                "branch_coverage":    branch_cov,
                "avg_constraints":    avg_c,
                "analysis_time_s":    elapsed,
                "filename":           filename,
                "avg_cyclomatic":     avg_cc,
                "avg_solver_time":    round(total_solver_time / max(len(trace), 1), 2),
                "total_solver_calls": len(trace),
                
                # New metrics
                "max_depth":          max_depth,
                "explored_paths":     explored_paths,
                "active_paths":       active_paths,
                "deadended_paths":    deadended_paths,
                "max_solver_time":    round(max_solver, 2),
                "total_sym_vars":     total_sym_vars,
            }
            binary_info = {
                "filename":   filename,
                "size_bytes": len(decoded),
                "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            try:
                findings = backend.get_vulnerability_findings()
                findings_data = [asdict(f) for f in findings]
            except Exception:
                findings_data = []

            return (
                f"✅  {filename}  —  analyzed in {elapsed}s",
                cfg_elements, cg_elements, trace, metrics, binary_info, findings_data,
            )

        except Exception as exc:
            return f"❌  Error: {exc}", [], [], [], {}, {}, []

    # Trace index navigation + graph selection + search match jump
    @app.callback(
        Output("trace-index",        "data"),
        Output("play-state",         "data"),
        Output("play-interval",      "disabled"),
        Input("btn-next",            "n_clicks"),
        Input("btn-prev",            "n_clicks"),
        Input("btn-first",           "n_clicks"),
        Input("btn-last",            "n_clicks"),
        Input("btn-play",            "n_clicks"),
        Input("play-interval",       "n_intervals"),
        Input("cytoscape-graph",     "tapNodeData"),
        Input({"type": "search-match", "addr": ALL}, "n_clicks"),
        State("trace-index",         "data"),
        State("trace-store",         "data"),
        State("play-state",          "data"),
        State("hide-library-toggle", "value"),
    )
    def update_trace_index(
        _n, _p, _first, _last, _play, _intvl, tap_node, search_clicks,
        cur_idx, trace, is_playing, hide_lib_val,
    ):
        if not trace:
            return 0, False, True

        hide_lib = "hide" in (hide_lib_val or [])
        triggered = ctx.triggered_id

        def first_vis() -> int:
            if not hide_lib or not trace[0].get("is_library", False):
                return 0
            return _next_vis(trace, -1, 1, hide_lib)

        def last_vis() -> int:
            if not hide_lib or not trace[-1].get("is_library", False):
                return len(trace) - 1
            return _next_vis(trace, len(trace), -1, hide_lib)

        # Graph node clicked → jump to first matching execution state
        if triggered == "cytoscape-graph":
            if tap_node:
                node_id = str(tap_node.get("id", ""))
                for i, s in enumerate(trace):
                    if str(s.get("instruction_address", "")) == node_id:
                        return i, False, True
            return no_update, no_update, no_update

        # Search match button clicked
        if isinstance(triggered, dict) and triggered.get("type") == "search-match":
            clicked_addr = triggered.get("addr")
            if clicked_addr:
                for i, s in enumerate(trace):
                    if str(s.get("instruction_address", "")) == clicked_addr:
                        return i, False, True

        if triggered == "btn-first":
            return first_vis(), False, True
        if triggered == "btn-last":
            return last_vis(), False, True
        if triggered == "btn-prev":
            return _next_vis(trace, cur_idx, -1, hide_lib), False, True
        if triggered == "btn-next":
            return _next_vis(trace, cur_idx,  1, hide_lib), False, True
        if triggered == "btn-play":
            new_state = not is_playing
            if new_state and cur_idx >= len(trace) - 1:
                return first_vis(), new_state, not new_state
            return cur_idx, new_state, not new_state
        if triggered == "play-interval":
            if cur_idx >= len(trace) - 1:
                return cur_idx, False, True
            return _next_vis(trace, cur_idx, 1, hide_lib), is_playing, False

        return cur_idx, is_playing, not is_playing

    # Zoom controls
    @app.callback(
        Output("cytoscape-graph", "zoom"),
        Input("btn-zoom-in",  "n_clicks"),
        Input("btn-zoom-out", "n_clicks"),
        State("cytoscape-graph", "zoom"),
        prevent_initial_call=True,
    )
    def handle_zoom(zi, zo, current_zoom):
        z = float(current_zoom or 1.0)
        if ctx.triggered_id == "btn-zoom-in":
            return min(z * 1.4, 4.0)
        return max(z / 1.4, 0.04)

    # Toggle advanced SMT view
    @app.callback(
        Output("advanced-visible", "data"),
        Input("btn-toggle-advanced", "n_clicks"),
        State("advanced-visible",    "data"),
    )
    def toggle_advanced(n, cur):
        return (not cur) if n else cur

    # Toggle vulnerability findings collapse
    @app.callback(
        Output("findings-visible", "data"),
        Output("btn-toggle-findings", "children"),
        Input("btn-toggle-findings", "n_clicks"),
        State("findings-visible",    "data"),
    )
    def toggle_findings(n, cur):
        if not n:
            return cur, ("🔻 Collapse" if cur else "🔺 Expand")
        new_val = not cur
        return new_val, ("🔻 Collapse" if new_val else "🔺 Expand")

    _CONFIDENCE_META = {
        "z3-confirmed": ("💥", "#3d0d0d", "#f85149", "Z3-CONFIRMED"),
        "static":       ("🔗", "#2d2409", "#e3b341", "STATIC (call graph)"),
        "heuristic":    ("🧭", "#1a2233", "#79c0ff", "STATIC (heuristic)"),
        "textual":      ("🔑", "#1a0f3d", "#8957e5", "TEXTUAL SCAN"),
    }
    _SEVERITY_COLOR = {
        "Critical": "#f85149", "High": "#e3b341", "Medium": "#79c0ff", "Low": "#8b949e",
    }

    def _render_finding_card(f: dict) -> html.Div:
        conf = f.get("confidence", "heuristic")
        icon, bg, fg, conf_label = _CONFIDENCE_META.get(conf, _CONFIDENCE_META["heuristic"])
        sev = f.get("severity", "Medium")
        sev_color = _SEVERITY_COLOR.get(sev, "#8b949e")
        status = f.get("status", "N/A")
        status_color = "#3fb950" if status == "SAT" else "#f85149" if status == "UNSAT" else "#8b949e"

        return html.Div([
            html.Div([
                html.Span(f.get("finding_id", "finding"), style={
                    "fontFamily": "JetBrains Mono, monospace", "fontWeight": "700",
                    "fontSize": "13px", "color": "var(--text)",
                }),
                html.Span(f"{icon} {conf_label}", style={
                    "backgroundColor": bg, "color": fg, "borderRadius": "4px",
                    "padding": "2px 8px", "fontSize": "10px", "fontWeight": "600",
                    "marginLeft": "8px",
                }),
                html.Span(sev, style={
                    "color": sev_color, "fontSize": "10px", "fontWeight": "700",
                    "float": "right", "textTransform": "uppercase",
                }),
            ], style={"marginBottom": "6px"}),

            html.Div([
                (html.Span(f.get("cwe"), style={
                    "fontFamily": "JetBrains Mono, monospace", "color": "var(--muted)",
                    "fontSize": "11px", "marginRight": "10px",
                }) if f.get("cwe") else None),
                html.Span(status, style={
                    "fontFamily": "JetBrains Mono, monospace", "color": status_color,
                    "fontSize": "11px", "fontWeight": "700",
                }),
            ], style={"marginBottom": "8px"}),

            html.Div([
                html.Strong("Constraint: ", style={"color": "var(--muted)", "fontSize": "11px"}),
                html.Span(f.get("constraint", ""), style={
                    "fontFamily": "JetBrains Mono, monospace", "fontSize": "11px", "color": "var(--text)",
                }),
            ], style={"marginBottom": "4px"}),

            html.Div([
                html.Strong("Witness: ", style={"color": "var(--muted)", "fontSize": "11px"}),
                html.Span(f.get("witness", ""), style={
                    "fontFamily": "JetBrains Mono, monospace", "fontSize": "11px", "color": "#3fb950",
                    "wordBreak": "break-all",
                }),
            ], style={"marginBottom": "4px"}),

            html.Div([
                html.Strong("Reason: ", style={"color": "var(--muted)", "fontSize": "11px"}),
                html.Span(f.get("reason", ""), style={"fontSize": "11px", "color": "var(--text)"}),
            ], style={"marginBottom": "4px"}),

            (html.Div(f"@ {f.get('address')} · {f.get('function_name')}", style={
                "fontSize": "10px", "color": "var(--muted)", "marginTop": "6px",
                "fontFamily": "JetBrains Mono, monospace",
            }) if f.get("address") else None),
        ], style={
            "border": f"1px solid {fg}", "borderRadius": "6px", "padding": "12px",
            "marginBottom": "10px", "backgroundColor": "var(--card)",
        })

    @app.callback(
        Output("findings-viewer", "children"),
        Input("findings-store",   "data"),
        Input("findings-visible", "data"),
    )
    def render_findings(findings, visible):
        if not findings:
            return html.Div("No findings yet — upload a binary to run the vulnerability scan.",
                             style={"color": "var(--muted)", "fontSize": "12px"})
        if not visible:
            crit = sum(1 for f in findings if f.get("severity") == "Critical")
            high = sum(1 for f in findings if f.get("severity") == "High")
            return html.Div(
                f"{len(findings)} finding(s) — {crit} critical, {high} high. Click Expand to view.",
                style={"color": "var(--muted)", "fontSize": "12px"}
            )

        # Z3-confirmed findings first (highest confidence), then by severity.
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        conf_rank = {"z3-confirmed": 0, "static": 1, "heuristic": 2, "textual": 3}
        ordered = sorted(
            findings,
            key=lambda f: (conf_rank.get(f.get("confidence"), 9), sev_rank.get(f.get("severity"), 9))
        )
        return [_render_finding_card(f) for f in ordered]

    # Main rendering: graph elements + right-panel content
    @app.callback(
        Output("cytoscape-graph",      "elements"),
        Output("cytoscape-graph",      "layout"),
        Output("state-viewer",         "children"),
        Output("smt-viewer",           "children"),
        Output("trace-progress-bar",   "style"),
        Output("trace-progress-label", "children"),
        Output("active-node-badge",    "children"),
        Input("trace-index",           "data"),
        Input("graph-selector",        "value"),
        Input("cfg-store",             "data"),
        Input("cg-store",              "data"),
        Input("advanced-visible",      "data"),
        Input("layout-selector",       "value"),
        Input("btn-fit",               "n_clicks"),
        State("trace-store",           "data"),
    )
    def update_graph_and_viewer(
        trace_idx, graph_type, cfg_data, cg_data, show_adv, layout_name, fit_clicks, trace
    ):
        elements = list(cfg_data or []) if graph_type == "cfg" else list(cg_data or [])
        triggered = ctx.triggered_id or ""

        # Auto-fit only on upload, layout selection change, graph type toggle, or fit button click
        force_fit = triggered in ("cfg-store", "cg-store", "graph-selector", "layout-selector", "btn-fit", "")
        
        layout_out = _build_layout(layout_name)
        if not force_fit:
            layout_out["fit"] = False

        pb_base = {"height": "3px", "backgroundColor": "var(--blue)",
                   "borderRadius": "2px", "transition": "width 0.3s ease"}

        if not elements:
            empty = html.Div("Upload a binary to begin.",
                             style={"color": "var(--muted)", "fontSize": "12px"})
            return ([], layout_out, empty, empty,
                    _merge(pb_base, {"width": "0%"}), "", [])

        viewer = []
        smt    = []
        pct    = 0
        plabel = ""
        badge  = []

        if trace and 0 <= trace_idx < len(trace):
            s   = trace[trace_idx]
            n   = len(trace)
            pct = round((trace_idx + 1) / n * 100)
            plabel = f"Step {trace_idx + 1} of {n}"

            active_id  = str(s.get("instruction_address", ""))
            event_type = s.get("event_type", "NORMAL")
            icon, label, evt_bg, evt_fg = EVENT_META.get(event_type, EVENT_META["NORMAL"])

            # Floating badge
            badge = [
                _event_badge(event_type),
                html.Span(active_id, style={
                    "fontFamily": "JetBrains Mono, monospace",
                    "fontSize": "11px", "color": "var(--text)",
                    "backgroundColor": "var(--panel)",
                    "border": "1px solid var(--border)",
                    "borderRadius": "4px", "padding": "2px 8px",
                }),
            ]

            # Compute visited sets and path edges
            visited_set = {
                str(p.get("instruction_address", ""))
                for p in trace[:trace_idx]
            } - {active_id}
            path_edges: set = set()
            for i in range(trace_idx):
                src = str(trace[i].get("instruction_address", ""))
                dst = str(trace[i + 1].get("instruction_address", ""))
                if src != dst:
                    path_edges.add((src, dst))

            # Update element CSS classes
            prev_id = str(trace[trace_idx - 1].get("instruction_address", "")) \
                      if trace_idx > 0 else ""
            for elem in elements:
                d       = elem["data"]
                classes = elem.get("classes", "")
                for m in (" active-execution-node", " visited-execution-node",
                           " branch-node", " active-edge", " visited-edge"):
                    classes = classes.replace(m, "")

                if "source" in d and "target" in d:
                    key = (d["source"], d["target"])
                    if key == (prev_id, active_id):
                        classes += " active-edge"
                    elif key in path_edges:
                        classes += " visited-edge"
                elif "id" in d:
                    if d["id"] == active_id:
                        classes += " active-execution-node"
                        if s.get("is_branch"):
                            classes += " branch-node"
                    elif d["id"] in visited_set:
                        classes += " visited-execution-node"
                elem["classes"] = classes.strip()

            # ── State viewer ──────────────────────────────────────────────
            extra_badges = []
            if s.get("is_library"):
                extra_badges.append(_badge("📚 library", "#1a0f3d", "var(--purple)",
                                           {"marginRight": "4px"}))
            if s.get("is_branch"):
                extra_badges.append(_badge("⑂ branch",  "#2d2409", "var(--yellow)",
                                           {"marginRight": "4px"}))

            sat_col = "--green" if s.get("solver_status") == "SAT" else "--red"

            viewer = [
                html.Div([_event_badge(event_type)] + extra_badges,
                         style={"marginBottom": "10px"}),
                _kv("Depth",            s.get("execution_depth", ""),     "--yellow"),
                _kv("Address",          s.get("instruction_address", ""), "--blue"),
                _kv("Function",         s.get("function_name", ""),       "--text"),
                _kv("Current Block",    s.get("basic_block", ""),         "--text"),
                _kv("Previous Block",   s.get("previous_block", "None"),  "--muted"),
                _kv("Next Block",       s.get("next_block", "Pending"),   "--muted"),
                _kv("Sym Vars",         s.get("symbolic_variables", ""),  "--muted"),
                _kv("Solver",           s.get("solver_status", ""),       sat_col),
                html.Hr(style={"borderColor": "var(--border)", "margin": "8px 0"}),
                html.Div("Contextual Explanation:",
                         style={"color": "var(--muted)", "fontSize": "11px", "marginBottom": "4px"}),
                html.Div(str(s.get("explanation", "")), style={
                    "backgroundColor": "var(--card)",
                    "borderLeft": "3px solid var(--blue)",
                    "padding": "8px 10px", "borderRadius": "0 4px 4px 0",
                    "fontSize": "12px", "lineHeight": "1.6",
                }),
                html.Div([
                    html.Span("Next State: ", style={"color": "var(--muted)", "fontSize": "12px"}),
                    html.Span(str(s.get("next_state", "")), style={
                        "fontFamily": "JetBrains Mono, monospace",
                        "color": "var(--cyan)", "fontSize": "12px",
                    }),
                ], style={"marginTop": "8px"}),
            ]

            # ── SMT panel ─────────────────────────────────────────────────
            smt_d = s.get("smt_diagnostics", {})
            status = smt_d.get("status", "N/A")
            stime  = smt_d.get("solver_time_ms", 0.0)
            anns   = smt_d.get("constraint_annotations", [])

            # Per-constraint cards
            c_cards: List[Any] = []
            for ann in anns:
                parts = ann.split(" — ", 1)
                c_cards.append(html.Div([
                    html.Div(parts[0], style={
                        "fontFamily": "JetBrains Mono, monospace",
                        "fontSize": "11px", "color": "var(--yellow)",
                        "marginBottom": "3px",
                    }),
                    html.Div(parts[1] if len(parts) > 1 else "", style={
                        "fontSize": "11px", "color": "var(--muted)",
                        "fontStyle": "italic", "lineHeight": "1.5",
                    }),
                ], style={
                    "backgroundColor": "var(--bg)",
                    "borderLeft": "3px solid var(--purple)",
                    "border": "1px solid var(--border)",
                    "borderLeftWidth": "3px",
                    "borderRadius": "0 4px 4px 0",
                    "padding": "7px 9px", "marginBottom": "6px",
                }))

            if not c_cards:
                c_cards = [html.Div("No symbolic constraints have accumulated yet. The program has executed linear instruction sequences or unconditional jumps that do not depend on symbolic inputs (stdin). The execution path is trivially satisfiable for any inputs.",
                                    style={"color": "var(--muted)", "fontSize": "12px", "fontStyle": "italic"})]

            # Symbolic variables table
            sym_vars = smt_d.get("symbolic_variables_list", [])
            if sym_vars:
                table_header = html.Thead(html.Tr([
                    html.Th("Variable", style={"color": "var(--muted)", "fontSize": "11px", "padding": "4px"}),
                    html.Th("Type",     style={"color": "var(--muted)", "fontSize": "11px", "padding": "4px"}),
                    html.Th("Size",     style={"color": "var(--muted)", "fontSize": "11px", "padding": "4px"}),
                    html.Th("Hex",      style={"color": "var(--muted)", "fontSize": "11px", "padding": "4px"}),
                    html.Th("ASCII",    style={"color": "var(--muted)", "fontSize": "11px", "padding": "4px"}),
                ]), style={"borderBottom": "1px solid var(--border)"})
                
                table_rows = []
                for var in sym_vars:
                    table_rows.append(html.Tr([
                        html.Td(var["name"], style={"fontFamily": "JetBrains Mono, monospace", "fontSize": "11px", "padding": "4px", "wordBreak": "break-all"}),
                        html.Td(var["type"], style={"fontSize": "11px", "padding": "4px"}),
                        html.Td(f"{var['size']} B", style={"fontSize": "11px", "padding": "4px"}),
                        html.Td(var["hex"], style={"fontFamily": "JetBrains Mono, monospace", "fontSize": "11px", "padding": "4px", "wordBreak": "break-all"}),
                        html.Td(var["ascii"], style={"fontFamily": "JetBrains Mono, monospace", "fontSize": "11px", "padding": "4px", "wordBreak": "break-all"}),
                    ]))
                
                sym_table = html.Table([table_header, html.Tbody(table_rows)], style={
                    "width": "100%", "borderCollapse": "collapse", "marginTop": "8px", "marginBottom": "8px"
                }, className="sym-table-styled")
            else:
                sym_table = html.Div("No active symbolic inputs are in scope.", style={"color": "var(--muted)", "fontSize": "12px", "fontStyle": "italic"})

            smt = [
                # Status row
                html.Div([
                    _badge(f"● {status}",
                           "var(--green)" if status == "SAT" else "#3d0c0c",
                           "var(--green)" if status == "SAT" else "var(--red)",
                           {"fontSize": "12px", "marginRight": "10px"}),
                    html.Span(f"{len(anns)} constraint(s)", style={"color": "var(--muted)", "fontSize": "11px"}),
                    html.Span(f"  ·  {stime:.1f} ms",
                              style={"color": "var(--dim)", "fontSize": "11px",
                                     "fontFamily": "JetBrains Mono, monospace"}),
                ], style={"marginBottom": "10px", "display": "flex",
                          "alignItems": "center", "flexWrap": "wrap"}),

                # Constraint annotation cards
                html.Div(c_cards),

                html.Hr(style={"borderColor": "var(--border)", "margin": "10px 0"}),

                # Satisfying Model Assignment
                html.Div("Satisfying Model Assignment:",
                         style={"color": "var(--muted)", "fontSize": "11px", "marginBottom": "4px"}),
                sym_table,

                html.Hr(style={"borderColor": "var(--border)", "margin": "10px 0"}),

                # Plain-language solver explanation (only displayed here in SMT Diagnostics panel)
                html.Div("Z3 Solver Analysis & Reasoning:", style={"color": "var(--muted)", "fontSize": "11px", "marginBottom": "4px"}),
                html.Div(smt_d.get("explanation", ""), style={
                    "fontSize": "12px", "color": "var(--muted)",
                    "fontStyle": "italic", "lineHeight": "1.5",
                    "marginBottom": "10px",
                }),

                # Solver statistics
                html.Div(smt_d.get("statistics", ""), style={
                    "fontSize": "11px", "color": "var(--dim)",
                    "fontFamily": "JetBrains Mono, monospace",
                    "whiteSpace": "pre-wrap",
                }),
            ]

            if show_adv:
                smt += [
                    html.Hr(style={"borderColor": "var(--border)", "margin": "10px 0"}),
                    html.Div("⚙  Raw SMT / Z3 Constraints:", style={
                        "color": "var(--red)", "fontSize": "11px",
                        "fontWeight": "600", "marginBottom": "4px",
                    }),
                    html.Div(smt_d.get("raw_constraint_list") or "None.", style={
                        "fontFamily": "JetBrains Mono, monospace",
                        "fontSize": "10px", "color": "var(--yellow)",
                        "backgroundColor": "var(--bg)", "padding": "6px 8px",
                        "borderRadius": "4px", "whiteSpace": "pre-wrap",
                        "wordBreak": "break-all",
                        "border": "1px solid var(--border)",
                    }),
                ]

        pb = _merge(pb_base, {"width": f"{pct}%"})
        return elements, layout_out, viewer, smt, pb, plabel, badge

    # Node hover → inspector panel
    @app.callback(
        Output("node-inspector", "children"),
        Input("cytoscape-graph", "mouseoverNodeData"),
    )
    def update_node_inspector(data):
        if not data:
            return html.Div("Hover over a node to inspect.",
                            style={"color": "var(--muted)", "fontSize": "12px"})

        nc = data.get("node_class", "internal")
        nc_color = {
            "entry":    "--green", "library": "--purple",
            "syscall":  "--yellow",
        }.get(nc, "--blue")

        is_rec = "Yes" if data.get("is_recursive") else "No"
        rec_color = "--red" if data.get("is_recursive") else "--muted"

        rows: List[Any] = [
            html.Div(_badge(f"⬡  {nc.upper()}", {
                "entry": "#1a4731", "library": "#1a0f3d", "syscall": "#2d2009",
            }.get(nc, "#0f2a47"), f"var({nc_color})"),
                style={"marginBottom": "10px"}),
            _kv("Name",         data.get("name") or data.get("label", ""), "--text"),
            _kv("Address",      data.get("addr", ""),   "--blue"),
            _kv("Type",         data.get("type", ""),   nc_color),
            _kv("Section",      data.get("binary_section", ".text"), "--muted"),
            _kv("Recursive",    is_rec,                 rec_color),
        ]

        if data.get("instruction_count") is not None:
            rows.append(_kv("Instructions",      data["instruction_count"], "--yellow"))
        if data.get("basic_block_count") is not None:
            rows.append(_kv("Basic Blocks",      data["basic_block_count"], "--yellow"))
        if data.get("cyclomatic_complexity") is not None:
            rows.append(_kv("Cyclomatic CC",     data["cyclomatic_complexity"], "--orange"))
        if data.get("size") is not None:
            rows.append(_kv("Size (bytes)",      data["size"], "--muted"))
        if data.get("incoming_edges") is not None:
            rows.append(_kv("In-degree",         data["incoming_edges"],  "--muted"))
        if data.get("outgoing_edges") is not None:
            rows.append(_kv("Out-degree",        data["outgoing_edges"],  "--muted"))

        for field_name, label in [("callers", "Callers"), ("callees", "Callees")]:
            raw = data.get(field_name, "[]")
            try:
                lst = json.loads(raw) if isinstance(raw, str) else raw
            except Exception:
                lst = []
            if lst:
                rows.append(html.Div([
                    html.Span(f"{label}: ",
                              style={"color": "var(--muted)", "fontSize": "12px"}),
                    html.Span(", ".join(str(x) for x in lst[:6]),
                              style={"fontFamily": "JetBrains Mono, monospace",
                                     "fontSize": "11px", "color": "var(--muted)"}),
                ], style={"marginBottom": "4px"}))

        if data.get("is_loop_header"):
            rows.append(html.Div(
                _badge("↻  Loop Header", "#063535", "var(--cyan)"),
                style={"marginTop": "6px"}
            ))

        return rows

    # Dashboard metrics panel
    @app.callback(
        Output("dashboard-metrics",  "children"),
        Output("header-binary-info", "children"),
        Input("metrics-store",    "data"),
        Input("binary-info-store","data"),
    )
    def update_dashboard(metrics, binary_info):
        bi = binary_info or {}
        if not metrics:
            return (
                html.Div("Upload a binary to begin.",
                         style={"color": "var(--muted)", "fontSize": "12px"}),
                "No binary loaded",
            )

        row1 = html.Div([
            _metric("Functions",   metrics.get("total_functions", 0),  "--blue",   "Total functions discovered in binary"),
            _metric("Lib Funcs",   metrics.get("library_functions", 0),"--purple", "Library procedures & runtime imports"),
            _metric("Usr Funcs",   metrics.get("user_functions", 0),   "--green",  "User-defined procedures"),
        ], style={"display": "flex", "gap": "6px", "marginBottom": "6px"})

        row2 = html.Div([
            _metric("Basic Blocks",metrics.get("total_basic_blocks", 0),"--orange","Total basic block nodes"),
            _metric("SAT",         metrics.get("sat_paths", 0),        "--green",  "Satisfiable execution states"),
            _metric("UNSAT",       metrics.get("unsat_paths", 0),      "--red",    "Unsatisfiable execution states"),
        ], style={"display": "flex", "gap": "6px", "marginBottom": "6px"})

        row3 = html.Div([
            _metric("Branch Cov",  metrics.get("branch_coverage", "0%"),"--yellow","Branch decision coverage percentage"),
            _metric("Avg Const",   metrics.get("avg_constraints", 0),  "--cyan",   "Average constraints accumulated per state"),
            _metric("Avg Solver",  f"{metrics.get('avg_solver_time', 0)}ms","--muted","Average time spent on SMT solver execution"),
        ], style={"display": "flex", "gap": "6px", "marginBottom": "6px"})

        row4 = html.Div([
            _metric("Max Depth",   metrics.get("max_depth", 0),        "--blue",   "Maximum path execution depth"),
            _metric("Active Paths",metrics.get("active_paths", 0),     "--green",  "Paths currently active in symbolic engine"),
            _metric("Deadended",   metrics.get("deadended_paths", 0),  "--purple", "Paths that terminated normally"),
        ], style={"display": "flex", "gap": "6px", "marginBottom": "6px"})

        row5 = html.Div([
            _metric("Max Solver",  f"{metrics.get('max_solver_time', 0.0)}ms","--cyan","Maximum solver time for a single state"),
            _metric("Sym Vars",    metrics.get("total_sym_vars", 0),   "--orange", "Total symbolic variables in scope"),
            _metric("Explored",    metrics.get("explored_paths", 0),   "--muted",  "Total paths explored (active + deadended + unsat + errored)"),
        ], style={"display": "flex", "gap": "6px", "marginBottom": "6px"})

        footer = html.Div(
            f"{bi.get('filename','')} · {bi.get('size_bytes', 0):,} bytes · {bi.get('timestamp','')}",
            style={"fontSize": "10px", "color": "var(--dim)",
                   "fontFamily": "JetBrains Mono, monospace"},
        )

        header_info = [
            html.Span("binary: ", style={"color": "var(--dim)"}),
            html.Span(bi.get("filename", ""), style={"color": "var(--blue)", "fontWeight": "600"}),
            html.Span(f"  ({bi.get('size_bytes', 0):,} bytes)", style={"color": "var(--dim)"}),
        ]

        return [row1, row2, row3, row4, row5, footer], header_info

    # Search function/address
    @app.callback(
        Output("search-results", "children"),
        Input("search-input", "value"),
        State("cfg-store", "data"),
        State("cg-store", "data"),
        State("graph-selector", "value"),
    )
    def handle_search(search_val, cfg_data, cg_data, graph_type):
        if not search_val:
            return ""
        
        elements = cfg_data if graph_type == "cfg" else cg_data
        if not elements:
            return "No graph loaded."
        
        matches = []
        val_lower = search_val.lower().strip()
        for elem in elements:
            d = elem.get("data", {})
            if "id" in d:
                name = str(d.get("name", "")).lower()
                addr = str(d.get("addr", "")).lower()
                section = str(d.get("binary_section", "")).lower()
                if val_lower in name or val_lower in addr or val_lower in section:
                    matches.append((d.get("name") or d.get("label"), d.get("addr") or d.get("id")))
        
        if not matches:
            return "No matching nodes found."
        
        # Display up to 5 matching nodes as clickable buttons
        results: List[Any] = [html.Div("Matches:", style={"fontWeight": "bold", "marginBottom": "3px"})]
        for name, addr in matches[:5]:
            results.append(html.Button(f"• {name} ({addr})", id={"type": "search-match", "addr": addr}, n_clicks=0, style={
                "fontFamily": "JetBrains Mono, monospace", "fontSize": "11px",
                "color": "var(--blue)", "cursor": "pointer", "padding": "2px 0",
                "background": "none", "border": "none", "textAlign": "left", "display": "block",
                "width": "100%"
            }))
        if len(matches) > 5:
            results.append(html.Div(f"...and {len(matches)-5} more matches", style={"fontStyle": "italic"}))
        return results

    # Report export
    @app.callback(
        Output("download-report", "data"),
        Input("btn-export",    "n_clicks"),
        State("trace-store",   "data"),
        State("metrics-store", "data"),
        prevent_initial_call=True,
    )
    def export_report(n_clicks, trace, metrics):
        if not n_clicks or not trace:
            raise PreventUpdate
        filename = (metrics or {}).get("filename", "unknown")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return dcc.send_string(
            _make_report(filename, trace or [], metrics or {}, ts),
            f"analysis_{filename}.html",
        )

    return app