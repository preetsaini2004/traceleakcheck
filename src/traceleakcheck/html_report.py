"""Self-contained HTML report: one card per checked test, in plain English, with fixes."""

from __future__ import annotations

from html import escape

from .explain import explain

_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;
--red:#c8341f;--red-bg:#fdecea;--green:#1f7a3f;--green-bg:#e8f5ec;--amber:#9a6400;--amber-bg:#fdf3dc;
--code:#f0f0ec}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--ink:#ecece8;--muted:#a3a39c;
--line:#33332f;--red:#ff7a66;--red-bg:#3a1d18;--green:#6fd18f;--green-bg:#16301f;--amber:#f0be5a;
--amber-bg:#352a12;--code:#2a2a27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 24px}
.totals{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:28px}
.pill{border-radius:999px;padding:6px 14px;font-weight:600;font-size:14px}
.pill.leak{background:var(--red-bg);color:var(--red)}.pill.clean{background:var(--green-bg);color:var(--green)}
.pill.incomplete,.pill.error{background:var(--amber-bg);color:var(--amber)}
.card.leak .headline{color:var(--red)}.card.clean .headline{color:var(--green)}
.card.incomplete .headline,.card.error .headline{color:var(--amber)}
.card{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--line);
border-radius:10px;padding:18px 20px;margin-bottom:16px}
.card.leak{border-left-color:var(--red)}.card.clean{border-left-color:var(--green)}
.card.incomplete,.card.error{border-left-color:var(--amber)}
.card h2{font-size:15px;margin:0 0 6px;font-family:ui-monospace,Consolas,monospace;
word-break:break-all;color:var(--muted);font-weight:500}
.headline{font-size:18px;font-weight:600;margin:0 0 10px}
.step{margin:10px 0 0}.step b{font-weight:600}ul{margin:4px 0 0;padding-left:22px}
.how{color:var(--muted)}.fix{margin-top:14px;padding-top:12px;border-top:1px dashed var(--line)}
.fix h3{font-size:15px;margin:0 0 4px}.fix p{margin:0 0 8px}
pre{background:var(--code);border-radius:6px;padding:10px 12px;overflow-x:auto;margin:0 0 6px;
font:13px/1.5 ui-monospace,Consolas,monospace}
details{margin-top:12px;color:var(--muted);font-size:13px}
details code{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
footer{color:var(--muted);font-size:13px;margin-top:32px}
"""

_ICON = {"leak": "🚨", "clean": "✅", "incomplete": "⚠️", "error": "⚠️"}
_LABEL = {"leak": "leaked", "clean": "clean", "incomplete": "couldn't check", "error": "unreadable data"}


def _card(r: dict) -> str:
    exp = explain(r)
    s = exp.status
    parts = [f'<section class="card {s}"><h2>{escape(r["nodeid"])}</h2>',
             f'<p class="headline">{_ICON[s]} {escape(exp.headline)}</p>']
    for g in exp.groups:
        if len(g.steps) == 1:
            where = escape(g.where())
        else:
            where = f"In {len(g.steps)} steps: " + ", ".join(f"<b>{escape(s)}</b>" for s in g.steps)
        items = "".join(f'<li>{escape(p.what)} <span class="how">({escape(p.how)})</span></li>' for p in g.places)
        parts.append(f'<div class="step">{where}:<ul>{items}</ul></div>')
    if s in ("incomplete", "error") and r.get("detail"):
        parts.append(f'<p class="how">{escape(r["detail"])}</p>')
    for t in exp.tips:
        code = f"<pre>{escape(t.code)}</pre>" if t.code else ""
        parts.append(f'<div class="fix"><h3>💡 How to fix: {escape(t.title)}</h3><p>{escape(t.text)}</p>{code}</div>')
    if r["findings"]:
        rows = "".join(f'<li><code>{escape(f["path"])}</code> ({escape(f["canary_kind"])}, {escape(f["variant"])})</li>'
                       for f in r["findings"])
        parts.append(f"<details><summary>Technical details</summary><ul>{rows}</ul></details>")
    parts.append("</section>")
    return "".join(parts)


def render(report: dict) -> str:
    s = report["summary"]
    order = {"leak": 0, "incomplete": 1, "error": 2, "clean": 3}
    cards = "".join(_card(r) for r in sorted(report["results"], key=lambda r: order[r["status"]]))
    pills = "".join(f'<span class="pill {k}">{s[k]} {_LABEL[k]}</span>' for k in ("leak", "incomplete", "error", "clean"))
    verdict = ("Secrets leaked. Fix the red cards below." if s["leak"]
               else "Some tests couldn't be checked." if s["incomplete"] or s["error"]
               else "No leaks found.")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TraceLeakCheck report</title><style>{_CSS}</style></head>
<body><main>
<h1>TraceLeakCheck report</h1>
<p class="sub">{escape(verdict)} Each card is one test that planted a fake secret and checked whether your
app sent it out in its monitoring data (OpenTelemetry).</p>
<div class="totals">{pills}</div>
{cards or '<p>No tests used the <code>canary</code> fixture.</p>'}
<footer>The secrets were fake canaries made for this run; none of your real keys appear in this report.</footer>
</main></body></html>
"""
