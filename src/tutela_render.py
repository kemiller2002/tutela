#!/usr/bin/env python3
"""Render a Tutela presentation projection into portable Forma/Folio-oriented HTML."""
from __future__ import annotations
import html, json, sys
from pathlib import Path
try:
    from .tutela_present import project
except ImportError:
    from tutela_present import project

def esc(x): return html.escape(str(x if x is not None else ""))
def render(a):
    v=project(a)
    inv="".join(f'<ef-invariant-result id="{esc(i["id"])}" data-state="{esc(i["state"].lower())}"><h3>{esc(i["id"])}</h3><strong>{esc(i["state"])}</strong><p>Evidence: {esc(", ".join(i["evidence"]) or "None")}</p></ef-invariant-result>' for i in v["invariants"])
    reasons="".join(f"<li>{esc(x)}</li>" for x in v["reasons"]) or "<li>None</li>"
    limitations="".join(f"<li>{esc(x)}</li>" for x in v["limitations"]) or "<li>None declared</li>"
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(v.get("assessmentId") or "Tutela assessment")}</title></head>
<body><main>
<ef-security-posture data-posture="{esc(v["posture"].lower())}"><h1>Tutela security evidence record</h1><strong>{esc(v["posture"])}</strong><p>{esc(v["qualification"])}</p><dl><dt>Repository</dt><dd>{esc(v["subject"].get("repository"))}</dd><dt>Ref</dt><dd><code>{esc(v["subject"].get("ref"))}</code></dd></dl></ef-security-posture>
<ef-security-blockers><h2>Posture reasons</h2><ul>{reasons}</ul></ef-security-blockers>
<section aria-labelledby="invariants"><h2 id="invariants">Security invariants</h2>{inv}</section>
<ef-print-security-record><h2>Methodology and limitations</h2><ul>{limitations}</ul></ef-print-security-record>
</main></body></html>'''
def main():
    a=json.loads(Path(sys.argv[1]).read_text()); out=render(a)
    if len(sys.argv)>2: Path(sys.argv[2]).write_text(out)
    else: print(out)
if __name__=="__main__": main()
