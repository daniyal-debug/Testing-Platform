"""Render an :class:`AnalysisResult` into JSON, Markdown and a self-contained
HTML document.

The HTML report is the primary deliverable — a single file with no external
dependencies that a developer can open, print, or hand to their team. It merges
each finding's short remediation with the long-form guide from
:mod:`apk_sentinel.knowledge`.
"""
from __future__ import annotations

import html
import json
from typing import List

from . import knowledge
from .models import AnalysisResult, Finding, Severity

_SEV_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}
_SEV_COLOR = {
    Severity.CRITICAL: "#b3123b",
    Severity.HIGH: "#d64518",
    Severity.MEDIUM: "#c08a00",
    Severity.LOW: "#2f7d9a",
    Severity.INFO: "#5b6472",
}


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_markdown(result: AnalysisResult) -> str:
    m = result.manifest
    lines: List[str] = []
    a = lines.append

    a(f"# APK Sentinel Report — {result.file_name}")
    a("")
    a(f"- **Package:** `{m.package or 'unknown'}`")
    a(f"- **Version:** {m.version_name or '?'} (code {m.version_code if m.version_code is not None else '?'})")
    a(f"- **Security grade:** {result.grade}  |  **Risk score:** {result.risk_score}/100")
    a(f"- **SHA-256:** `{result.sha256}`")
    a(f"- **Analyzed:** {result.analyzed_at} (engine {result.engine_version})")
    a("")

    counts = result.severity_counts
    a("## Summary")
    a("")
    a("| Severity | Count |")
    a("| --- | --- |")
    for s in Severity:
        a(f"| {_SEV_LABEL[s]} | {counts[s.value]} |")
    a("")

    a("## Prioritized action plan")
    a("")
    top = [f for f in result.sorted_findings() if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    if not top:
        a("No high-priority issues. Address any Low/Info items as good hygiene.")
    else:
        for i, f in enumerate(top, 1):
            a(f"{i}. **[{_SEV_LABEL[f.severity]}]** {f.title} — {f.remediation}")
    a("")

    a("## App details")
    a("")
    a(f"- Min SDK: {m.min_sdk}  |  Target SDK: {m.target_sdk}  |  Max SDK: {m.max_sdk}")
    a(f"- DEX files: {result.dex_count}  |  Native ABIs: {', '.join(sorted({n.split('/')[1] for n in result.native_libs if '/' in n})) or 'none'}")
    a(f"- Uncompressed size: {_human(result.total_uncompressed)}")
    cert = result.certificate
    a(f"- Signing: v1={cert.v1_signed} v2={cert.v2_signed} v3={cert.v3_signed}")
    a(f"- Permissions requested: {len(m.permissions)}")
    a("")

    a("## Findings")
    a("")
    for f in result.sorted_findings():
        a(f"### [{_SEV_LABEL[f.severity]}] {f.title}")
        a("")
        a(f"*Category: {f.category}"
          + (f" · {f.cwe}" if f.cwe else "")
          + (f" · {f.masvs}" if f.masvs else "") + "*")
        a("")
        a(f.description)
        a("")
        if f.evidence:
            a("**Evidence:**")
            a("")
            for e in f.evidence:
                a(f"- `{e}`")
            a("")
        a(f"**How to fix:** {f.remediation}")
        a("")
        guide = knowledge.get_guide(f.id)
        if guide:
            _md_guide(a, guide)
        if f.references:
            a("**References:** " + " · ".join(f.references))
            a("")
        a("---")
        a("")

    a("## Methodology & limitations")
    a("")
    a(_METHODOLOGY)
    return "\n".join(lines)


def _md_guide(a, guide: dict) -> None:
    steps = guide.get("fix_steps") or []
    if steps:
        a("**Step-by-step:**")
        a("")
        for i, s in enumerate(steps, 1):
            a(f"{i}. {s}")
        a("")
    code = guide.get("code_example")
    if code:
        a("```")
        a(code.strip())
        a("```")
        a("")
    verify = guide.get("how_to_verify")
    if verify:
        a(f"**Verify the fix:** {verify}")
        a("")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def render_html(result: AnalysisResult, nav_html: str = "") -> str:
    """Render the full self-contained HTML report.

    ``nav_html`` is optional markup injected right after ``<body>`` — the web app
    uses it to add a sticky toolbar with download links.
    """
    m = result.manifest
    counts = result.severity_counts
    e = html.escape

    grade_color = {
        "A+": "#1a7f4b", "A": "#1a7f4b", "B": "#2f7d9a",
        "C": "#c08a00", "D": "#d64518", "F": "#b3123b",
    }.get(result.grade, "#5b6472")

    parts: List[str] = []
    p = parts.append

    p("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    p("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    p(f"<title>APK Sentinel — {e(result.file_name)}</title>")
    p(f"<style>{_CSS}</style></head><body>")
    if nav_html:
        p(nav_html)

    # -- header ----------------------------------------------------------
    p("<header class='hero'><div class='hero-main'>")
    p("<div class='brand'>🛡️ APK Sentinel</div>")
    p(f"<h1>{e(m.package or result.file_name)}</h1>")
    p("<div class='sub'>")
    p(f"<span>v{e(m.version_name or '?')} (code {m.version_code if m.version_code is not None else '?'})</span>")
    p(f"<span>{e(result.file_name)}</span>")
    p(f"<span>{_human(result.file_size)}</span>")
    p(f"<span>Analyzed {e(result.analyzed_at)}</span>")
    p("</div></div>")
    p(f"<div class='grade' style='--gc:{grade_color}'><div class='g'>{result.grade}</div>"
      f"<div class='rs'>Risk {result.risk_score}/100</div></div>")
    p("</header>")

    # -- severity chips --------------------------------------------------
    p("<section class='chips'>")
    for s in Severity:
        c = counts[s.value]
        cls = "chip" + ("" if c else " zero")
        p(f"<div class='{cls}' style='--sc:{_SEV_COLOR[s]}'><b>{c}</b><span>{_SEV_LABEL[s]}</span></div>")
    p("</section>")

    # -- executive summary ----------------------------------------------
    p("<section class='card'><h2>Executive summary</h2>")
    p(f"<p>{_exec_summary(result)}</p>")
    top = [f for f in result.sorted_findings()
           if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    if top:
        p("<h3>Prioritized action plan</h3><ol class='plan'>")
        for f in top:
            p(f"<li><span class='sev' style='--sc:{_SEV_COLOR[f.severity]}'>{_SEV_LABEL[f.severity]}</span>"
              f"<b>{e(f.title)}</b><br><span class='muted'>{e(f.remediation)}</span></li>")
        p("</ol>")
    else:
        p("<p class='muted'>No high-priority issues found. Address any Low/Info items as good hygiene.</p>")
    p("</section>")

    # -- app details -----------------------------------------------------
    cert = result.certificate
    abis = sorted({n.split('/')[1] for n in result.native_libs if '/' in n})
    rows = [
        ("Package", m.package or "—"),
        ("Version", f"{m.version_name or '?'} (code {m.version_code if m.version_code is not None else '?'})"),
        ("Min / Target / Max SDK", f"{m.min_sdk} / {m.target_sdk} / {m.max_sdk}"),
        ("SHA-256", result.sha256),
        ("MD5", result.md5),
        ("DEX files", str(result.dex_count)),
        ("Native ABIs", ", ".join(abis) or "none"),
        ("Uncompressed size", _human(result.total_uncompressed)),
        ("Signing schemes", _sign_str(cert)),
        ("Permissions", str(len(m.permissions))),
    ]
    p("<section class='card'><h2>Application details</h2><table class='kv'>")
    for k, v in rows:
        p(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>")
    p("</table>")
    if cert.signers:
        p("<h3>Signing certificate</h3><table class='kv'>")
        for i, sg in enumerate(cert.signers, 1):
            p(f"<tr><th>Signer {i} subject</th><td>{e(sg.get('subject','—'))}</td></tr>")
            p(f"<tr><th>Signature algorithm</th><td>{e(sg.get('sig_algorithm','—'))}"
              + (" <span class='warn'>weak</span>" if sg.get('weak_signature') else "")
              + (" <span class='warn'>debug key</span>" if sg.get('debug_certificate') else "")
              + "</td></tr>")
            if sg.get("valid_until"):
                p(f"<tr><th>Valid until</th><td>{e(sg.get('valid_until'))}</td></tr>")
        p("</table>")
    p("</section>")

    # -- permissions -----------------------------------------------------
    if m.permissions:
        p("<section class='card'><h2>Requested permissions "
          f"<span class='count'>{len(m.permissions)}</span></h2><ul class='perms'>")
        for perm in sorted(m.permissions):
            short = perm.split(".")[-1]
            p(f"<li title='{e(perm)}'>{e(short)}</li>")
        p("</ul></section>")

    # -- components ------------------------------------------------------
    comps = m.all_components
    if comps:
        p("<section class='card'><h2>Components "
          f"<span class='count'>{len(comps)}</span></h2><table class='comp'>")
        p("<tr><th>Type</th><th>Name</th><th>Exported</th><th>Permission</th></tr>")
        for c in comps:
            exp = c.effective_exported
            exp_cls = "yes" if exp else "no"
            exp_txt = ("exported" if exp else "internal")
            if exp and c.exported is None:
                exp_txt = "implicit"
            p(f"<tr><td>{e(c.kind)}</td><td class='mono'>{e(_short(c.name))}</td>"
              f"<td class='{exp_cls}'>{exp_txt}</td><td>{e(c.permission or '—')}</td></tr>")
        p("</table></section>")

    # -- findings --------------------------------------------------------
    p("<section class='card'><h2>Findings "
      f"<span class='count'>{len(result.findings)}</span></h2>")
    if not result.findings:
        p("<p class='muted'>No issues detected by the current rule set. 🎉</p>")
    for f in result.sorted_findings():
        p(_finding_html(f))
    p("</section>")

    # -- secrets ---------------------------------------------------------
    if result.secrets:
        p("<section class='card'><h2>Potential secrets</h2>"
          "<p class='muted'>Values are partially masked. Treat any real credential as compromised and rotate it.</p>"
          "<table class='comp'><tr><th>Kind</th><th>Preview</th><th>Source</th></tr>")
        for s in result.secrets:
            p(f"<tr><td>{e(s.kind)}</td><td class='mono'>{e(s.value_preview)}</td><td class='mono'>{e(s.source)}</td></tr>")
        p("</table></section>")

    # -- methodology -----------------------------------------------------
    p("<section class='card muted-card'><h2>Methodology &amp; limitations</h2>"
      f"<p>{e(_METHODOLOGY)}</p></section>")

    p(f"<footer>Generated by APK Sentinel v{e(result.engine_version)} · "
      "Static analysis only · Not a substitute for a full manual security assessment</footer>")
    p("</body></html>")
    return "".join(parts)


def _finding_html(f: Finding) -> str:
    e = html.escape
    color = _SEV_COLOR[f.severity]
    out = [f"<article class='finding' style='--sc:{color}'>"]
    tags = f"<span class='pill'>{e(f.category)}</span>"
    if f.cwe:
        tags += f"<span class='pill'>{e(f.cwe)}</span>"
    if f.masvs:
        tags += f"<span class='pill'>{e(f.masvs)}</span>"
    out.append(f"<div class='fhead'><span class='sev' style='--sc:{color}'>{_SEV_LABEL[f.severity]}</span>"
               f"<h3>{e(f.title)}</h3></div>")
    out.append(f"<div class='tags'>{tags}</div>")
    out.append(f"<p>{e(f.description)}</p>")
    if f.evidence:
        out.append("<div class='evidence'><b>Evidence</b><ul>")
        for ev in f.evidence:
            out.append(f"<li class='mono'>{e(ev)}</li>")
        out.append("</ul></div>")
    out.append(f"<div class='fix'><b>How to fix</b><p>{e(f.remediation)}</p>")

    guide = knowledge.get_guide(f.id)
    if guide:
        steps = guide.get("fix_steps") or []
        if steps:
            out.append("<b>Step-by-step</b><ol>")
            for s in steps:
                out.append(f"<li>{e(s)}</li>")
            out.append("</ol>")
        code = guide.get("code_example")
        if code:
            out.append(f"<pre><code>{e(code.strip())}</code></pre>")
        verify = guide.get("how_to_verify")
        if verify:
            out.append(f"<p class='verify'><b>Verify:</b> {e(verify)}</p>")
    out.append("</div>")

    refs = list(f.references)
    guide_refs = (guide or {}).get("references") or []
    for r in guide_refs:
        if r not in refs:
            refs.append(r)
    if refs:
        out.append("<div class='refs'><b>References</b> " +
                   " · ".join(_ref_link(r) for r in refs) + "</div>")
    out.append("</article>")
    return "".join(out)


def _ref_link(ref: str) -> str:
    e = html.escape
    if ref.startswith("http"):
        return f"<a href='{e(ref)}' target='_blank' rel='noopener'>{e(_ref_label(ref))}</a>"
    return f"<span>{e(ref)}</span>"


def _ref_label(url: str) -> str:
    try:
        host = url.split("//", 1)[1].split("/", 1)[0]
        return host.replace("www.", "")
    except Exception:
        return url


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _exec_summary(result: AnalysisResult) -> str:
    c = result.severity_counts
    m = result.manifest
    total = len(result.findings)
    parts = [
        f"Static analysis of <b>{html.escape(m.package or result.file_name)}</b> "
        f"produced <b>{total}</b> finding(s): "
        f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, "
        f"{c['low']} low, {c['info']} informational."
    ]
    if c["critical"]:
        parts.append("Critical issues must be resolved before release.")
    elif c["high"]:
        parts.append("High-severity issues should be resolved before release.")
    elif c["medium"]:
        parts.append("No critical/high issues, but medium items are worth addressing.")
    else:
        parts.append("No critical, high or medium issues were detected.")
    return " ".join(parts)


def _sign_str(cert) -> str:
    schemes = []
    if cert.v1_signed:
        schemes.append("v1")
    if cert.v2_signed:
        schemes.append("v2")
    if cert.v3_signed:
        schemes.append("v3")
    return ", ".join(schemes) or "unsigned"


def _short(name: str, keep: int = 48) -> str:
    if not name:
        return "(unnamed)"
    if len(name) <= keep:
        return name
    return "…" + name[-(keep - 1):]


def _human(n: int) -> str:
    step = 1024.0
    units = ["B", "KB", "MB", "GB"]
    v = float(n)
    for u in units:
        if v < step or u == units[-1]:
            return f"{v:.0f} {u}" if u == "B" else f"{v:.1f} {u}"
        v /= step
    return f"{n} B"


_METHODOLOGY = (
    "APK Sentinel performs static analysis: it decodes the AndroidManifest, "
    "inspects signing metadata, extracts string constants from DEX bytecode and "
    "applies a catalog of security and quality rules. It does not execute the "
    "app, so runtime-only issues (business logic flaws, live network behaviour, "
    "obfuscated logic) are out of scope. Findings should be validated in context; "
    "a clean report is not a guarantee of security. For high-assurance needs, "
    "combine this with dynamic analysis and a manual review against the OWASP MASTG."
)

_CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#1a1f28;--muted:#5b6472;--line:#e4e7ec;--accent:#2f6df6;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
.hero{display:flex;justify-content:space-between;align-items:center;gap:24px;
 background:linear-gradient(120deg,#111827,#1f2937);color:#fff;padding:28px 32px;}
.hero h1{margin:6px 0 8px;font-size:26px;word-break:break-all}
.brand{font-weight:700;letter-spacing:.3px;opacity:.9}
.hero .sub{display:flex;flex-wrap:wrap;gap:14px;color:#c7cdd6;font-size:13px}
.hero .sub span{white-space:nowrap}
.grade{background:var(--gc);color:#fff;border-radius:16px;padding:16px 22px;text-align:center;min-width:120px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.grade .g{font-size:46px;font-weight:800;line-height:1}
.grade .rs{font-size:12px;opacity:.95;margin-top:4px}
.chips{display:flex;gap:12px;flex-wrap:wrap;padding:20px 32px 4px}
.chip{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--sc);
 border-radius:10px;padding:10px 16px;min-width:96px;display:flex;flex-direction:column}
.chip b{font-size:22px;color:var(--sc)}
.chip span{font-size:12px;color:var(--muted)}
.chip.zero{opacity:.5}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:16px 32px;padding:22px 26px}
.card h2{margin:0 0 14px;font-size:19px}
.card h3{font-size:15px;margin:18px 0 8px}
.count{background:#eef1f6;color:var(--muted);border-radius:20px;font-size:12px;padding:2px 10px;margin-left:6px;vertical-align:middle}
.muted{color:var(--muted)}
.muted-card{background:#fafbfc}
table.kv{width:100%;border-collapse:collapse}
table.kv th{text-align:left;color:var(--muted);font-weight:600;width:210px;padding:6px 10px;vertical-align:top;font-size:13px}
table.kv td{padding:6px 10px;word-break:break-all;font-size:13px}
table.kv tr:nth-child(even){background:#fafbfc}
.warn{background:#fde7ec;color:#b3123b;border-radius:6px;font-size:11px;padding:1px 7px;margin-left:6px}
.perms{list-style:none;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:8px}
.perms li{background:#eef1f6;border-radius:8px;padding:5px 10px;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace}
table.comp{width:100%;border-collapse:collapse;font-size:13px}
table.comp th{text-align:left;background:#f3f5f9;padding:8px 10px;font-size:12px;color:var(--muted)}
table.comp td{padding:8px 10px;border-top:1px solid var(--line);word-break:break-all}
td.yes{color:#b3123b;font-weight:600}
td.no{color:var(--muted)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
ol.plan{margin:6px 0 0;padding-left:20px}
ol.plan li{margin:8px 0}
.sev{display:inline-block;background:var(--sc);color:#fff;border-radius:6px;font-size:11px;
 font-weight:700;padding:2px 9px;margin-right:8px;text-transform:uppercase;letter-spacing:.4px;vertical-align:middle}
.finding{border:1px solid var(--line);border-left:5px solid var(--sc);border-radius:12px;padding:16px 18px;margin:14px 0;background:#fff}
.finding .fhead{display:flex;align-items:center;gap:4px}
.finding h3{margin:0;font-size:16px}
.tags{margin:8px 0}
.pill{display:inline-block;background:#eef1f6;color:var(--muted);border-radius:20px;font-size:11px;padding:2px 10px;margin-right:6px}
.evidence,.fix,.refs{margin-top:12px}
.evidence ul{margin:6px 0;padding-left:18px}
.evidence li{font-size:12.5px;word-break:break-all;color:#2b3240}
.fix{background:#f6faf7;border:1px solid #dcece1;border-radius:10px;padding:12px 14px}
.fix ol{margin:6px 0;padding-left:20px}
.fix pre{background:#0f1720;color:#e6edf3;border-radius:8px;padding:12px 14px;overflow:auto;font-size:12.5px;line-height:1.5}
.fix code{font-family:ui-monospace,Menlo,Consolas,monospace}
.verify{background:#eef4ff;border-radius:8px;padding:8px 12px;font-size:13px}
.refs{font-size:12.5px;color:var(--muted)}
.refs a{color:var(--accent);text-decoration:none}
.refs a:hover{text-decoration:underline}
footer{color:var(--muted);text-align:center;padding:24px;font-size:12px}
@media(max-width:640px){.hero{flex-direction:column;align-items:flex-start}.card,.chips{margin:12px 14px}}
@media print{body{background:#fff}.card,.finding{break-inside:avoid}}
"""
