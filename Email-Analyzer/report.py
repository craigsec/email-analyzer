"""
Readable HTML report + ticket summary for Email Analyzer.
Used by the desktop app and the command-line tool. Written in the language set in config.txt (i18n.py).
"""
import base64
import html
import re
from datetime import datetime
from pathlib import Path

import appconfig
import i18n
import qr_check as engine
from i18n import T

HERE = Path(__file__).resolve().parent


def logo_file():
    """Optional logo for the report header and the app. No logo.png, no logo."""
    return HERE / "logo.png"


def tr_lines(notes, recs):
    """Score explanation with the warnings in the current language."""
    score, parts = file_score(notes, recs)
    return score, [f"+{pt:<3} {i18n.msg(m)}" for pt, _, m in sorted(parts, key=lambda x: -x[0])]

LEVELS = {
    "danger": ("DANGEROUS", "#d93d42", "#fdecec"),
    "warn":   ("SUSPICIOUS", "#c97f00", "#fff5e0"),
    "minor":  ("LOW RISK", "#8a6d1c", "#faf4df"),
    "known":  ("KNOWN SITE", "#21875a", "#e8f6ee"),
    "clean":  ("NO FLAGS", "#68778b", "#eef1f5"),
    "info":   ("NOT A LINK", "#4d63c9", "#eceffd"),
}
RANK = {"danger": 0, "warn": 1, "minor": 2, "known": 3, "clean": 4, "info": 5}
SKIP_PREFIX = ("urlscan report:", "Screenshot saved:", "Screenshot not ready yet")
# big platforms used as stepping stones: block the hidden destination, not these
NEVER_BLOCK = {"google.com", "bing.com", "youtube.com", "facebook.com", "linkedin.com", "t.co",
               "twitter.com", "x.com", "instagram.com", "apple.com", "amazon.com"}

HOST_RE = re.compile(r"(?<![\w@/.\[-])((?:[a-z0-9-]+\.)+[a-z]{2,63})(?![\w-])", re.I)
URL_RE = re.compile(r"(?i)\bhttps?://[^\s'\")<]+")


# ------------------------------------------------------------------ helpers
def level_of(rec):
    v = rec.get("verdict", "")
    if v.startswith("LIKELY"):
        return "danger"
    if v.startswith("SUSP"):
        return "warn"
    if v.startswith("LOW RISK"):
        return "minor"
    if v.startswith("Domain matches"):
        return "known"
    if v.startswith("No red flags"):
        return "clean"
    return "info"


def defang(text):
    """Make links, domains and emails unclickable: hxxps://evil[.]top, user[@]corp[.]com"""
    text = engine.EMAIL_RE.sub(lambda m: m.group(0).replace("@", "[@]").replace(".", "[.]"), text)
    text = URL_RE.sub(lambda m: m.group(0).replace("http", "hxxp", 1).replace(".", "[.]"), text)
    return HOST_RE.sub(lambda m: m.group(1).replace(".", "[.]"), text)


def sentence(m):
    """Messages about the top-level file start mid-sentence; capitalise them for display."""
    return m[0].upper() + m[1:] if m and m[0].islower() else m


def order_notes(notes):
    """Context first (Subject/From), then dangers, warnings, good news, then background details."""
    def key(n):
        lv, m = n
        if lv == engine.INFO and m.startswith(("Subject:", "From:")):
            return (0, 0)
        return (1, {engine.HIGH: 0, engine.MED: 1, engine.LOW: 2, engine.GOOD: 3}.get(lv, 4))
    return sorted(notes, key=key)


def flatten(recs):
    out = []
    for r in recs:
        out.append(r)
        out.extend(flatten(r.get("links_inside", [])))
    return out


def file_score(notes, recs):
    """Risk score for a whole file or email: every warning about the file itself, plus its WORST link
    (not all links, so an email with 30 ordinary links does not add up to a false alarm).
    Returns (score 0-100, [(points, level, message)])."""
    _, parts = engine.score_findings([(n[0], sentence(n[1])) for n in notes])
    best = max(flatten(recs), key=lambda r: r.get("score", 0), default=None)
    if best and best.get("score"):
        parts += [(sp["points"], sp["level"], "Worst link: " + sp["detail"]) for sp in best.get("score_parts", [])]
    return min(100, sum(pt for pt, _, _ in parts)), parts


def file_level(notes, recs):
    lv = [level_of(r) for r in flatten(recs)]
    worst = min(lv, key=lambda x: RANK[x]) if lv else "clean"
    score, _ = file_score(notes, recs)
    by_score = ("danger" if score >= engine.DANGER_AT else "warn" if score >= engine.SUSPICIOUS_AT
                else "minor" if score > 0 else "info")
    return min(worst, by_score, key=lambda x: RANK[x])


def score_lines(notes, recs):
    """Plain-text explanation of the score, one line per contributing finding."""
    score, parts = file_score(notes, recs)
    return score, [f"+{pt:<3} {m}" for pt, _, m in sorted(parts, key=lambda x: -x[0])]


# red flags about the address in general, not the domain itself: never a reason to block a domain
NOT_DOMAIN_FLAGS = ("Plain http", "is a link shortener", "File-sharing link", "Link path mentions",
                    "Link carries the recipient", "Could not read", "Link is malformed",
                    "belongs to", "Link hides a second address")


def domain_is_bad(url, brands):
    findings, _ = engine.domain_checks(url, brands)
    return any(lv == engine.HIGH or (lv == engine.MED and not any(t in m for t in NOT_DOMAIN_FLAGS))
               for lv, m in findings)


def block_lists(results, brands):
    """Domains and full links worth adding to Defender's Tenant Allow/Block List.
    A domain is only listed when the domain itself is the problem."""
    known = {d for b in brands for d in b["domains"]}
    domains, urls = [], []

    def add_domain(url, force=False):
        u = engine.normalise_url(url) or ""
        if not u:
            return
        _, parts, host, _, _ = engine.browser_parse(u)
        if not host:
            return
        ip = engine.numeric_ip(host)
        if ip:
            entry = ip
        else:
            _, reg = engine.host_info(host)
            if (reg in known or reg in NEVER_BLOCK or reg in engine.SHORTENERS
                    or any(reg == d or reg.endswith("." + d) for d in engine.FILE_SHARE)):
                return
            if not force and not domain_is_bad(u, brands):
                return
            # free hosting: block the attacker's own sub-site, never the whole platform
            entry = host if any(reg == d or reg.endswith("." + d) for d in engine.ABUSED_HOSTING) else reg
        if entry not in domains:
            domains.append(entry)

    for _, _, recs in results:
        for r in flatten(recs):
            if level_of(r) not in ("danger", "warn"):
                continue
            raw = r.get("raw", "").strip()
            if engine.normalise_url(raw):
                if raw not in urls:
                    urls.append(raw)
                add_domain(raw)
            for h in r.get("unwrapped", []) + r.get("hidden_destinations", []):
                add_domain(h)
            us = r.get("urlscan") or {}
            if us.get("final_url"):
                add_domain(us["final_url"], force=bool(us.get("malicious")))
    return domains, urls


def summary_text(results, mode, user, when=None):
    when = when or datetime.now()
    mode_shown = " + ".join(T(m) for m in str(mode).split(" + "))
    lines = [f"{T('Email Analyzer report')}  |  {when:%d/%m/%Y %H:%M}  |  {T('checked by')} {user}  |  {mode_shown}",
             T("(links are defanged: hxxp and [.] so they cannot be clicked)"), ""]
    for path, notes, recs in results:
        flat = flatten(recs)
        lv = [level_of(r) for r in flat]
        worst = file_level(notes, recs)
        lines.append(f"{T('File:')} {engine.visible(Path(path).name)}")
        score, why = tr_lines(notes, recs)
        lines.append(f"{T('Overall:')} {T(LEVELS[worst][0])}  |  {T('risk score')} {score}/100  ({lv.count('danger')} {T('dangerous')}, "
                     f"{lv.count('warn')} {T('suspicious')}, {lv.count('minor')} {T('low risk')}, "
                     f"{lv.count('known') + lv.count('clean')} {T('ok')})")
        lines.append(f"{T('What to do:')} {i18n.action(worst)}")
        if why:
            lines.append("  " + T("Score made of:"))
            lines += [f"    {defang(engine.visible(w))}" for w in why[:12]]
        for lvl, m in order_notes(notes):
            if lvl in (engine.HIGH, engine.MED, engine.LOW, engine.GOOD) or m.startswith(("Subject:", "From:")):
                lines.append(f"  [{lvl}] {defang(engine.visible(i18n.msg(sentence(m))))}")
        for r in flat:
            first = (r.get("raw", "").splitlines() or [""])[0]
            lines.append(f"  [{T(LEVELS[level_of(r)][0])}] {defang(engine.visible(first))}")
            lines.append(f"      {T('found in:')} {i18n.where(engine.visible('; '.join(r.get('found_in', []))))}")
            for f in r.get("findings", []):
                if f["level"] in ("HIGH", "MEDIUM", "LOW") and not f["detail"].startswith(SKIP_PREFIX):
                    lines.append(f"      - {defang(i18n.msg(f['detail']))}")
            us = r.get("urlscan") or {}
            if us.get("report"):
                lines.append(f"      urlscan report: {us['report']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _img_data_uri(path):
    try:
        data = Path(path).read_bytes()
        return "data:image/png;base64," + base64.b64encode(data).decode()
    except Exception:
        return ""


# --------------------------------------------------------------------- html
CSS = """
:root{--navy:#004680;--blue:#008ad8;--mid:#0069b1;--grey:#888b8d;--ink:#17212e;--muted:#5d6b7c;--line:#e3e8ef}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;color:var(--ink);background:#f4f6f9;font-size:14px;line-height:1.45}
header{background:var(--navy);color:#fff;padding:18px 32px;display:flex;align-items:center;gap:22px;border-bottom:4px solid var(--blue)}
header img{height:40px}
header .t{border-left:1px solid #3c6f9e;padding-left:22px}
header h1{margin:0;font-size:20px}
header p{margin:2px 0 0;color:#a9c6e3;font-size:12.5px}
main{max-width:1060px;margin:0 auto;padding:24px 28px 60px}
.meta{color:var(--muted);font-size:12.5px;margin:0 0 18px}
.banner{border-radius:12px;padding:16px 20px;display:flex;align-items:center;gap:16px;margin-bottom:22px;border:1px solid var(--line);background:#fff}
.banner .bar{width:8px;align-self:stretch;border-radius:4px}
.banner h2{margin:0;font-size:19px}
.banner .sub{color:var(--muted);font-size:12.5px}
.chips{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.chip{border-radius:20px;padding:4px 12px;font-weight:600;font-size:12.5px}
.box{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin-bottom:18px}
.box h3{margin:0 0 10px;font-size:15px;display:flex;align-items:center;gap:10px}
.box h3 .btn{margin-left:auto}
pre,code,.mono{font-family:"Cascadia Mono",Consolas,"DejaVu Sans Mono",monospace;font-size:12.5px}
pre{background:#f6f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;white-space:pre-wrap;word-break:break-all;margin:0;max-height:340px;overflow:auto}
.btn{font:inherit;font-size:12.5px;font-weight:600;border:1px solid #c6d3e1;background:#fff;color:var(--mid);border-radius:7px;padding:4px 11px;cursor:pointer}
.btn:hover{background:#eef5fc}
.btn.done{color:#21875a;border-color:#a7d9bf}
.filehead{margin:28px 0 10px}
.filehead h2{margin:0;font-size:17px}
.filehead .sub{color:var(--muted);font-size:12.5px;word-break:break-all}
.note{border-radius:9px;padding:9px 13px;margin:6px 0;font-size:13px}
.card{background:#fff;border:1px solid var(--line);border-left:6px solid;border-radius:12px;padding:14px 18px;margin:10px 0;page-break-inside:avoid}
.card.inner{margin-left:34px}
.row{display:flex;gap:12px;align-items:flex-start}
.pill{font-size:11px;font-weight:700;border-radius:7px;padding:3px 8px;white-space:nowrap;margin-top:1px}
.url{flex:1;word-break:break-all;font-size:13px}
.found{color:var(--muted);font-size:12px;margin:6px 0 8px}
ul.f{margin:0;padding-left:0;list-style:none}
ul.f li{position:relative;padding-left:16px;margin:3px 0;font-size:13px}
ul.f li:before{content:"";position:absolute;left:2px;top:7px;width:7px;height:7px;border-radius:50%;background:var(--c)}
.scan{display:flex;gap:16px;background:#f6f8fb;border:1px solid var(--line);border-radius:9px;padding:10px 12px;margin-top:10px}
.scan img{width:260px;border-radius:6px;border:1px solid var(--line)}
.scan .k{font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.04em}
.quick{display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:#fff;border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin-bottom:18px}
.quick b{font-size:13px;margin-right:6px}
.quick .btn{font-size:13px;padding:6px 14px}
.quick .btn.main{background:var(--blue);border-color:var(--blue);color:#fff}
.quick .btn.main:hover{background:var(--mid)}
details.box summary{cursor:pointer;font-weight:600;font-size:15px}
details.box[open] summary{margin-bottom:10px}
h2.sec{font-size:15px;margin:26px 0 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
footer{color:var(--muted);font-size:11.5px;text-align:center;padding:24px}
@media print{body{background:#fff}.btn,.quick{display:none}details.box{display:block}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 .card,.box,.banner{-webkit-print-color-adjust:exact;print-color-adjust:exact}pre{max-height:none}}
"""

JS = """
function copyText(id, btn){
  var t = document.getElementById(id).textContent;
  function ok(){ var o = btn.textContent; btn.textContent = 'Copied'; btn.classList.add('done');
                 setTimeout(function(){ btn.textContent = o; btn.classList.remove('done'); }, 1400); }
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(t).then(ok, function(){ fallback(t); ok(); });
  } else { fallback(t); ok(); }
}
function fallback(t){
  var a = document.createElement('textarea'); a.value = t; a.style.position = 'fixed'; a.style.opacity = '0';
  document.body.appendChild(a); a.select(); try { document.execCommand('copy'); } catch(e) {} document.body.removeChild(a);
}
"""


def build_html(results, mode, user, brands, when=None):
    when = when or datetime.now()
    e = html.escape
    uid = [0]

    def nid():
        uid[0] += 1
        return f"c{uid[0]}"

    def copy_block(title, text, hint=""):
        i = nid()
        return (f'<div class="box"><h3>{e(title)}<button class="btn" onclick="copyText(\'{i}\',this)">Copy</button></h3>'
                + (f'<div class="found">{e(hint)}</div>' if hint else "")
                + f'<pre id="{i}">{e(text)}</pre></div>')

    all_recs = [r for _, _, rs in results for r in flatten(rs)]
    all_notes = [n for _, ns, _ in results for n in ns]
    worst = min([file_level(ns, rs) for _, ns, rs in results] or ["clean"], key=lambda x: RANK[x])
    lv = [level_of(r) for r in all_recs]
    top_score = max([file_score(ns, rs)[0] for _, ns, rs in results] or [0])
    titles = {"danger": "Dangerous: do not open, report and block", "warn": "Suspicious: needs a closer look",
              "minor": "Low risk: only minor flags",
              "known": "Links go to known legitimate sites", "clean": "No red flags found",
              "info": "No web links found"}
    lab, col, soft = LEVELS[worst]
    chips = "".join(f'<span class="chip" style="background:{LEVELS[k][2]};color:{LEVELS[k][1]}">'
                    f'{lv.count(k)} {T(LEVELS[k][0].lower())}</span>'
                    for k in ("danger", "warn", "minor", "known", "clean", "info") if lv.count(k))
    logo = _img_data_uri(logo_file())
    org = appconfig.org_name()
    mode_shown = " + ".join(T(m) for m in str(mode).split(" + "))

    h = [f"<!DOCTYPE html><html lang='{i18n.language()}'><head><meta charset='utf-8'><title>{e(T('Email Analyzer report'))}</title>"
         f"<style>{CSS}</style><script>{JS}</script></head><body>"]
    h.append("<header>" + (f"<img src='{logo}' alt='{e(org)}'>" if logo else "")
             + f"<div class='t'><h1>{e(T('Email Analyzer report'))}</h1><p>"
             f"{e(T('ICT security tool  ·  Email, attachment and link phishing check'))}</p></div></header><main>")
    h.append(f"<p class='meta'>{e(T('Checked'))} {e(i18n.date(when, long=True))}  ·  {e(T('by'))} {e(user)}  ·  {e(mode_shown)}  ·  "
             f"{e(T('links shown here cannot be clicked'))}</p>")
    h.append(f"<div class='banner' style='background:{soft if worst in ('danger', 'warn') else '#fff'}'>"
             f"<div class='bar' style='background:{col}'></div><div><h2>{e(T(titles[worst]))}</h2>"
             f"<div style='font-weight:600;margin:2px 0 3px'>{e(T('What to do:'))} {e(i18n.action(worst))}</div>"
             f"<div class='sub'>{e(T('Risk score'))} {top_score}/100  ·  {len(results)} {e(T('file(s)'))}, {len(all_recs)} {e(T('link(s)'))}"
             f"</div></div>"
             f"<div class='chips'>{chips}</div></div>")

    domains, urls = block_lists(results, brands)
    summary = summary_text(results, mode, user, when)
    sid, did, uid_ = nid(), nid(), nid()
    copy = e(T("Copy"))
    q = [f"<div class='quick'><b>{e(T('Quick copy'))}</b>",
         f"<button class='btn main' onclick=\"copyText('{sid}',this)\">{e(T('Ticket summary'))}</button>"]
    if domains:
        q.append(f"<button class='btn' onclick=\"copyText('{did}',this)\">{e(T('Domains to block'))} ({len(domains)})</button>")
    if urls:
        q.append(f"<button class='btn' onclick=\"copyText('{uid_}',this)\">{e(T('All links, defanged'))} ({len(urls)})</button>")
    q.append(f"<span class='found' style='margin:0 0 0 auto'>{e(T('Everything copied is safe to paste: links cannot be clicked.'))}</span></div>")
    h.append("".join(q))
    if domains:
        h.append(f"<div class='box'><h3>{e(T('Domains to block'))}<button class='btn' onclick=\"copyText('{did}',this)\">{copy}</button></h3>"
                 f"<div class='found'>{e(T('For Defender > Tenant Allow/Block List. Real banks, Microsoft, Google, link shorteners and file-sharing sites are left out on purpose.'))}</div>"
                 f"<pre id='{did}'>{e(chr(10).join(domains))}</pre></div>")
    tail = [f"<details class='box'><summary>{e(T('Ticket summary (text)'))}</summary>"
            f"<div class='found'>{e(T('Paste into the ticket. Links are defanged so nobody can click them.'))} "
            f"<button class='btn' onclick=\"copyText('{sid}',this)\">{copy}</button></div>"
            f"<pre id='{sid}'>{e(summary)}</pre></details>"]
    if urls:
        tail.append(f"<details class='box'><summary>{e(T('All dangerous and suspicious links'))} ({len(urls)})</summary>"
                    f"<div class='found'>{e(T('Exactly as found, made unclickable.'))} "
                    f"<button class='btn' onclick=\"copyText('{uid_}',this)\">{copy}</button></div>"
                    f"<pre id='{uid_}'>{e(chr(10).join(defang(engine.visible(u)) for u in urls))}</pre></details>")
    h.append(f"<h2 class='sec'>{e(T('Results'))}</h2>")

    def card(r, inner=False):
        lv_ = level_of(r)
        lab_, col_, soft_ = LEVELS[lv_]
        i = nid()
        raw = r.get("raw", "")
        lis = "".join(
            f"<li style='--c:{ {'HIGH': '#d93d42', 'MEDIUM': '#e6a21a', 'LOW': '#c9b458', 'GOOD': '#21875a'}.get(f['level'], '#9aa6b5')}'>"
            f"{e(defang(i18n.msg(f['detail'])))}</li>"
            for f in r.get("findings", []) if not f["detail"].startswith(SKIP_PREFIX))
        out = (f"<div class='card{' inner' if inner else ''}' style='border-left-color:{col_}'>"
               f"<div class='row'><span class='pill' style='background:{soft_};color:{col_}'>{e(T(lab_))}"
               + (f" · {r['score']}" if r.get("score") else "") + "</span>"
               f"<span class='url mono' id='{i}'>{e(defang(engine.visible(raw)))}</span>"
               f"<button class='btn' onclick=\"copyText('{i}',this)\">{copy}</button></div>"
               f"<div class='found'>{e(T('Found in:'))} {e(i18n.where(engine.visible('; '.join(r.get('found_in', [])))))}</div>"
               f"<ul class='f'>{lis}</ul>")
        us = r.get("urlscan") or {}
        if us.get("report") or us.get("final_url"):
            shot = _img_data_uri(us["screenshot_file"]) if us.get("screenshot_file") else ""
            out += ("<div class='scan'><div style='flex:1'><div class='k'>LIVE SCAN  ·  URLSCAN.IO</div>"
                    + (f"<div class='mono' style='margin-top:4px'>{e(T('Lands on:'))} {e(defang(us['final_url']))}</div>" if us.get("final_url") else "")
                    + (f"<div>{e(T('Page title:'))} {e(engine.visible(us['title']))}</div>" if us.get("title") else "")
                    + (f"<div style='margin-top:6px'><a href='{e(us['report'])}' target='_blank'>{e(T('Open full urlscan report'))}</a></div>" if us.get("report") else "")
                    + "</div>" + (f"<img src='{shot}' alt='screenshot'>" if shot else "") + "</div>")
        out += "</div>"
        for sub in r.get("links_inside", []):
            out += card(sub, inner=True)
        return out

    for path, notes, recs in results:
        p = Path(path)
        h.append(f"<div class='filehead'><h2>{e(engine.visible(p.name))}</h2><div class='sub'>{e(engine.visible(str(p.parent)))}  ·  "
                 f"{len(recs)} {e(T('QR code(s) or link(s) found'))}</div></div>")
        f_score, f_why = tr_lines(notes, recs)
        f_level = file_level(notes, recs)
        f_lab, f_col, f_soft = LEVELS[f_level]
        explain = T("Each warning adds points (HIGH {h}, MEDIUM {m}, LOW {l}). From {s} suspicious, from {d} dangerous. "
                    "Only the worst link counts, plus everything about the email or file itself.",
                    h=engine.WEIGHTS[engine.HIGH], m=engine.WEIGHTS[engine.MED], l=engine.WEIGHTS[engine.LOW],
                    s=engine.SUSPICIOUS_AT, d=engine.DANGER_AT)
        h.append(f"<div class='box' style='border-left:6px solid {f_col}'><h3>{e(T(f_lab))}  ·  {e(T('risk score'))} {f_score}/100</h3>"
                 f"<div style='font-weight:600;margin-bottom:6px'>{e(T('What to do:'))} {e(i18n.action(f_level))}</div>"
                 f"<div class='found'>{e(explain)}</div>"
                 + ("<pre>" + e(chr(10).join(defang(engine.visible(w)) for w in f_why)) + "</pre>" if f_why else
                    f"<div class='found'>{e(T('Nothing added points.'))}</div>") + "</div>")
        for lvl, m in order_notes(notes):
            c = {"HIGH": ("#fdecec", "#b3262b"), "MEDIUM": ("#fff5e0", "#8a5a00"), "LOW": ("#faf4df", "#6f5a1a"),
                 "GOOD": ("#e8f6ee", "#1d6e47")}.get(lvl, ("transparent", "#5d6b7c"))
            pad = "" if lvl in ("HIGH", "MEDIUM", "LOW", "GOOD") else "padding:2px 13px;margin:2px 0;"
            h.append(f"<div class='note' style='background:{c[0]};color:{c[1]};{pad}'>{e(defang(engine.visible(i18n.msg(sentence(m)))))}</div>")
        for r in recs:
            h.append(card(r))
        if not recs and not notes:
            h.append(f"<div class='note' style='background:#eef1f5'>{e(T('No QR codes or links found.'))}</div>")

    h.append(f"<h2 class='sec'>{e(T('For the ticket'))}</h2>" + "".join(tail))
    h.append("</main><footer>" + (e(org) + "  ·  " if org else "") + "Email Analyzer  ·  "
             + e(T("A clean result is not proof of safety. If in doubt, treat it as phishing.")) + "</footer></body></html>")
    return "".join(h)


def report_path_for(paths, when=None):
    """Single file: <name>.emailcheck.html next to it. Several files: one combined report."""
    when = when or datetime.now()
    first = Path(paths[0])
    if len(paths) == 1:
        return first.with_suffix(".emailcheck.html")
    return first.parent / f"Email-check-{when:%Y%m%d-%H%M%S}.html"


def fallback_dir():
    """Used when the attachment's own folder cannot be written to (network share, Outlook temp)."""
    d = Path.home() / "Documents" / "Email Analyzer reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_text_safely(path, text):
    """Write next to the checked file; if that folder is read-only, use Documents. Returns the path or None."""
    for target in (Path(path), None):
        try:
            if target is None:
                target = fallback_dir() / Path(path).name
            target.write_text(text, encoding="utf-8")
            return target
        except Exception:
            continue
    return None


def write_report(results, mode, user, brands, when=None):
    when = when or datetime.now()
    path = report_path_for([r[0] for r in results], when)
    try:
        page = build_html(results, mode, user, brands, when)
    except Exception:
        return None
    return write_text_safely(path, page)


# ------------------------------------------------------------ domain watch
def build_watch_html(results, own, problems, user, when=None):
    import domain_watch
    when = when or datetime.now()
    e = html.escape
    col = {engine.HIGH: LEVELS["danger"], engine.MED: LEVELS["warn"], engine.INFO: LEVELS["clean"]}
    blk = domain_watch.block_list(results)
    logo = _img_data_uri(logo_file())
    org = appconfig.org_name()
    n_high = sum(r["level"] == engine.HIGH for r in results)
    n_med = sum(r["level"] == engine.MED for r in results)
    worst = "danger" if n_high else ("warn" if n_med else "clean")
    title = (f"{n_high} dangerous lookalike domain(s) found" if n_high else
             f"{n_med} suspicious lookalike domain(s) found" if n_med else "No dangerous lookalike domains found")
    h = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Lookalike domain watch</title>"
         f"<style>{CSS}</style><script>{JS}</script></head><body>"]
    h.append("<header>" + (f"<img src='{logo}' alt='{e(org)}'>" if logo else "")
             + "<div class='t'><h1>Lookalike domain watch</h1><p>Domains registered to imitate us or our partners</p></div></header><main>")
    h.append(f"<p class='meta'>Checked {when:%d %B %Y, %H:%M}  ·  by {e(user)}  ·  watched: {e(', '.join(own))}</p>")
    lab, c, soft = LEVELS[worst]
    h.append(f"<div class='banner' style='background:{soft if worst != 'clean' else '#fff'}'><div class='bar' style='background:{c}'></div>"
             f"<div><h2>{e(title)}</h2><div class='sub'>{len(results)} registered lookalike(s) in total</div></div></div>")
    for p in problems:
        h.append(f"<div class='note' style='background:#fff5e0;color:#8a5a00'>{e(p)}</div>")
    sid, bid = "w1", "w2"
    h.append("<div class='quick'><b>Quick copy</b>"
             f"<button class='btn main' onclick=\"copyText('{sid}',this)\">Ticket summary</button>"
             + (f"<button class='btn' onclick=\"copyText('{bid}',this)\">Domains to block ({len(blk)})</button>" if blk else "")
             + "<span class='found' style='margin:0 0 0 auto'>Block these in Defender's Tenant Allow/Block List and "
               "add them to anti-phishing impersonation protection.</span></div>")
    if blk:
        h.append(f"<div class='box'><h3>Domains to block<button class='btn' onclick=\"copyText('{bid}',this)\">Copy</button></h3>"
                 f"<pre id='{bid}'>{e(chr(10).join(blk))}</pre></div>")
    h.append("<h2 class='sec'>Registered lookalikes</h2>")
    for r in results:
        lab_, c_, soft_ = col[r["level"]]
        lab_ = "PROBABLY OURS" if r.get("ours") else ("PARKED" if r["level"] == engine.INFO else lab_)
        extra = []
        if r.get("created"):
            extra.append(f"Registered {e(r['created'])}")
        if r["mx"]:
            extra.append("Mail servers: " + e(", ".join(r["mx"][:3])))
        if r["a"]:
            extra.append("Web address: " + e(", ".join(r["a"][:3])))
        if r["ns"]:
            extra.append("Name servers: " + e(", ".join(r["ns"][:2])))
        h.append(f"<div class='card' style='border-left-color:{c_}'><div class='row'>"
                 f"<span class='pill' style='background:{soft_};color:{c_}'>{lab_}</span>"
                 f"<span class='url mono'>{e(r['domain'].replace('.', '[.]'))}</span></div>"
                 f"<div class='found'>Imitates {e(r['imitates'])}  ·  {e(r['technique'])}</div>"
                 f"<ul class='f'><li style='--c:{c_}'>{e(r['why'])}</li>"
                 + "".join(f"<li style='--c:#9aa6b5'>{x}</li>" for x in extra) + "</ul></div>")
    if not results and not problems:
        h.append("<div class='note' style='background:#e8f6ee;color:#21875a'>No registered lookalikes of the watched domains.</div>")
    h.append(f"<h2 class='sec'>For the ticket</h2><details class='box'><summary>Ticket summary (text)</summary>"
             f"<pre id='{sid}'>{e(domain_watch.summary_text(results, own, when))}</pre></details>")
    h.append("</main><footer>" + (e(org) + "  ·  " if org else "") + "Email Analyzer  ·  Run this monthly; new lookalikes appear all the time.</footer></body></html>")
    return "".join(h)
