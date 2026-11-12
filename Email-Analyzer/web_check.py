"""
HTML and SVG: fake login pages sent as attachments, HTML smuggling (building a
malicious file inside the browser), scrambled script, hidden redirects, SVG pictures
that carry code. Also used for email bodies (attachment=False).
"""
import base64
import io
import re
from html import unescape

import inspectors
import qr_check as E

HIGH, MED, INFO = E.HIGH, E.MED, E.INFO

BRAND_WORDS = ("microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint", "excel online",
               "adobe", "docusign", "dhl", "maersk", "eurobank", "piraeus", "alpha bank", "nbg", "national bank",
               "wetransfer", "dropbox", "google", "sign in", "log in", "login", "verify your")


def _text(blob):
    for enc in ("utf-8", "utf-16"):
        try:
            return blob.decode(enc)
        except UnicodeDecodeError:
            continue
    return blob.decode("latin-1", "ignore")


def decode_layers(html, rounds=3):
    """Undo the usual wrapping: unescape('%3c...'), atob('PGh0...'), decodeURIComponent. Returns all layers."""
    layers = [html]
    cur = html
    for _ in range(rounds):
        found = []
        for m in re.findall(r"""(?:atob|base64_decode)\s*\(\s*['"]([A-Za-z0-9+/=\s]{40,})['"]""", cur):
            try:
                found.append(base64.b64decode(re.sub(r"\s", "", m) + "==="[: (-len(m)) % 4]).decode("utf-8", "ignore"))
            except Exception:
                pass
        for m in re.findall(r"""(?:unescape|decodeURIComponent|decodeURI)\s*\(\s*['"]((?:%[0-9a-fA-F]{2}|[^'"]){20,})['"]""", cur):
            try:
                from urllib.parse import unquote
                found.append(unquote(m))
            except Exception:
                pass
        if not found:
            break
        cur = "\n".join(found)
        layers.append(cur)
    return layers


def inspect(name, blob, where, depth, ctx, svg=False, attachment=True):
    raw = _text(blob)
    layers = decode_layers(raw)
    allhtml = "\n".join(layers)
    low = allhtml.lower()
    what = "SVG picture" if svg else ("web page" if attachment else "email")
    scrambled = len(layers) > 1

    # ---------- links in every layer
    seen = set()

    def add(u, how):
        u = unescape(u.strip())
        if not u or u in seen or u.startswith(("#", "mailto:", "cid:", "about:")) or len(u) > 4000:
            return
        if u.lower().startswith("javascript:"):
            return
        if inspectors.is_schema(u):
            return
        seen.add(u)
        ctx.items.append((u, f"{where}{how}"))

    file_msgs = set()
    for m in re.finditer(r"""<a\b[^>]*?\bhref\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>""", allhtml, re.I | re.S):
        href, label = m.group(1), re.sub(r"<[^>]+>", "", m.group(2))
        add(href, "link in " + what + (f" (shows '{E.visible(unescape(label).strip()[:60])}')" if label.strip() else ""))
        label_domain = _domain_in(unescape(label))
        real = real_destination(href)          # through Safe Links / Proofpoint / Barracuda rewriting
        href_domain = _host(real)
        if label_domain and href_domain and not _same_site(label_domain, href_domain):
            ctx.notes.append((HIGH, f"{where}a link shows '{E.visible(label_domain)}' but really goes to "
                                    f"'{E.visible(href_domain)}'. Classic phishing trick."))
        msg = file_label_mismatch(unescape(label), real)
        if msg and msg not in file_msgs:
            file_msgs.add(msg)
            ctx.notes.append((MED, f"{where}{msg}"))
    for m in re.finditer(r"""<(?:iframe|frame|embed|script|img|link|object)\b[^>]*?\b(?:src|data|href)\s*=\s*["']?(https?://[^"'\s>]+)""", allhtml, re.I):
        add(m.group(1), f"resource loaded by the {what}")
    for m in re.finditer(r"""<form\b[^>]*?\baction\s*=\s*["']?([^"'\s>]+)""", allhtml, re.I):
        add(m.group(1), f"form in the {what} sends typed data here")
    for m in re.finditer(r"""http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)""", allhtml, re.I):
        add(m.group(1), f"automatic redirect in the {what}")
    for m in re.finditer(r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["'`](https?://[^"'`]+)""", allhtml, re.I):
        add(m.group(1), f"script redirect in the {what}")
    for m in re.finditer(r"""(?:fetch|open|post|ajax|\$\.post|XMLHttpRequest[^;]*open)\s*\(\s*["'`](?:POST["'`]\s*,\s*["'`])?(https?://[^"'`]+)""", allhtml, re.I):
        add(m.group(1), f"script in the {what} sends data here")
    if attachment:   # email bodies: the anchors above already give the real links
        for u in E.URL_IN_TEXT_RE.findall(allhtml):
            add(u.rstrip(".,;)'\""), f"address in the {what}")

    # ---------- QR codes in inline pictures
    for m in re.finditer(r"data:image/(?:png|jpe?g|gif|bmp|webp);base64,([A-Za-z0-9+/=]{100,})", allhtml):
        try:
            from PIL import Image
            data = base64.b64decode(m.group(1))
            if not ctx.take(len(data)):
                break
            img = Image.open(io.BytesIO(data))
            img.load()
            for t, fmt in E.decode_qr(img, heavy=True):
                ctx.items.append((t, f"{where}{fmt} in a picture inside the {what}"))
        except Exception:
            pass

    if not attachment:
        return   # email bodies: links and QR codes only; the email checks judge the rest

    # ---------- red flags for attached pages / pictures
    has_password = re.search(r"""<input\b[^>]*type\s*=\s*["']?password""", low) is not None
    brand = next((b for b in BRAND_WORDS if b in low), None)
    if has_password:
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} is a login page sent as a file"
                                + (f" (it mentions '{brand}')" if brand else "")
                                + ". Real companies never email you a page to type your password into."))
    smuggle_blob = re.search(r"new\s+blob\s*\(|createobjecturl|mssaveoropenblob|navigator\.mssaveblob", low)
    big_b64 = re.search(r"[A-Za-z0-9+/]{20000,}={0,2}", allhtml)
    if smuggle_blob and (big_b64 or "atob(" in low or "download" in low):
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} builds a file inside your browser and downloads it (HTML smuggling). "
                                "This is how malware gets past email scanners."))
    elif re.search(r"data:application/(?:octet-stream|x-msdownload|zip|x-zip|vnd\.ms|x-iso)", low):
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} carries a hidden file to download."))
    if scrambled or re.search(r"\beval\s*\(|string\.fromcharcode\s*\(|document\.write\s*\(\s*(unescape|atob)", low):
        ctx.notes.append((MED if not has_password else HIGH,
                          f"{inspectors.subj(where, name)} contains scrambled script that hides what the page really does."))
    if re.search(r"""value\s*=\s*["'][^"'@\s]+@[^"'\s]+\.[a-z]{2,}["']""", low) or re.search(r"#[A-Za-z0-9+/=]{12,}\s*$", raw.strip()):
        ctx.notes.append((MED, f"{inspectors.subj(where, name)} has the recipient's email address filled in, a sign of a targeted lure."))
    if svg:
        if re.search(r"<script\b|\bon(load|click|mouseover|error|begin|end)\s*=", low):
            ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} is a picture that contains program code. Opening it in a "
                                    "browser can redirect you to a phishing page (SVG phishing)."))
        if "<foreignobject" in low:
            ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} is a picture with a hidden web page inside it."))
    elif not has_password and attachment and seen:
        ctx.notes.append((MED, f"{inspectors.subj(where, name)} is a web page sent as a file. Opening it runs in your browser; "
                               "businesses rarely send these."))


def real_destination(url):
    """The address behind email-gateway rewriting (Safe Links etc.), or the address itself."""
    url = unescape(url.strip())
    for _ in range(3):
        inner, _name = E.unwrap(url)
        if not inner:
            break
        url = inner
    return url


FILE_LABEL_RE = re.compile(r"[\w)\]]\.(pdf|docx?|docm|xlsx?|xlsm|pptx?|zip|rar|7z|csv|rtf)\s*$", re.I)


def file_label_mismatch(label, real_url):
    """Link text that names a document ('Quote.pdf') but opens a web page somewhere else.
    Not flagged: the link really ends in that file type, or goes to a file-sharing service
    (those get their own warning)."""
    label = re.sub(r"\s+", " ", label).strip()
    m = FILE_LABEL_RE.search(label)
    host = _host(real_url)
    if not m or not host:
        return None
    path = (E.safe_split(real_url)[0].path or "").lower()
    if path.endswith("." + m.group(1).lower()):
        return None
    if any(host == d or host.endswith("." + d) for d in E.FILE_SHARE):
        return None
    return (f"a link is labelled as a file ('{E.visible(label[-60:])}') but opens a web page on "
            f"'{E.visible(host)}', not that file. Fake 'shared document' links work this way.")


def _host(url):
    url = unescape(url.strip())
    if not re.match(r"(?i)https?://", url):
        return None
    parts, _ = E.safe_split(url)
    return (parts.hostname or "").lower() or None


def _domain_in(label):
    label = label.strip()
    m = re.match(r"(?i)^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)", label)
    if not m:
        return None
    dom = m.group(1).lower()
    if label.lower().startswith(("http://", "https://")):
        return dom
    # link text like "DA.pdf" or "report.zip" is a file name, not a website
    suffix = E.EXTRACT(dom).suffix
    if not suffix or dom.rsplit(".", 1)[-1] in E.FILE_EXT_TLDS:
        return None
    return dom


def _same_site(a, b):
    _, ra = E.host_info(a)
    _, rb = E.host_info(b)
    return ra == rb
