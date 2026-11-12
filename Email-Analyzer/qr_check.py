#!/usr/bin/env python3
"""
Email Analyzer engine
Decodes QR codes (and links) inside PDFs or images WITHOUT opening them,
then checks where they point:
  - real domain vs your list of known bank / brand domains (banks.txt)
  - lookalike domains (eur0bank.gr, piraeusbank-secure.com, punycode)
  - URL shorteners and commonly abused free hosting
  - victim email address hidden in the link (plain or base64)
  - domain age via RDAP (does not touch the target site)
  - VirusTotal domain reputation (optional, does not touch the target site)
  - urlscan.io PRIVATE scan with screenshot and final landing page (optional,
    this one DOES visit the link, from urlscan's servers, with emails redacted)

Nothing is sent to the internet unless you opt in:
  --lookups   domain age (rdap.org) and VirusTotal: only the DOMAIN NAME is sent
  --live      urlscan.io visits the link from ITS servers (emails redacted)

Usage:  python qr_check.py file.eml [more files] [--lookups] [--live] [--password X]
        python qr_check.py --paste        (paste an email, then Ctrl+Z Enter / Ctrl+D)
"""
import argparse
import base64
import difflib
import io
import ipaddress
import json
import os
import re
import contextlib
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import pymupdf
import requests
import tldextract
import zxingcpp
from PIL import Image, ImageFilter, ImageOps

HERE = Path(__file__).resolve().parent
# Bundled public suffix list, no network needed
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "qrco.de", "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "rb.gy",
    "tiny.cc", "s.id", "lnkd.in", "v.gd", "shorturl.gg", "qr.link", "l.ead.me",
    "linktr.ee", "short.gy", "bl.ink", "urlz.fr", "y2u.be", "me-qr.com",
    "qr-codes.io", "qrfy.io", "u.to",
}
ABUSED_HOSTING = {
    "workers.dev", "pages.dev", "web.app", "firebaseapp.com", "netlify.app",
    "vercel.app", "github.io", "glitch.me", "ngrok-free.app", "ngrok.io",
    "blob.core.windows.net", "web.core.windows.net", "azurewebsites.net",
    "r2.dev", "storage.googleapis.com", "appspot.com", "weebly.com",
    "wixsite.com", "square.site", "godaddysites.com", "webflow.io",
    "herokuapp.com", "onrender.com", "replit.app", "framer.app",
    "ipfs.io", "dweb.link", "canva.site", "notion.site",
}
KNOWN_SHARE_LINKS = {"maps.app.goo.gl": "a Google Maps share link", "youtu.be": "a YouTube short link",
                     "wa.me": "a WhatsApp chat link"}
FILE_SHARE = {"sharepoint.com", "my.sharepoint.com", "onedrive.com", "docs.google.com", "drive.google.com",
              "dropbox.com", "box.com", "wetransfer.com", "1drv.ms", "onedrive.live.com"}
RISKY_TLDS = {"top", "xyz", "icu", "cfd", "sbs", "click", "buzz", "rest",
              "monster", "quest", "zip", "mov", "lol", "cyou", "bond",
              "ru", "su", "tk", "ml", "ga", "cf", "gq"}
# cheap endings that phishing uses a lot, but so do many real shops and events: weak signal only
CHEAP_TLDS = {"shop", "online", "site", "store", "live", "link"}

EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}(?![A-Za-z0-9-])")
MAX_LINK = 8000   # the largest QR code holds about 7,000 characters
URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
DUMMY_EMAIL = "test.user@example.com"

HIGH, MED, LOW, INFO, GOOD = "HIGH", "MEDIUM", "LOW", "INFO", "GOOD"

# ------------------------------------------------------------ risk score
# Every finding adds points; the total decides the verdict. One weak signal (LOW) is never
# enough on its own, several together are. Change the numbers here and nowhere else.
WEIGHTS = {HIGH: 70, MED: 25, LOW: 10}
DANGER_AT = 70        # score from which the verdict is DANGEROUS (one HIGH is enough)
SUSPICIOUS_AT = 25    # score from which the verdict is SUSPICIOUS (one MEDIUM, or three LOW)


def score_findings(findings):
    """findings: [(level, message)]. Returns (score 0-100, [(points, level, message)]).
    The same message is only counted once."""
    seen, parts, total = set(), [], 0
    for lv, m in findings:
        pts = WEIGHTS.get(lv, 0)
        if not pts or m in seen:
            continue
        seen.add(m)
        parts.append((pts, lv, m))
        total += pts
    return min(100, total), parts


# -------------------------------------------------------- network policy
# OFF by default. "lookups": rdap.org domain age + VirusTotal (only the domain name leaves the PC).
# "live": urlscan.io (their servers visit the link). Every web request in this tool goes through _http().
_NET = {"lookups": False, "live": False}


class NetworkOff(Exception):
    pass


def set_network(lookups=False, live=False):
    _NET["lookups"], _NET["live"] = bool(lookups), bool(live)


def network_allowed(kind):
    return bool(_NET.get(kind))


@contextlib.contextmanager
def network(lookups=False, live=False):
    """Temporarily allow online checks (used by Domain watch, which is an online tool by nature)."""
    old = dict(_NET)
    set_network(lookups, live)
    try:
        yield
    finally:
        _NET.update(old)


def _http(kind, method, url, **kw):
    if not network_allowed(kind):
        raise NetworkOff(f"{kind} is switched off")
    return requests.request(method, url, **kw)


import unicodedata


def visible(text, one_line=True):
    """Show hidden characters instead of obeying them: terminal escapes, right-to-left overrides,
    zero-width spaces. Attacker-supplied text must never be able to restyle or reorder the display."""
    out_chars = []
    for ch in str(text):
        if ch == "\n":
            out_chars.append("  |  " if one_line else ch)
        elif ch == "\t":
            out_chars.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf") or ch in ("\u2028", "\u2029"):
            out_chars.append(f"<U+{ord(ch):04X}>")
        else:
            out_chars.append(ch)
    return "".join(out_chars)


# ----------------------------------------------------------------- config
def load_keys():
    keys = {}
    f = HERE / "keys.txt"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip()
    for k in ("URLSCAN_API_KEY", "VT_API_KEY"):
        if os.environ.get(k):
            keys[k] = os.environ[k]
    return {k: v for k, v in keys.items() if v}


def load_brands():
    """banks.txt:  Name | domain1, domain2 | keyword1, keyword2"""
    brands = []
    import appconfig
    lines = appconfig.brand_list_text(HERE / "banks.txt").splitlines()   # shared list if one is set
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            continue
        name = parts[0]
        domains = [d.strip().lower() for d in parts[1].split(",") if d.strip()]
        kws = [k.strip().lower() for k in parts[2].split(",")] if len(parts) > 2 else []
        kws = [k for k in kws if k]
        brands.append({"name": name, "domains": domains, "keywords": kws})
    # domains on the lookalike watch list are ours: senders and links imitating them get flagged
    try:
        import domain_watch
        own = domain_watch.load_watch_list(HERE / "watch_domains.txt")
    except Exception:
        own = []
    if own:
        ours = next((b for b in brands if b["name"].lower() in ("our company", "own company")), None)
        if ours is None:
            ours = {"name": "Our company", "domains": [], "keywords": []}
            brands.append(ours)
        for d in own:
            if d not in ours["domains"]:
                ours["domains"].append(d)
            label = EXTRACT(d).domain
            if len(label) >= 5 and label not in ours["keywords"]:
                ours["keywords"].append(label)
    return brands


# ------------------------------------------------------------ extraction
MAX_PIXELS = 45_000_000  # protects against giant pages / images


_F = zxingcpp.BarcodeFormat
# 2D codes only: skipping shop-style 1D barcodes makes scanning much faster
QR_FORMATS = (_F.QRCode, _F.MicroQRCode, _F.RMQRCode, _F.DataMatrix, _F.Aztec, _F.PDF417)
_FORMAT_ARG = None


def _read(img):
    """zxing-cpp 3.x takes a tuple of formats, 2.x the formats OR-ed together; work with both."""
    global _FORMAT_ARG
    if _FORMAT_ARG is None:
        try:
            zxingcpp.read_barcodes(Image.new("L", (8, 8), 255), formats=QR_FORMATS)
            _FORMAT_ARG = QR_FORMATS
        except TypeError:
            combined = QR_FORMATS[0]
            for f in QR_FORMATS[1:]:
                combined = combined | f
            _FORMAT_ARG = combined
    return zxingcpp.read_barcodes(img, formats=_FORMAT_ARG)


def decode_qr(img, heavy=False, light=False):
    """Plain image and its inverse. heavy: cleaned-up versions that rescue dotted,
    blurred or low-contrast codes. light: plain image only."""
    found = []
    img = img.convert("RGB")
    if img.width * img.height > MAX_PIXELS:
        scale = (MAX_PIXELS / (img.width * img.height)) ** 0.5
        img = img.resize((int(img.width * scale), int(img.height * scale)))
    if heavy:
        g = ImageOps.autocontrast(img.convert("L"))
        variants = [g.filter(ImageFilter.MinFilter(3)), g.filter(ImageFilter.GaussianBlur(2))]
    elif light:
        variants = [img]
    else:
        variants = [img, ImageOps.invert(img)]
    seen = set()
    for v in variants:
        try:
            for r in _read(v):
                if r.text and r.text not in seen:
                    seen.add(r.text)
                    found.append((r.text, str(r.format).split(".")[-1]))
        except Exception:
            pass
    return found


MAX_PAGES = 60
ACTION_KEYS = {"/JavaScript": "JavaScript", "/JS": "JavaScript", "/Launch": "Launch (runs a program)",
               "/SubmitForm": "SubmitForm (sends typed data to a website)", "/ImportData": "ImportData",
               "/GoToR": "GoToR (opens another file)", "/GoToE": "GoToE (opens an embedded file)"}


ACTION_RE = re.compile(r"/(JavaScript|JS|Launch|SubmitForm|ImportData|GoToR|GoToE)\b")


def scan_pdf_actions(doc, prefix, items, notes):
    """Look inside the PDF's internal objects for scripts and automatic actions."""
    kinds = set()
    try:
        cat = doc.pdf_catalog()
        open_action = doc.xref_get_key(cat, "OpenAction")[1] if cat else ""
    except Exception:
        open_action = ""
    for xref in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(xref, compressed=False)
        except Exception:
            continue
        hit = sorted({ACTION_KEYS["/" + m] for m in ACTION_RE.findall(obj)})
        text = obj
        if doc.xref_is_stream(xref) and ("/JavaScript" in obj or "/JS" in obj or hit):
            try:
                text += doc.xref_stream(xref).decode("latin-1", "ignore")
            except Exception:
                pass
        if "/JS" in obj:
            # JS stored as a separate stream object
            m = re.search(r"/JS\s+(\d+)\s+0\s+R", obj)
            if m:
                try:
                    text += doc.xref_stream(int(m.group(1))).decode("latin-1", "ignore")
                except Exception:
                    pass
        kinds.update(hit)
        if hit or "/URI" in obj:
            auto = (f"{xref} 0 R" in open_action) or "/AA" in obj
            for u in URL_IN_TEXT_RE.findall(text.replace("\\/", "/")):
                u = u.rstrip(").,;'\\")
                where = f"{prefix}PDF {'automatic ' if auto else ''}{'/'.join(hit) or 'link'} action"
                items.append((u, where))
    if kinds:
        lvl = HIGH if ({"Launch (runs a program)", "JavaScript"} & kinds) else MED
        notes.append((lvl, f"{prefix}PDF contains hidden actions: {', '.join(sorted(kinds))}. "
                           "Normal invoices and statements do not need these."))


def extract_from_pdf(path, password=None, data=None, prefix="", depth=0, notes=None, ctx=None):
    items = []
    notes = notes if notes is not None else []
    try:
        doc = pymupdf.open(stream=data, filetype="pdf") if data else pymupdf.open(path)
    except Exception:
        if depth:
            notes.append((MED, f"{prefix}hidden attachment is damaged and could not be opened."))
            return items, notes
        raise RuntimeError("This file could not be opened as a PDF. It may be damaged, or not really a PDF. "
                           "Damaged files are a known trick to slip past scanners, so treat it as suspicious.")
    if doc.needs_pass and password and doc.authenticate(password):
        notes.append((HIGH, f"{prefix}PDF was password-protected (unlocked with the supplied password). "
                            "Locking a PDF is a common trick to get it past email scanners."))
    elif doc.needs_pass and not doc.authenticate(""):
        if depth:
            notes.append((HIGH, f"{prefix}hidden attachment is password-protected and could not be checked."))
            return items, notes
        raise RuntimeError("PDF is password-protected. That alone is a common "
                           "trick to get past email scanners. Treat as suspicious. "
                           "If the email gives the password, run again with --password <pw>.")
    if doc.is_repaired or doc.page_count == 0:
        notes.append((MED, f"{prefix}PDF is damaged or malformed"
                           f"{' and has no readable pages' if doc.page_count == 0 else ''}. "
                           "Some viewers still show content the checker cannot read. Treat as suspicious."))
    if doc.page_count > MAX_PAGES:
        notes.append((MED, f"{prefix}PDF has {doc.page_count} pages; only the first {MAX_PAGES} were checked."))

    jobs = []   # (tag, image, mode, label)
    for pno, page in enumerate(doc, 1):
        if pno > MAX_PAGES:
            break
        tag = f"{prefix}page {pno}"
        try:
            area = page.rect.width * page.rect.height
            for dpi, mode in ((150, "normal"), (100, "heavy"), (300, "light")):
                if area * (dpi / 72) ** 2 > MAX_PIXELS:
                    dpi = int(72 * (MAX_PIXELS / area) ** 0.5)
                pix = page.get_pixmap(dpi=dpi)  # includes annotations
                jobs.append((tag, Image.frombytes("RGB", (pix.width, pix.height), pix.samples), mode, "rendered page"))
        except Exception as e:
            notes.append((INFO, f"{tag}: could not render ({e.__class__.__name__})."))
        for info in page.get_images(full=True):
            try:
                pix = pymupdf.Pixmap(doc, info[0])
                if pix.width * pix.height > MAX_PIXELS or pix.width < 20 or pix.height < 20:
                    continue
                if pix.n - pix.alpha >= 4:
                    pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                jobs.append((tag, Image.open(io.BytesIO(pix.tobytes("png"))), "normal", "embedded image"))
            except Exception:
                pass
        try:
            for link in page.get_links():
                if link.get("uri"):
                    items.append((link["uri"], f"{tag}: clickable link"))
            for m in URL_IN_TEXT_RE.findall(page.get_text()):
                items.append((m.rstrip(".,;"), f"{tag}: URL written in text"))
        except Exception:
            pass
        try:
            for a in page.annots(types=[pymupdf.PDF_ANNOT_FILE_ATTACHMENT]):
                info = a.file_info
                handle_attachment(info.get("filename", "file"), a.get_file(), tag, depth, items, notes, ctx, prefix)
        except Exception:
            pass

    def run(job):
        tag, img, mode, label = job
        return [(text, f"{tag}: {fmt} ({label})")
                for text, fmt in decode_qr(img, heavy=mode == "heavy", light=mode == "light")]
    with ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 2))) as ex:
        for res in ex.map(run, jobs):
            items.extend(res)

    scan_pdf_actions(doc, prefix, items, notes)

    # files attached to the PDF as a whole (paperclip panel)
    for name in doc.embfile_names():
        try:
            handle_attachment(name, doc.embfile_get(name), prefix.rstrip(" >") or "PDF", depth, items, notes, ctx, prefix)
        except Exception:
            notes.append((MED, f"{prefix}could not open attached file '{name}'."))
    return items, notes


def handle_attachment(name, blob, where, depth, items, notes, ctx=None, prefix=""):
    notes.append((MED, f"{where}: contains a hidden attached file '{visible(name)}'. "
                       "Attackers hide the real lure inside attachments of attachments."))
    if depth >= 3 or not blob:
        return
    pre = f"{prefix}attachment '{visible(name)}' > "
    if ctx is not None:   # full inspection: Office, HTML, archives, emails, PDFs, pictures
        import inspectors
        inspectors.analyze(name, blob, pre, depth + 1, ctx)
        return
    if blob[:5] == b"%PDF-":
        sub, _ = extract_from_pdf(None, data=blob, prefix=pre, depth=depth + 1, notes=notes)
        items.extend(sub)
    else:
        try:
            img = Image.open(io.BytesIO(blob))
            for text, fmt in decode_qr(img, heavy=True):
                items.append((text, f"{pre}{fmt} (image)"))
        except Exception:
            pass


def extract_from_image(path):
    try:
        img = Image.open(path)
        img.load()
    except Exception:
        raise RuntimeError("This file could not be opened as a picture. It may be damaged or not really an image.")
    return [(t, f"image: {fmt}") for t, fmt in decode_qr(img, heavy=True)], []


def collect(path, password=None, pasted=False):
    """pasted=True: the file holds email text pasted by the user (with or without headers)."""
    import inspectors
    raw, notes = inspectors.collect_file(path, password, pasted=pasted)
    merged = {}
    for text, where in raw:
        merged.setdefault(text.strip(), [])
        if where not in merged[text.strip()]:
            merged[text.strip()].append(where)

    def first_page(item):  # show links in page order; attachments and hidden actions last
        pages = [int(m) for w in item[1] if not w.startswith("attachment")
                 for m in re.findall(r"^page (\d+)", w)]
        body = any(w.startswith("email") for w in item[1])
        return (min(pages) if pages else (0 if body else 10 ** 6), item[1][0])
    return dict(sorted(merged.items(), key=first_page)), notes


# --------------------------------------------------------------- checks
def normalise_url(text):
    t = text.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*:", t, re.I) and not t.lower().startswith(("http:", "https:")):
        return None  # mailto:, tel:, WIFI:, etc.
    if not t.lower().startswith(("http://", "https://")):
        if re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", t, re.I):
            return "http://" + t
        return None
    return t


def find_emails(url):
    """Return {email: [(kind, token, urlsafe)]} for plain or base64-hidden addresses."""
    hits = {}
    text = unquote(url)
    for e in EMAIL_RE.findall(text):
        for t in {e, quote(e, safe=""), quote(e)}:
            hits.setdefault(e, set()).add(("plain", t, False))
    for tok in set(re.findall(r"[A-Za-z0-9+/_-]{12,}={0,2}", text)):
        padded = tok + "=" * (-len(tok) % 4)
        for urlsafe, dec in ((False, base64.b64decode), (True, base64.urlsafe_b64decode)):
            try:
                s = dec(padded, validate=True).decode("utf-8") if not urlsafe else dec(padded).decode("utf-8")
            except Exception:
                continue
            found = EMAIL_RE.findall(s)
            for e in found:
                hits.setdefault(e, set()).add(("b64", tok, urlsafe))
            if found:
                break
    return {k: sorted(v, key=lambda x: len(x[1]), reverse=True) for k, v in hits.items()}


def redact(url, emails):
    """Swap the victim's address for a dummy, keeping the same encoding."""
    out = url
    for email, tokens in emails.items():
        for kind, tok, urlsafe in tokens:
            if kind == "plain":
                out = out.replace(tok, DUMMY_EMAIL)
                continue
            padded = tok + "=" * (-len(tok) % 4)
            dec = base64.urlsafe_b64decode if urlsafe else base64.b64decode
            if "+" not in tok and "/" not in tok:
                urlsafe = True  # keep the replacement URL-safe when the original allows it
            plain = dec(padded).decode("utf-8", "ignore").replace(email, DUMMY_EMAIL)
            enc = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(plain.encode()).decode()
            if not tok.endswith("="):
                enc = enc.rstrip("=")
            out = out.replace(tok, enc)
            out = out.replace(quote(tok, safe=""), quote(enc, safe=""))
    return out


def homoglyph_fold(s):
    s = s.lower()
    for a, b in (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
                 ("5", "s"), ("4", "a"), ("7", "t"), ("8", "b"), ("-", ""), ("_", "")):
        s = s.replace(a, b)
    return s.replace("i", "l")


def host_info(host):
    ext = EXTRACT(host)
    reg = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    return ext, (reg or host).lower()


def matched_brand_early(host, brands):
    return any(host == d or host.endswith("." + d) for b in brands for d in b["domains"])


CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "в": "b", "к": "k", "м": "m",
    "н": "h", "т": "t", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k",
    "ε": "e", "υ": "u", "χ": "x", "β": "b", "ɡ": "g", "ı": "i", "ℓ": "l", "ｏ": "o",
})
FILE_EXT_TLDS = {"zip", "mov", "md", "sh", "py", "pl", "rs", "ps", "cs", "ai", "doc", "pdf", "exe"}
REDIRECT_PATH_MARKERS = {"amp", "s", "url", "redirect", "r", "out", "go", "l", "link", "away",
                         "exit", "to", "click", "track", "redir", "forward"}


def safe_split(url):
    """urlsplit that never raises (it does on stray [ or ] in the host). Returns (parts, malformed)."""
    try:
        parts = urlsplit(url)
        parts.hostname  # can also raise
        return parts, False
    except ValueError:
        pass
    try:
        parts = urlsplit(url.replace("[", "%5B").replace("]", "%5D"))
        parts.hostname
        return parts, True
    except ValueError:
        return urlsplit(""), True


def numeric_ip(host):
    """Turn disguised IPs (3115156780, 0xb9.0xdc.0x65.0x2c, 0271.0.0.1) into dotted form."""
    if not host or not re.fullmatch(r"[0-9a-fx.]+", host, re.I) or "." in host and host.count(".") > 3:
        return None
    try:
        nums = []
        for part in host.split("."):
            if part.lower().startswith("0x"):
                nums.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                nums.append(int(part, 8))
            else:
                nums.append(int(part))
    except ValueError:
        return None
    if len(nums) == 1:
        val = nums[0]
    else:
        val = 0
        for i, n in enumerate(nums[:-1]):
            if n > 255:
                return None
            val |= n << (24 - 8 * i)
        if nums[-1] >= 1 << (8 * (5 - len(nums))):
            return None
        val |= nums[-1]
    if val > 0xFFFFFFFF:
        return None
    return str(ipaddress.IPv4Address(val))


def browser_parse(url):
    """Read the link the way a phone browser does, not the way it looks."""
    notes = []
    raw = url.strip()
    u = re.sub(r"[\t\r\n]", "", raw)
    head = re.split(r"[?#]", u, maxsplit=1)[0]
    if "\\" in head:
        u = head.replace("\\", "/") + u[len(head):]
        notes.append("backslash")
    parts, malformed = safe_split(u)
    if malformed:
        notes.append("malformed")
    host = (parts.hostname or "").rstrip(".")
    uni = None
    if any(ord(ch) > 127 for ch in host):
        uni = host
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass
    return u, parts, host.lower(), notes, uni


def nested_urls(url):
    """Addresses hidden inside a link: open redirects, base64 or double-encoded targets."""
    parts, _ = safe_split(url.replace("\\", "/"))
    out = []
    for blob in (parts.query, parts.fragment, parts.path):
        txt = blob or ""
        for _ in range(5):
            nxt = unquote(txt)
            if nxt == txt:
                break
            txt = nxt
        candidates = [txt]
        for tok in re.findall(r"[A-Za-z0-9+/_-]{12,}={0,2}", txt):
            for t in (tok, tok[2:]):  # some trackers prefix the base64 (e.g. 'a1')
                try:
                    dec = base64.urlsafe_b64decode(t.replace("+", "-").replace("/", "_").rstrip("=")
                                                   + "=" * (-len(t.rstrip("=")) % 4)).decode("utf-8")
                except Exception:
                    continue
                if dec.isprintable():
                    candidates.append(unquote(dec))
        for c in candidates:
            for m in re.findall(r"https?://[^\s&#\"'<>]+", c, re.I):
                if m != url:
                    out.append(m)
            for m in re.findall(r"(?:^|[=&?])(?:url|u|q|redirect|redirect_uri|target|dest|next|link|goto|to|d)="
                                r"((?:www\.)?[a-z0-9-]+\.[a-z]{2,}[^\s&#]*)", c, re.I):
                if "@" in m.split("/")[0]:
                    continue   # ?u=name@company.com is an email address, not a hidden website
                out.append("http://" + m)
    segs = [x for x in parts.path.split("/") if x]
    for i, seg in enumerate(segs):
        if (i and segs[i - 1].lower() in REDIRECT_PATH_MARKERS) or seg.lower().startswith("www."):
            ext = EXTRACT(seg)
            if ext.suffix and ext.domain and ext.suffix.split(".")[-1] not in FILE_EXT_TLDS:
                out.append("https://" + "/".join(segs[i:]))
                break
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def classify_payload(text):
    """QR codes that are not web addresses can still be dangerous."""
    t, low, f = text.strip(), text.strip().lower(), []
    urls = URL_IN_TEXT_RE.findall(t)
    if low.startswith("data:"):
        f.append((HIGH, "QR holds a whole web page (data: link) instead of a website address. "
                        "There is no site to look up, which is exactly why attackers use it."))
        m = re.match(r"data:[^,]*?(;base64)?,(.*)", t, re.I | re.S)
        if m:
            body = m.group(2)
            try:
                body = (base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "ignore")
                        if m.group(1) else unquote(body))
            except Exception:
                pass
            urls += URL_IN_TEXT_RE.findall(body)
            if re.search(r"<form|password|<script|<iframe", body, re.I):
                f.append((HIGH, "The hidden page contains a form or script, typical of a credential grab."))
    elif low.startswith(("javascript:", "vbscript:")):
        f.append((HIGH, "QR contains script code, not an address."))
    elif low.startswith("wifi:"):
        m = re.search(r"S:((?:\\;|[^;])*)", t)
        f.append((MED, f"QR joins the phone to a Wi-Fi network '{m.group(1) if m else '?'}'. A fake network "
                       "can watch or redirect traffic. Only join networks ICT has announced."))
    elif low.startswith(("begin:vcard", "mecard:")):
        f.append((INFO, "QR adds a contact card to the phone"
                  + (". The web link inside it is checked separately below." if urls else ".")))
    elif low.startswith(("smsto:", "sms:")):
        target = re.split(r"[:;?]", t, maxsplit=2)[1] if ":" in t else "?"
        f.append((MED, f"QR prepares a text message to {target}. Premium-rate and scam numbers use this. "
                       "Check the number is genuine before sending."))
    elif low.startswith(("tel:", "mailto:", "matmsg:")):
        target = re.split(r"[:;?]", t, maxsplit=2)[1] if ":" in t else "?"
        f.append((INFO, f"QR starts a call or email to {target}. Check it is genuine."))
    elif low.startswith(("intent:", "market:", "itms-services:", "itms-apps:")):
        f.append((HIGH, "QR tries to open or install an app on the phone."))
    else:
        f.append((INFO, "QR contains plain text, not a link."))
    return f, list(dict.fromkeys(urls))


def domain_checks(url, brands):
    """Checks that never contact the target. Returns (findings, registered_domain)."""
    f = []
    url, parts, host, notes, uni = browser_parse(url)
    if not host:
        return [(MED, "Could not read a website name from this link. Malformed links are a trick to confuse "
                      "scanners; treat it as suspicious.")], None
    if "malformed" in notes:
        f.append((MED, "Link is malformed (stray [ or ] in the address). Browsers may read it differently "
                       "from scanners; treat it as suspicious."))

    hidden = sorted({f"U+{ord(ch):04X}" for ch in url if unicodedata.category(ch) == "Cf"})
    if hidden:
        f.append((HIGH, f"Link contains invisible characters ({', '.join(hidden)}). They are used to make an "
                        "address look different from where it really goes."))

    if "backslash" in notes:
        f.append((HIGH, f"Link contains a backslash. Phones and browsers treat it as '/', so it really "
                        f"goes to {host}, whatever the rest of the address seems to say."))

    if "@" in parts.netloc:
        fake = parts.netloc.rsplit("@", 1)[0]
        f.append((HIGH, f"Link uses the user@host trick: the browser ignores '{fake}' and really goes to {host}."))

    ip = numeric_ip(host)
    if ip and ip != host:
        f.append((HIGH, f"'{host}' is an IP address in disguise. It really means {ip}."))
    try:
        ipaddress.ip_address(ip or host)
        f.append((HIGH, f"Link goes to a raw IP address ({ip or host}), not a domain. Banks never do this."))
        return f, ip or host
    except ValueError:
        pass

    if uni:
        folded = uni.translate(CONFUSABLES)
        _, freg = host_info(folded)
        fake_of = [b["name"] for b in brands if freg in b["domains"]]
        f.append((HIGH, f"Domain uses foreign letters that look like normal ones: it shows as '{uni}' "
                        f"but is really '{host}'"
                        + (f", an imitation of {freg} ({fake_of[0]})." if fake_of else ".")))
    elif "xn--" in host:
        try:
            shown = host.encode().decode("idna")
        except Exception:
            shown = "?"
        f.append((HIGH, f"Punycode domain (looks like '{shown}'). Often used to fake a brand with lookalike letters."))

    ext, reg = host_info(host)
    label = ext.domain.lower()

    if parts.scheme == "http":
        f.append((LOW, "Plain http, not https. No real bank login page uses this."))

    if host in KNOWN_SHARE_LINKS:
        f.append((INFO, f"{host} is {KNOWN_SHARE_LINKS[host]}."))
    elif reg in SHORTENERS or host in SHORTENERS:
        f.append((MED, f"{reg} is a link shortener. The real destination is hidden; see the urlscan result for where it lands."))
    if any(host == d or host.endswith("." + d) for d in ABUSED_HOSTING):
        f.append((MED, f"Hosted on free/cheap web hosting ({host}). Common for phishing pages, never used by banks for login."))
    if any(host == d or host.endswith("." + d) for d in FILE_SHARE) and not matched_brand_early(host, brands):
        f.append((LOW, f"File-sharing link ({host}). Legit service, but often abused to host a fake login page "
                       "or form. Check who shared it before anyone signs in."))
    if ext.suffix.split(".")[-1] in RISKY_TLDS:
        f.append((MED, f"Domain ends in .{ext.suffix}, a TLD heavily used for throwaway phishing sites."))
    elif ext.suffix.split(".")[-1] in CHEAP_TLDS:
        f.append((LOW, f"Domain ends in .{ext.suffix}, a cheap ending used by many throwaway sites "
                       "(and by many real shops and events)."))
    prefix = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    if re.search(r"[a-z0-9-]+\.(com|net|org|gr|co\.uk|eu|io|gov|bank)(\.|$)", prefix):
        f.append((MED, f"Hostname is dressed up to look like '{prefix}', but the real site is {reg}."))
    if host.count(".") >= 4:
        f.append((INFO, f"Unusually deep subdomain chain ({host}). Often used to push the real domain out of view on a phone screen."))

    # most specific entry wins: "ourco-my.sharepoint.com" beats Microsoft's "sharepoint.com"
    matched_brand, best = None, -1
    for b in brands:
        for d in b["domains"]:
            if host == d or host.endswith("." + d) or reg == d:
                if len(d) > best:
                    matched_brand, best = b, len(d)

    user_content = any(host == d or host.endswith("." + d) for d in ABUSED_HOSTING | FILE_SHARE)
    # a specific tenant listed in banks.txt (e.g. yourcompany-my.sharepoint.com) is trusted
    own_tenant = matched_brand and any((host == d or host.endswith("." + d)) and d.count(".") > reg.count(".")
                                       for d in matched_brand["domains"])
    if matched_brand and user_content and not own_tenant:
        f.append((LOW, f"{host} belongs to {matched_brand['name']}, but anyone can host files or pages "
                       f"there, so the domain alone proves nothing. Check the screenshot and who shared it."))
    elif matched_brand:
        f.append((GOOD, f"Real domain {host if own_tenant else reg} matches your known list for {matched_brand['name']}."))
    else:
        path_q = unquote((parts.path or "") + "?" + (parts.query or "")).lower()
        for b in brands:
            # real brand domain used as a decoy prefix, e.g. alpha.gr.login-check.cfd
            decoy = [d for d in b["domains"] if (d + ".") in (host + ".") and not host.endswith(d)]
            if decoy:
                f.append((HIGH, f"Hostname starts with the real {b['name']} domain '{decoy[0]}' as a decoy, "
                                f"but the site is actually {reg}."))
                continue
            # brand name in the hostname but wrong real domain
            host_hit = [k for k in b["keywords"] if k and k in host]
            if host_hit:
                f.append((HIGH, f"Hostname contains '{host_hit[0]}' but the real domain is {reg}, "
                                f"not {', '.join(b['domains'])}. Classic fake {b['name']} page."))
                continue
            # brand word spelled with swapped characters inside a longer name, e.g. micros0ft-login.com
            # folded word by word, so two innocent words joined by a hyphen can never form a brand name
            bare = host[: -len(ext.suffix) - 1] if ext.suffix else host
            folded_host = "-".join(homoglyph_fold(t) for t in bare.split("-"))
            fold_hit = [k for k in b["keywords"] if len(k) >= 6 and "-" not in k and homoglyph_fold(k) in folded_host]
            if fold_hit:
                f.append((HIGH, f"Hostname contains a disguised spelling of '{fold_hit[0]}' (swapped characters), and the "
                                f"real domain is {reg}, not {', '.join(b['domains'][:4])}. Classic fake {b['name']} page."))
                continue
            # lookalike spelling of a known domain label
            for d in b["domains"]:
                dl = EXTRACT(d).domain.lower()
                if len(dl) >= 5 and label != dl:
                    if homoglyph_fold(label) == homoglyph_fold(dl):
                        f.append((HIGH, f"'{reg}' is a lookalike of {d} ({b['name']}) using swapped characters."))
                        break
                    if difflib.SequenceMatcher(None, label, dl).ratio() >= 0.8:
                        f.append((HIGH, f"'{reg}' is spelled very close to {d} ({b['name']}). Likely typosquat."))
                        break
            path_hit = [k for k in b["keywords"] if len(k) >= 4 and k in path_q]
            if path_hit:
                f.append((MED, f"Link path mentions '{path_hit[0]}' but the site is {reg}, not one of {b['name']}'s domains."))
    return f, reg


_RDAP_CACHE = {}


AGE_OFF = "not checked (online lookups are off)"


def rdap_age(reg):
    """(days, date) or (None, reason). Never touches the network unless online lookups are on."""
    if not network_allowed("lookups"):
        return None, AGE_OFF
    if reg not in _RDAP_CACHE:
        _RDAP_CACHE[reg] = _rdap_age(reg)
    return _RDAP_CACHE[reg]


def _rdap_age(reg):
    try:
        r = _http("lookups", "GET", f"https://rdap.org/domain/{reg}", timeout=6,
                  headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None, f"registry gave HTTP {r.status_code} (some ccTLDs such as .gr have no RDAP)"
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - dt).days, dt.date().isoformat()
        return None, "no registration date published"
    except Exception as e:
        return None, f"lookup failed ({e.__class__.__name__})"


_VT_CACHE = {}


def vt_domain(reg, key):
    if reg in _VT_CACHE:
        return _VT_CACHE[reg]
    _VT_CACHE[reg] = res = _vt_domain(reg, key)
    return res


def _vt_domain(reg, key):
    try:
        for attempt in range(5):
            r = _http("lookups", "GET", f"https://www.virustotal.com/api/v3/domains/{reg}",
                      headers={"x-apikey": key}, timeout=15)
            if r.status_code != 429:
                break
            print("  VirusTotal free limit is 4 lookups/minute, waiting 20s...")
            time.sleep(20)
        if r.status_code == 404:
            return {"note": "VirusTotal has never seen this domain"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        a = r.json()["data"]["attributes"]
        s = a.get("last_analysis_stats", {})
        return {"malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0), "reputation": a.get("reputation")}
    except Exception as e:
        return {"error": e.__class__.__name__}


def download_screenshot(url, key, path, tries=6):
    """Fetch the urlscan screenshot (works for private scans with the API key)."""
    for _ in range(tries):
        try:
            r = _http("live", "GET", url, headers={"API-Key": key}, timeout=20)
            if r.status_code == 200 and r.content[:8] == b"\x89PNG\r\n\x1a\n":
                Path(path).write_bytes(r.content)
                return str(path)
        except Exception:
            pass
        time.sleep(5)
    return None


def urlscan(url, key, wait=120, save_png=None):
    h = {"API-Key": key, "Content-Type": "application/json"}
    try:
        r = _http("live", "POST", "https://urlscan.io/api/v1/scan/", headers=h, timeout=20,
                  json={"url": url, "visibility": "private", "tags": ["qr-check"]})
    except Exception as e:
        return {"error": f"submit failed ({e.__class__.__name__})"}
    if r.status_code != 200:
        return {"error": f"submit failed HTTP {r.status_code}: {r.text[:200]}"}
    uuid = r.json()["uuid"]
    res = {"report": f"https://urlscan.io/result/{uuid}/",
           "screenshot": f"https://urlscan.io/screenshots/{uuid}.png"}
    time.sleep(12)
    end = time.time() + wait
    while time.time() < end:
        try:
            g = _http("live", "GET", f"https://urlscan.io/api/v1/result/{uuid}/", headers={"API-Key": key}, timeout=20)
        except NetworkOff:
            break
        except Exception:
            time.sleep(5)
            continue
        if g.status_code == 200:
            d = g.json()
            page = d.get("page", {})
            ov = d.get("verdicts", {}).get("overall", {})
            brands = [b.get("name", str(b)) if isinstance(b, dict) else str(b) for b in ov.get("brands", [])]
            res.update({"final_url": page.get("url"), "final_domain": page.get("apexDomain") or page.get("domain"),
                        "ip": page.get("ip"), "country": page.get("country"),
                        "malicious": ov.get("malicious"), "score": ov.get("score"), "brands": brands,
                        "title": page.get("title")})
            if save_png:
                res["screenshot_file"] = download_screenshot(res["screenshot"], key, save_png)
            return res
        time.sleep(5)
    res["error"] = "timed out waiting for result; open the report link later"
    return res


# --------------------------------------------------------------- report
def overall(findings):
    lv = {x[0] for x in findings}
    score, _ = score_findings(findings)
    if score >= DANGER_AT:
        return "LIKELY FAKE / MALICIOUS - do not open, report and block"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS - verify before anyone opens it"
    if score > 0:
        return "LOW RISK - minor flags only, not enough on their own. Judge it together with the rest of the email."
    if GOOD in lv:
        return ("Domain matches a known legitimate site. A compromised real site "
                "(watering hole) is not ruled out; check the urlscan verdict.")
    return "No red flags from these checks. That is not proof it is safe."


COL = {HIGH: "\033[91m", MED: "\033[93m", LOW: "\033[33m", GOOD: "\033[92m", INFO: "\033[96m", "END": "\033[0m", "B": "\033[1m"}


_TLS = threading.local()


def out(text=""):
    """Print, or collect into the current link's buffer when checks run in parallel."""
    buf = getattr(_TLS, "buf", None)
    if buf is not None:
        buf.append(text)
    else:
        print(text)


def p(level, msg):
    out(f"  {COL.get(level, '')}[{level}]{COL['END']} {visible(msg)}")


WRAPPERS = {
    "safelinks.protection.outlook.com": "Microsoft Safe Links",
    "urldefense.com": "Proofpoint URL Defense",
    "urldefense.proofpoint.com": "Proofpoint URL Defense",
    "linkprotect.cudasvc.com": "Barracuda Link Protection",
}


def unwrap(url):
    """Email security gateways rewrite links. Return (real_url, wrapper_name) or (None, None)."""
    try:
        parts, _ = safe_split(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None, None
    name = next((v for k, v in WRAPPERS.items() if host == k or host.endswith("." + k)), None)
    if not name:
        return None, None
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    inner = None
    if "safelinks" in host:
        inner = qs.get("url")
    elif host.endswith("cudasvc.com"):
        inner = qs.get("a")
    elif "/v3/__" in url:
        m = re.search(r"/v3/__(.+?)__;", url)
        inner = m.group(1) if m else None
    elif "/v2/url" in parts.path and qs.get("u"):
        inner = re.sub(r"-([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), qs["u"].replace("_", "/"))
    if inner and normalise_url(inner):
        return inner, name
    return None, None


def check_link(text, where, brands, keys, do_scan, do_redact, png_path=None):
    owner = getattr(_TLS, "buf", None) is None
    if owner:
        _TLS.buf = []
    try:
        return _check_link(text, where, brands, keys, do_scan, do_redact, png_path)
    except Exception as e:  # one hostile link must never stop the others being checked
        out(f"  [MEDIUM] This link could not be fully checked ({e.__class__.__name__}). Treat it as suspicious.")
        return {"raw": text, "found_in": where,
                "verdict": "SUSPICIOUS - verify before anyone opens it", "score": WEIGHTS[MED],
                "findings": [{"level": MED, "detail": f"This link could not be fully checked "
                                                       f"({e.__class__.__name__}). Treat it as suspicious."}]}
    finally:
        if owner:
            _TLS.last = "\n".join(_TLS.buf)
            _TLS.buf = None


def _check_link(text, where, brands, keys, do_scan, do_redact, png_path=None):
    rec = {"raw": text, "found_in": where, "findings": []}
    too_long = len(text) > MAX_LINK
    if too_long:   # larger than any real QR code: analyse the start, flag the rest
        rec["raw"] = text[:MAX_LINK]
        text = text[:MAX_LINK]
    shown = visible(text if len(text) < 300 else text[:300] + "...")
    out(f"\n{COL['B']}Link:{COL['END']} {shown}")
    out(f"  found in: {visible('; '.join(where))}")
    url = normalise_url(text)
    if not url:
        pf, inner = classify_payload(text)
        if too_long:
            pf.append((MED, f"Content is {len(rec['raw'])}+ characters, longer than any real QR code holds. "
                         "Only the first part was analysed; treat it as suspicious."))
        for lv, m in pf:
            p(lv, m)
        sc, parts = score_findings(pf)
        v = overall(pf) if sc >= SUSPICIOUS_AT else "Not a web link. Check the content by hand."
        out(f"  {COL['B']}VERDICT:{COL['END']} {v}  (risk score {sc}/100)")
        rec["findings"] = [{"level": lv, "detail": visible(m)} for lv, m in pf]
        rec["verdict"] = v
        rec["score"] = sc
        rec["score_parts"] = [{"points": pt, "level": lv, "detail": visible(m)} for pt, lv, m in parts]
        rec["links_inside"] = [check_link(u, ["inside the QR content above"], brands, keys, do_scan, do_redact)
                               for u in inner]
        return rec

    wrap_notes = []
    for _ in range(3):   # a link can be wrapped more than once
        inner, wrapper = unwrap(url)
        if not inner:
            break
        wrap_notes.append((INFO, f"Rewritten by {wrapper}. The real destination is {inner}, and that is what was checked."))
        rec.setdefault("unwrapped", []).append(inner)
        url = inner

    findings, reg = domain_checks(url, brands)
    findings = wrap_notes + findings
    if too_long:
        findings.append((MED, f"Content is {len(rec['raw'])}+ characters, longer than any real QR code holds. "
                         "Only the first part was analysed; treat it as suspicious."))
    rec["registered_domain"] = reg
    rec["checked_url"] = url

    for inner in nested_urls(url):
        ih = (safe_split(inner)[0].hostname or "").lower()
        _, ireg = host_info(ih) if ih else (None, None)
        if not ireg or ireg == reg:
            continue
        same_brand = any(reg in b["domains"] and ireg in b["domains"] for b in brands)
        if same_brand:
            continue  # e.g. Microsoft login redirecting back to another Microsoft domain
        rec.setdefault("hidden_destinations", []).append(inner)
        findings.append((MED, f"Link hides a second address inside it ({inner}). "
                              f"{reg} is being used as a stepping stone (open redirect)."))
        f2, _ = domain_checks(inner, brands)
        findings += [(lv, "Hidden destination: " + m) for lv, m in f2]

    emails = find_emails(url)
    if emails:
        # alone: newsletters and trackers do this too. With any other red flag: a personalised lure.
        other_flags = any(lv in (HIGH, MED) for lv, _ in findings)
        findings.append((HIGH if other_flags else LOW,
                         f"Link carries the recipient's email address ({', '.join(emails)}). "
                         + ("Personalised phishing lure; opening it confirms the address to the attacker."
                            if other_flags else
                            "Newsletters do this too, but a phishing link would use it to confirm the address.")))
        rec["emails_in_link"] = list(emails)

    is_known_brand = any(x[0] == GOOD for x in findings)
    skip_age = (not reg or is_known_brand or "." not in reg or reg in SHORTENERS
                or any(reg == d or reg.endswith("." + d) for d in ABUSED_HOSTING | FILE_SHARE)
                or any(x[1].startswith("Link goes to a raw IP") for x in findings))
    if not skip_age:
        days, info = rdap_age(reg)
        if days is not None:
            rec["domain_registered"] = info
            if days < 30:
                findings.append((HIGH, f"Domain {reg} was registered {days} days ago ({info})."))
            elif days < 180:
                findings.append((MED, f"Domain {reg} is only {days} days old ({info})."))
            else:
                findings.append((INFO, f"Domain {reg} registered {info} ({days} days ago)."))
        else:
            findings.append((INFO, f"Domain age for {reg}: {info}."))

    if reg and keys.get("VT_API_KEY") and network_allowed("lookups"):
        vt = vt_domain(reg, keys["VT_API_KEY"])
        rec["virustotal_domain"] = vt
        if vt.get("malicious", 0) >= 2:
            findings.append((HIGH, f"VirusTotal: {vt['malicious']} engines flag {reg} as malicious."))
        elif vt.get("malicious", 0) == 1 or vt.get("suspicious", 0) >= 1:
            findings.append((MED, f"VirusTotal: {vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious for {reg}."))
        elif "note" in vt:
            findings.append((LOW, f"{vt['note']} ({reg}). Brand-new or rarely used."))
        elif "error" in vt:
            findings.append((INFO, f"VirusTotal lookup failed: {vt['error']} (check VT_API_KEY in keys.txt)."))
        else:
            findings.append((INFO, f"VirusTotal: no engines flag {reg}."))

    if do_scan and keys.get("URLSCAN_API_KEY") and network_allowed("live"):
        scan_url = redact(url, emails) if (emails and do_redact) else url
        if scan_url != url:
            out(f"  scanning redacted URL: {scan_url}")
        out("  submitting PRIVATE urlscan.io scan (visits the link from urlscan's servers)...")
        us = urlscan(scan_url, keys["URLSCAN_API_KEY"], save_png=png_path)
        rec["urlscan"] = us
        if us.get("final_domain"):
            fd = us["final_domain"].lower()
            if fd != reg:
                findings.append((INFO, f"Link redirects and lands on {fd} ({us.get('final_url')})."))
                f2, _ = domain_checks(us["final_url"], brands)
                findings += [(lv, "Landing page: " + m) for lv, m in f2]
            if us.get("malicious"):
                findings.append((HIGH, f"urlscan verdict: MALICIOUS (score {us.get('score')})."))
            if us.get("brands"):
                landed_known = any(fd in b["domains"] or any(fd.endswith("." + d) for d in b["domains"]) for b in brands)
                lvl = INFO if landed_known else HIGH
                findings.append((lvl, f"urlscan saw the page imitating/showing: {', '.join(us['brands'])}"
                                      + ("" if landed_known else f" while hosted on {fd}.")))
            if us.get("title"):
                findings.append((INFO, f"Page title: {us['title']}"))
        if us.get("error"):
            findings.append((INFO, f"urlscan: {us['error']}"))
        findings.append((INFO, f"urlscan report: {us.get('report')}"))
        if us.get("screenshot_file"):
            findings.append((INFO, f"Screenshot saved: {us['screenshot_file']}"))
        elif us.get("report"):
            findings.append((INFO, f"Screenshot not ready yet, view online: {us.get('screenshot')}"))
    elif do_scan and network_allowed("live"):
        findings.append((INFO, "No urlscan API key in keys.txt, live scan skipped."))

    order = {HIGH: 0, MED: 1, LOW: 2, GOOD: 3, INFO: 4}
    findings.sort(key=lambda x: order.get(x[0], 9))
    for lv, m in findings:
        p(lv, m)
    v = overall(findings)
    sc, parts = score_findings(findings)
    colour = COL[HIGH] if v.startswith("LIKELY") else COL[MED] if v.startswith("SUSP") else COL[LOW] if v.startswith("LOW RISK") else COL[GOOD]
    out(f"  {COL['B']}VERDICT:{COL['END']} {colour}{v}{COL['END']}  (risk score {sc}/100)")
    rec["findings"] = [{"level": lv, "detail": visible(m)} for lv, m in findings]
    rec["verdict"] = v
    rec["score"] = sc
    rec["score_parts"] = [{"points": pt, "level": lv, "detail": visible(m)} for pt, lv, m in parts]
    return rec


def check_links(links, brands, keys, do_scan, do_redact, png_for=None):
    """Check every link concurrently (network lookups dominate). Yields records in order."""
    items = list(links.items())
    workers = 4 if (do_scan and keys.get("URLSCAN_API_KEY") and network_allowed("live")) else 8
    with ThreadPoolExecutor(max_workers=workers) as ex:
        def one(n, text, where):
            try:
                png = png_for(n, text) if png_for else None
            except Exception:
                png = None
            rec = check_link(text, where, brands, keys, do_scan, do_redact, png)
            rec["_console"] = getattr(_TLS, "last", "")
            return rec
        futs = [ex.submit(one, n, text, where) for n, (text, where) in enumerate(items, 1)]
        for f in futs:
            yield f.result()


def main():
    if os.name == "nt":
        os.system("")  # enable ANSI colours in Windows console
    ap = argparse.ArgumentParser(description="Check emails, attachments and QR codes for phishing. "
                                             "Offline unless you add --lookups or --live.")
    ap.add_argument("files", nargs="*")
    ap.add_argument("--paste", action="store_true",
                    help="read a pasted email from the keyboard (finish with Ctrl+Z then Enter on Windows, Ctrl+D elsewhere)")
    ap.add_argument("--lookups", action="store_true",
                    help="online: domain age (rdap.org) and VirusTotal. Only the domain name is sent")
    ap.add_argument("--live", action="store_true",
                    help="online: urlscan.io visits the link from its own servers (needs a key in keys.txt)")
    ap.add_argument("--no-scan", action="store_true", help="kept for old scripts; offline is now the default")
    ap.add_argument("--no-redact", action="store_true", help="send the URL to urlscan unchanged")
    ap.add_argument("--open", action="store_true", help="open each saved screenshot when done")
    ap.add_argument("--password", help="password for a locked PDF (often given in the phishing email)")
    a = ap.parse_args()
    live = a.live and not a.no_scan
    set_network(lookups=a.lookups, live=live)

    import report as html_report
    pasted = set()
    if a.paste:
        print("Paste the email (best: the full message source with headers), then finish with "
              + ("Ctrl+Z and Enter." if os.name == "nt" else "Ctrl+D."))
        text = sys.stdin.read()
        if text.strip():
            f = html_report.fallback_dir() / f"Pasted-email-{datetime.now():%Y%m%d-%H%M%S}.txt"
            f.write_text(text, encoding="utf-8")
            a.files.append(str(f))
            pasted.add(str(f))
    if not a.files:
        ap.error("give a file to check, or use --paste")

    keys, brands = load_keys(), load_brands()
    if live and not keys.get("URLSCAN_API_KEY"):
        print("  --live needs a urlscan.io key in keys.txt; continuing without the live scan.")
        live = False
    mode = ("live scan (urlscan.io)" if live else "offline check") + (" + online lookups" if a.lookups else "")
    print(f"Mode: {mode}" + ("" if (live or a.lookups) else ". Nothing is sent to the internet."))
    for path in a.files:
        print(f"\n{'=' * 78}\n{COL['B']}File:{COL['END']} {path}")
        try:
            links, notes = collect(path, a.password, pasted=str(path) in pasted)
            for lv, m in notes:
                p(lv, m)
        except Exception as e:
            p(HIGH if "password" in str(e).lower() else MED, str(e))
            continue
        if not links:
            if any(lv in (HIGH, MED) for lv, _ in notes):
                p(MED, "No QR codes or links could be read, but see the warnings above.")
            else:
                p(INFO, "No QR codes or links found.")
        report = {"file": str(path), "checked": datetime.now().isoformat(timespec="seconds"), "mode": mode,
                  "file_findings": [{"level": lv, "detail": m} for lv, m in notes], "links": []}
        shots_dir = Path(path).parent / (Path(path).stem + "_screenshots")

        def png_for(n, text, shots_dir=shots_dir):
            if not live or not normalise_url(text):
                return None
            try:
                shots_dir.mkdir(exist_ok=True)
            except Exception:
                return None
            host = re.sub(r"[^A-Za-z0-9.-]", "_", safe_split(normalise_url(text))[0].hostname or "link")[:60]
            return shots_dir / f"link{n}_{host}.png"

        for rec in check_links(links, brands, keys, live, not a.no_redact, png_for):
            print(rec.pop("_console", ""))
            report["links"].append(rec)
            saved = rec.get("urlscan", {}).get("screenshot_file")
            if saved and a.open and os.name == "nt":
                os.startfile(saved)
        score, parts = html_report.file_score(notes, report["links"])
        level = html_report.LEVELS[html_report.file_level(notes, report["links"])][0]
        report["risk_score"], report["overall"] = score, level
        report["score_parts"] = [{"points": pt, "level": lv, "detail": m} for pt, lv, m in parts]
        print(f"\n{COL['B']}OVERALL: {level}  |  risk score {score}/100{COL['END']}")
        for pt, lv, m in parts:
            print(f"   +{pt:<3} {visible(m)[:150]}")
        report_path = Path(path).with_suffix(".emailcheck.json")
        try:
            report_path = html_report.write_text_safely(report_path, json.dumps(report, indent=2, ensure_ascii=False))
            import getpass
            page = html_report.write_report([(path, notes, report["links"])], mode, getpass.getuser(), brands)
            print(f"\nReport saved: {page or report_path}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
