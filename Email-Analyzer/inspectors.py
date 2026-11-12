"""
File inspectors for Email Analyzer

Works out what a file really is (from its content, never its name) and pulls out
links, QR codes and red flags from: PDFs, pictures, Office documents, HTML/SVG,
emails (.eml/.msg), ZIP and ISO archives. Nested files are inspected recursively,
with limits so a hostile file cannot exhaust the PC.

Every analyser adds:
  items  -> (link_or_qr_text, where_found)   checked later by the link engine
  notes  -> (level, message)                 file-level red flags shown above the links
"""
import base64
import email
import email.policy
import io
import os
import re
import zipfile
from email.utils import getaddresses, parseaddr
from html import unescape
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree as ET

import qr_check as E

HIGH, MED, INFO, GOOD = E.HIGH, E.MED, E.INFO, E.GOOD

MAX_DEPTH = 4                     # file inside file inside file ...
MAX_TOTAL = 400 * 1024 * 1024     # bytes unpacked per check (zip-bomb guard)
MAX_MEMBER = 80 * 1024 * 1024     # biggest single file we unpack
MAX_MEMBERS = 400                 # files per archive
MAX_FILE = 200 * 1024 * 1024      # biggest file we read at all

DANGEROUS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
             ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msix", ".msp", ".appx", ".appxbundle", ".jar", ".dll",
             ".cpl", ".reg", ".iso", ".img", ".vhd", ".vhdx", ".one", ".onepkg", ".xll", ".chm", ".url",
             ".application", ".appref-ms", ".gadget", ".inf", ".scf", ".sct", ".library-ms", ".search-ms",
             ".settingcontent-ms", ".svgz"}
DOC_LOOKING = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt",
               ".csv", ".rtf", ".odt", ".zip"}
FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "yahoo.gr",
             "aol.com", "icloud.com", "me.com", "gmx.com", "gmx.net", "mail.com", "proton.me", "protonmail.com",
             "yandex.com", "yandex.ru", "zoho.com", "hotmail.gr", "windowslive.com"}
EXPECT = {".pdf": "pdf", ".docx": "office", ".docm": "office", ".dotx": "office", ".dotm": "office",
          ".xlsx": "office", ".xlsm": "office", ".xltx": "office", ".xltm": "office", ".pptx": "office",
          ".pptm": "office", ".zip": "zip", ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".msg": "ole",
          ".iso": "iso", ".img": "iso", ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
          ".bmp": "image", ".tif": "image", ".tiff": "image", ".webp": "image", ".htm": "html", ".html": "html",
          ".shtml": "html", ".xhtml": "html", ".svg": "svg", ".eml": "eml", ".rtf": "rtf"}
SUPPORTED_EXT = set(EXPECT) | {".txt"}
KIND_NAMES = {"pdf": "a PDF", "office": "an Office document", "zip": "a ZIP archive", "ole": "an Office/Outlook file",
              "iso": "a disk image", "image": "a picture", "html": "a web page", "svg": "an SVG picture",
              "eml": "an email", "rtf": "an RTF document", "exe": "a Windows program", "lnk": "a Windows shortcut",
              "onenote": "a OneNote file", "7z": "a 7-Zip archive", "rar": "a RAR archive",
              "gzip": "a compressed file", "text": "plain text", "unknown": "an unknown file type"}


class Ctx:
    """Shared state for one top-level check."""
    def __init__(self, password=None):
        self.items, self.notes = [], []
        self.password = password
        self.budget = MAX_TOTAL

    def take(self, n):
        self.budget -= n
        return self.budget >= 0


# ------------------------------------------------------------------ sniff
def sniff(blob):
    """What the file really is, from its content. Exact signatures first, lenient rules last."""
    head = blob[:4096]
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        try:
            names = zipfile.ZipFile(io.BytesIO(blob)).namelist()
            if "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
                return "office"
        except Exception:
            pass
        return "zip"
    if head.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole"
    if len(blob) > 0x8006 and any(blob[o:o + 5] == b"CD001" for o in (0x8001, 0x8801, 0x9001)):
        return "iso"
    if head.startswith(b"MZ"):
        return "exe"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D"):
        return "onenote"
    if head.startswith(b"7z\xBC\xAF\x27\x1C"):
        return "7z"
    if head.startswith(b"Rar!"):
        return "rar"
    if head.startswith(b"\x1F\x8B"):
        return "gzip"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xFF\xD8\xFF" or head[:4] in (b"GIF8", b"II*\x00", b"MM\x00*") \
            or head[:2] == b"BM" or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    # email: a block of "Header: value" lines (with folded continuation lines) at the very start
    if re.match(rb"(?:[!-9;-~]+:[^\n]*\r?\n(?:[ \t][^\n]*\r?\n)*){2,}", head) and \
            re.search(rb"^(From|Received|Return-Path|Message-ID|Subject|Date|MIME-Version|To):", head, re.M | re.I):
        return "eml"
    text = head.decode("utf-8", "ignore").lstrip("﻿ \r\n\t").lower()
    if re.match(r"(<\?xml[^>]*>\s*)?(<!--.*?-->\s*)*<svg", text, re.S) or ("<svg" in text[:800] and "<html" not in text[:800]):
        return "svg"
    if re.match(r"(<!doctype html|<html|<head|<body|<script|<meta|<form|<div|<iframe|<!--)", text) \
            or re.search(r"<(html|script|form|iframe)\b", text[:2048]):
        return "html"
    if b"%PDF-" in head[:1024]:
        return "pdf"          # PDF readers accept the header anywhere in the first 1 KB
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head[:512]):
        return "text"
    return "unknown"


def subj(where, name):
    """How to refer to a file in a message, without repeating its name:
    where="attachment 'a.html' > ", name="a.html"  ->  "attachment 'a.html'"."""
    tag = f"'{E.visible(name)}' > "
    if where.endswith(tag):
        return where[:-3]
    return f"{where}'{E.visible(name)}'"


def inside(where, name):
    """Prefix for things found inside a file."""
    tag = f"'{E.visible(name)}' > "
    return where if where.endswith(tag) else f"{where}{tag}"


def file_name_checks(name, kind, where, ctx):
    """Names that lie: wrong extension, double extension, right-to-left tricks, program files."""
    p = Path(name)
    ext = p.suffix.lower()
    exts = [s.lower() for s in p.suffixes[-3:]]
    if ext in DANGEROUS or kind in ("exe", "lnk", "onenote"):
        what = KIND_NAMES.get(kind, "a program") if kind in ("exe", "lnk", "onenote") else f"a {ext} file"
        ctx.notes.append((HIGH, f"{subj(where, name)} is {what}. Opening it can run code on the PC. "
                                "Business documents are never sent like this."))
    if len(exts) >= 2 and exts[-2] in DOC_LOOKING and exts[-1] in DANGEROUS:
        ctx.notes.append((HIGH, f"{subj(where, name)} has a double extension: it looks like {exts[-2]} but is really {exts[-1]}."))
    if re.search(r"\s{6,}\.\w+$", name):
        ctx.notes.append((HIGH, f"{subj(where, name)} hides its real extension behind many spaces."))
    if any(ord(c) in (0x202E, 0x202D, 0x200F, 0x200E, 0x2066, 0x2067, 0x2068) for c in name):
        ctx.notes.append((HIGH, f"{subj(where, name)} uses a hidden right-to-left character to fake its file type."))
    expected = EXPECT.get(ext)
    if expected and kind not in (expected, "unknown", "text") and not (expected == "ole" and kind == "office"):
        lvl = HIGH if kind in ("exe", "lnk", "onenote", "html", "svg") else MED
        ctx.notes.append((lvl, f"{subj(where, name)} is named {ext} but is really {KIND_NAMES.get(kind, kind)}. "
                               "Disguised files are a common trick."))


SCHEMA_HOSTS = ("www.w3.org", "w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org",
                "ns.adobe.com", "www.xfa.org", "ns.microsoft.com", "schemas.xmlsoap.org", "xmlns.com")
ASCII_URL_RE = re.compile(r"https?://[\x21-\x7e]+", re.I)


def is_schema(url):
    host = (E.safe_split(url)[0].hostname or "").lower()
    return host in SCHEMA_HOSTS


def urls_in_text(text, ascii_only=False):
    out = []
    for u in (ASCII_URL_RE if ascii_only else E.URL_IN_TEXT_RE).findall(text):
        u = re.split(r"[\x00<>\"'\s]", u)[0].rstrip(".,;)'\"")
        if len(u) > 10 and not is_schema(u):
            out.append(u)
    return out


# ---------------------------------------------------------------- dispatch
def analyze(name, blob, where, depth, ctx, top=False):
    """Inspect one file (top-level or nested). `where` is the prefix used in every message."""
    if depth > MAX_DEPTH:
        ctx.notes.append((MED, f"{where}files are nested too deeply; the innermost ones were not checked."))
        return
    if not top and not ctx.take(len(blob)):
        ctx.notes.append((MED, f"{where}the archive unpacks to far more data than it should (zip bomb). "
                               "Checking stopped there; treat it as suspicious."))
        return
    kind = sniff(blob)
    file_name_checks(name, kind, where, ctx)
    if kind not in ("pdf", "zip", "office", "eml") and b"%PDF-" in blob[1:1024]:
        ctx.notes.append((MED, f"{subj(where, name)} is two file types at once ({KIND_NAMES.get(kind, kind)} "
                               "and a PDF). Such 'polyglot' files are built to fool scanners."))
    try:
        if kind == "pdf":
            items, _ = E.extract_from_pdf(None, password=ctx.password if top else None, data=blob,
                                          prefix=where, depth=depth, notes=ctx.notes, ctx=ctx)
            ctx.items.extend(items)
        elif kind == "image":
            from PIL import Image
            img = Image.open(io.BytesIO(blob))
            img.load()
            ctx.items.extend((t, f"{where}{fmt} (picture)") for t, fmt in E.decode_qr(img, heavy=True))
        elif kind == "office":
            import office_check
            office_check.inspect_ooxml(name, blob, where, depth, ctx)
        elif kind == "ole":
            import office_check
            import email_check
            if email_check.is_msg(blob):
                email_check.inspect_msg(name, blob, where, depth, ctx)
            else:
                office_check.inspect_ole(name, blob, where, depth, ctx)
        elif kind in ("html", "svg"):
            import web_check
            web_check.inspect(name, blob, where, depth, ctx, svg=(kind == "svg"), attachment=True)
        elif kind == "eml":
            import email_check
            email_check.inspect_eml(name, blob, where, depth, ctx)
        elif kind == "zip":
            inspect_zip(name, blob, where, depth, ctx)
        elif kind == "iso":
            inspect_iso(name, blob, where, depth, ctx)
        elif kind in ("7z", "rar", "gzip"):
            ctx.notes.append((MED, f"{subj(where, name)} is {KIND_NAMES[kind]}, which this tool cannot open. "
                                   "Unusual for business email; ask ICT before opening it."))
        elif kind == "rtf":
            text = blob.decode("latin-1", "ignore")
            ctx.items.extend((u, f"{where}link in RTF text") for u in urls_in_text(text))
            if re.search(r"\\object\\objemb|\\objdata|\\objupdate", text):
                ctx.notes.append((HIGH, f"{where}RTF document contains an embedded object that can run when opened "
                                        "(a known exploit technique)."))
        elif kind == "text":
            text = blob.decode("utf-8", "ignore")
            ctx.items.extend((u, f"{where}link in text") for u in urls_in_text(text))
    except RuntimeError:
        raise
    except Exception as e:
        ctx.notes.append((MED, f"{subj(where, name)} could not be fully checked ({e.__class__.__name__}). "
                               "Treat it as suspicious."))


# ---------------------------------------------------------------- archives
def inspect_zip(name, blob, where, depth, ctx):
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        ctx.notes.append((MED, f"{subj(where, name)} is a damaged ZIP archive."))
        return
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_MEMBERS:
        ctx.notes.append((MED, f"{where}archive holds {len(infos)} files; only the first {MAX_MEMBERS} were checked."))
    encrypted = [i for i in infos if i.flag_bits & 0x1]
    if encrypted:
        ctx.notes.append((HIGH, f"{subj(where, name)} is a password-protected ZIP. Locked archives are used "
                                "to hide malware from email scanners."))
    for info in infos[:MAX_MEMBERS]:
        inner = f"{subj(where, name)} > "
        member = info.filename
        if info.file_size > MAX_MEMBER:
            ctx.notes.append((MED, f"{inner}'{E.visible(member)}' is very large ({info.file_size // 1048576} MB) and was not unpacked."))
            continue
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 200 and info.file_size > 10 * 1048576:
            ctx.notes.append((HIGH, f"{inner}'{E.visible(member)}' is a zip bomb (compresses {info.file_size // info.compress_size}:1)."))
            continue
        try:
            pwd = ctx.password.encode() if (info.flag_bits & 0x1 and ctx.password) else None
            data = zf.read(info, pwd=pwd)
        except RuntimeError:
            file_name_checks(member, "unknown", inner, ctx)
            continue
        except Exception:
            file_name_checks(member, "unknown", inner, ctx)
            ctx.notes.append((MED, f"{inner}'{E.visible(member)}' could not be unpacked."))
            continue
        analyze(Path(member).name or member, data, inner, depth + 1, ctx)


def inspect_iso(name, blob, where, depth, ctx):
    ctx.notes.append((HIGH, f"{subj(where, name)} is a disk image (ISO/IMG). Attackers send these because "
                            "files inside skip Windows' internet-download warnings."))
    try:
        import pycdlib
        iso = pycdlib.PyCdlib()
        iso.open_fp(io.BytesIO(blob))
    except Exception:
        ctx.notes.append((MED, f"{where}the disk image could not be opened, so its contents were not checked."))
        return
    count = 0
    try:
        facade_kind = "joliet" if iso.has_joliet() else ("udf" if iso.has_udf() else ("rr" if iso.has_rock_ridge() else "iso9660"))
        for dirname, _dirs, files in iso.walk(**{f"{facade_kind}_path" if facade_kind != "iso9660" else "iso_path": "/"}):
            for fname in files:
                count += 1
                if count > MAX_MEMBERS:
                    break
                path = (dirname.rstrip("/") + "/" + fname)
                buf = io.BytesIO()
                key = f"{facade_kind}_path" if facade_kind != "iso9660" else "iso_path"
                try:
                    iso.get_file_from_iso_fp(buf, **{key: path})
                except Exception:
                    continue
                clean = re.sub(r";\d+$", "", fname)
                analyze(clean, buf.getvalue()[:MAX_MEMBER], f"{subj(where, name)} > ", depth + 1, ctx)
    finally:
        try:
            iso.close()
        except Exception:
            pass


# ------------------------------------------------------------- top level
def collect_pasted(text, ctx):
    """Email text pasted by the user. With headers it is checked as a full email, without as a body."""
    import email_check
    text = text.lstrip("\ufeff \t\r\n")
    blob = text.encode("utf-8", "ignore")
    if sniff(blob) == "eml":
        email_check.inspect_eml("pasted email", blob, "", 0, ctx)
    else:
        email_check.inspect_pasted(text, "", 0, ctx)


# ------------------------------------------------------------------ when Windows will not let us read a file
# Measured on a real company PC (Nov 2026) with the harmless DDE test sample: Microsoft Defender answers
# "access denied" (Windows error 5) at once, then removes the file about 6 seconds later. Python's own open()
# reports every refusal as the same "Permission denied", so the real Windows reason is asked for separately.
ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION = 5, 32
ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED = 225, 226
BLOCK_WAIT = 30          # seconds to watch a refused file for removal by Defender (took ~6 s on a real PC;
                         # the margin is for slow or busy PCs). A removed file is reported as soon as it goes.

DEFENDER_REMOVED = ("Microsoft Defender blocked this file and then removed it: it found something dangerous in it. "
                    "Do not open it or any copy of it (for example the original attachment in the email). Report it to ICT.")
DEFENDER_VIRUS = ("Microsoft Defender blocked this file: Windows reports that it contains a virus or unwanted software. "
                  "Do not open it or any copy of it (for example the original attachment in the email). Report it to ICT.")
READ_REFUSED = ("Windows refused to let this file be read, so it was not checked. This is usually Microsoft Defender "
                "blocking something dangerous: look in Windows Security > Protection history. "
                "Do not open it until ICT has looked at it.")
FILE_IN_USE = "This file is open in another program, so it could not be read. Close it there and check again."
FILE_GONE = ("This file no longer exists, so it was not checked. If nobody deleted it, Microsoft Defender probably "
             "removed it: do not open any copy of it and report it to ICT.")


def windows_open_error(path):
    """The real Windows error for opening `path` to read (0 = it opens). None when not on Windows."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes as W
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = W.HANDLE
    k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
    k.CloseHandle.argtypes = [W.HANDLE]
    h = k.CreateFileW(str(path), 0x80000000, 0x7, None, 3, 0x80, None)   # read, share all, open existing only
    if h == W.HANDLE(-1).value:
        return ctypes.get_last_error()
    k.CloseHandle(h)
    return 0


def read_refused(p, open_error=None, sleep=None, wait=BLOCK_WAIT):
    """A file exists but cannot be read. Returns the (LEVEL, sentence) note to show, None when the file can
    be read after all (try again), or raises RuntimeError for refusals that say nothing about the file."""
    import time
    sleep = sleep or time.sleep
    code = (open_error or windows_open_error)(p)
    if code == 0:
        return None
    if code in (ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED):
        return (HIGH, DEFENDER_VIRUS)
    if code == ERROR_SHARING_VIOLATION:
        raise RuntimeError(FILE_IN_USE)
    print("Windows blocked this file. Checking whether Microsoft Defender removes it...")
    waited = 0.0
    while waited < wait:
        if not p.exists():
            return (HIGH, DEFENDER_REMOVED)
        sleep(0.5)
        waited += 0.5
    return (HIGH, DEFENDER_REMOVED) if not p.exists() else (MED, READ_REFUSED)


def collect_file(path, password=None, pasted=False):
    """Read a file from disk and inspect it. Returns (items, notes)."""
    p = Path(path)
    try:
        size = p.stat().st_size
    except FileNotFoundError:
        raise RuntimeError(FILE_GONE)
    if size > MAX_FILE:
        raise RuntimeError(f"This file is {size // 1048576} MB, too large to check safely.")
    blob = None
    for attempt in (1, 2):
        try:
            blob = p.read_bytes()
            break
        except FileNotFoundError:
            return [], [(HIGH, DEFENDER_REMOVED)]      # there a moment ago, gone when read: removed
        except OSError as e:
            # PermissionError, or 'virus found' which Python reports as a generic error 22
            if not (isinstance(e, PermissionError) or e.errno == 22) or attempt == 2:
                raise
            if e.errno == 22 and windows_open_error(p) not in (ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED):
                raise
            note = read_refused(p)
            if note is not None:
                return [], [note]
            # readable after all (a scan had it locked for a moment): read it again
    if not blob:
        raise RuntimeError("This file is empty (0 bytes). Damaged or empty files are a known trick; treat it as suspicious.")
    ctx = Ctx(password)
    if pasted:
        text = blob.decode("utf-8", "ignore")
        if not text.strip():
            raise RuntimeError("Nothing was pasted.")
        collect_pasted(text, ctx)
        return ctx.items, ctx.notes
    kind = sniff(blob)
    if kind == "pdf":
        # keep the original top-level PDF behaviour (password prompt, plain messages)
        file_name_checks(p.name, kind, "", ctx)
        items, _ = E.extract_from_pdf(None, password=password, data=blob, prefix="", depth=0, notes=ctx.notes, ctx=ctx)
        ctx.items.extend(items)
    elif kind == "image":
        file_name_checks(p.name, kind, "", ctx)
        from PIL import Image
        try:
            img = Image.open(io.BytesIO(blob))
            img.load()
        except Exception:
            raise RuntimeError("This file could not be opened as a picture. It may be damaged or not really an image.")
        ctx.items.extend((t, f"image: {fmt}") for t, fmt in E.decode_qr(img, heavy=True))
    else:
        analyze(p.name, blob, "", 0, ctx, top=True)
    return ctx.items, ctx.notes
