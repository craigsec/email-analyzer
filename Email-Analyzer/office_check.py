"""
Office documents: Word, Excel, PowerPoint (new .docx/.xlsx/.pptx and macro versions,
plus old .doc/.xls/.ppt).  Finds links, QR codes in pictures, macros, templates or
objects loaded from the internet, DDE commands, embedded files and Windows-password leaks.
"""
import io
import re
import struct
import zipfile
from xml.etree import ElementTree as ET

import qr_check as E

HIGH, MED, INFO = E.HIGH, E.MED, E.INFO
REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"


def _unc(target):
    t = target.strip().lower()
    return t.startswith("\\\\") or t.startswith("file://") or t.startswith("//") and not t.startswith("//www")


def inspect_ooxml(name, blob, where, depth, ctx):
    import inspectors
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        ctx.notes.append((MED, f"{inspectors.subj(where, name)} is a damaged Office document."))
        return
    names = zf.namelist()

    def read(n, limit=inspectors.MAX_MEMBER):
        info = zf.getinfo(n)
        if info.file_size > limit or not ctx.take(info.file_size):
            return b""
        return zf.read(n)

    # macros
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} contains macros (code that runs if you click 'Enable content'). "
                                "Do not enable it. Real invoices and statements never need macros."))
    # relationships: hyperlinks, remote templates, external objects, UNC paths
    for n in names:
        if not n.endswith(".rels"):
            continue
        try:
            root = ET.fromstring(read(n))
        except Exception:
            continue
        for rel in root.iter(f"{REL_NS}Relationship"):
            target = rel.get("Target", "")
            rtype = rel.get("Type", "").rsplit("/", 1)[-1]
            if rel.get("TargetMode") != "External" or not target or inspectors.is_schema(target):
                continue
            if _unc(target):
                ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} connects to a network share ({E.visible(target[:120])}) when "
                                        "opened. This can leak your Windows password hash to the attacker."))
                continue
            if rtype == "hyperlink":
                ctx.items.append((target, f"{where}link in document"))
            elif rtype in ("attachedTemplate", "oleObject", "frame", "subDocument", "package"):
                ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} loads content from the internet when opened "
                                        f"({rtype}: {E.visible(target[:150])}). This 'remote template' trick "
                                        "downloads malware after the file passes scanners."))
                ctx.items.append((target, f"{where}{rtype} loaded when the document opens"))
            elif rtype in ("image", "audio", "video"):
                ctx.notes.append((MED, f"{inspectors.subj(where, name)} fetches a {rtype} from the internet when opened "
                                       "(tells the sender you opened it)."))
                ctx.items.append((target, f"{where}{rtype} loaded from the internet"))
            elif rtype == "externalLinkPath" or "externalLink" in rtype:
                ctx.notes.append((MED, f"{inspectors.subj(where, name)} links to an outside workbook ({E.visible(target[:150])})."))
                ctx.items.append((target, f"{where}external workbook link"))
            else:
                ctx.items.append((target, f"{where}external {rtype}"))

    dde_seen = False
    for n in names:
        low = n.lower()
        if low.endswith(".xml") and (low.startswith(("word/", "xl/", "ppt/"))):
            xml = read(n, 30 * 1024 * 1024).decode("utf-8", "ignore")
            if not dde_seen and (re.search(r"\bDDE(AUTO)?\b", xml) and "instrText" in xml or "<ddeLink" in xml
                                 or re.search(r"=\s*\w+\|'?/[cC]", xml)):
                dde_seen = True
                ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} contains a DDE command that can start programs on the PC "
                                        "when the document opens."))
            text = re.sub(r"<[^>]+>", " ", xml)
            for u in inspectors.urls_in_text(unescape_xml(text)):
                ctx.items.append((u, f"{where}address written in document"))
            # instrText HYPERLINK fields
            for u in re.findall(r'HYPERLINK\s+"([^"]+)"', xml):
                ctx.items.append((u, f"{where}link in document"))
        elif "/media/" in low and re.search(r"\.(png|jpe?g|gif|bmp|tiff?|webp|emf|wmf)$", low):
            data = read(n, 30 * 1024 * 1024)
            if data and not low.endswith((".emf", ".wmf")):
                try:
                    from PIL import Image
                    img = Image.open(io.BytesIO(data))
                    img.load()
                    for t, fmt in E.decode_qr(img, heavy=True):
                        ctx.items.append((t, f"{where}{fmt} in a picture inside the document"))
                except Exception:
                    pass
        elif "/embeddings/" in low:
            data = read(n)
            if not data:
                continue
            inner = n.rsplit("/", 1)[-1]
            pkg = ole10native(data)
            if pkg:
                pname, pdata = pkg
                ctx.notes.append((HIGH if pname.lower().endswith(tuple(inspectors.DANGEROUS)) else MED,
                                  f"{inspectors.subj(where, name)} has a file packed inside it: '{E.visible(pname)}'."))
                inspectors.analyze(pname, pdata, f"{inspectors.subj(where, name)} > ", depth + 1, ctx)
            else:
                ctx.notes.append((MED, f"{inspectors.subj(where, name)} has an embedded object '{E.visible(inner)}'."))
                inspectors.analyze(inner, data, f"{inspectors.subj(where, name)} > ", depth + 1, ctx)


def unescape_xml(text):
    return text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')


def ole10native(data):
    """Return (filename, bytes) from an OLE 'Package' object, the classic way to hide a file in a document."""
    try:
        import olefile
        if not olefile.isOleFile(io.BytesIO(data)):
            return None
        ole = olefile.OleFileIO(io.BytesIO(data))
        if not ole.exists("\x01Ole10Native"):
            return None
        raw = ole.openstream("\x01Ole10Native").read()
        pos = 6                                        # total size (4) + flags (2)
        end = raw.index(b"\x00", pos)
        label = raw[pos:end].decode("latin-1", "ignore")
        pos = raw.index(b"\x00", end + 1) + 1          # original path
        pos += 4                                       # unknown
        tlen = struct.unpack_from("<I", raw, pos)[0]
        pos += 4 + tlen                                # temp path
        dlen = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        return label or "packaged-file", raw[pos:pos + dlen]
    except Exception:
        return None


def inspect_ole(name, blob, where, depth, ctx):
    """Old binary Office files (.doc/.xls/.ppt)."""
    import inspectors
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(blob))
    except Exception:
        ctx.notes.append((MED, f"{inspectors.subj(where, name)} is a damaged Office file."))
        return
    streams = ["/".join(s) for s in ole.listdir(streams=True, storages=True)]
    low = [s.lower() for s in streams]
    if "encryptedpackage" in low or "encryptioninfo" in low:
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} is a password-protected Office file, so it cannot be checked. "
                                "Locking files is a common trick to get past scanners."))
        return
    if any(s.startswith(("macros/vba", "_vba_project_cur", "vba/")) or s.endswith("/vba") or "vba/dir" in s for s in low):
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} contains macros (code that runs if you click 'Enable content'). "
                                "Do not enable it."))
    if any(s.startswith("objectpool/") for s in low) or any("ole10native" in s for s in low):
        ctx.notes.append((MED, f"{inspectors.subj(where, name)} contains embedded objects."))
    text = blob.decode("latin-1", "ignore") + " " + blob.decode("utf-16-le", "ignore")
    for u in inspectors.urls_in_text(text, ascii_only=True):
        if len(u) < 400:
            ctx.items.append((u, f"{where}address found in document"))
    if re.search(r"\bDDEAUTO\b", text):
        ctx.notes.append((HIGH, f"{inspectors.subj(where, name)} contains a DDE command that can start programs on the PC."))
    for s in streams:
        if s.lower().endswith("ole10native"):
            try:
                raw = ole.openstream(s).read()
                pkg = ole10native_from_stream(raw)
                if pkg:
                    inspectors.analyze(pkg[0], pkg[1], f"{inspectors.subj(where, name)} > ", depth + 1, ctx)
            except Exception:
                pass


def ole10native_from_stream(raw):
    try:
        pos = 6
        end = raw.index(b"\x00", pos)
        label = raw[pos:end].decode("latin-1", "ignore")
        pos = raw.index(b"\x00", end + 1) + 1 + 4
        tlen = struct.unpack_from("<I", raw, pos)[0]
        pos += 4 + tlen
        dlen = struct.unpack_from("<I", raw, pos)[0]
        return label or "packaged-file", raw[pos + 4:pos + 4 + dlen]
    except Exception:
        return None
