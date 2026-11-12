"""Minimal Compound File (OLE / CFB) writer, used ONLY by the tests to build Outlook .msg and old
.doc samples, laid out like real Outlook files (small streams in the mini stream)."""
import struct

SECTOR = 512
FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def _key(name):
    return (len(name), name.upper())


def build(tree):
    """tree: {"name": bytes | {subtree}}  ->  CFB file bytes."""
    entries = [{"name": "Root Entry", "type": 5, "data": b"", "children": []}]

    def add(parent_idx, subtree):
        for name, val in subtree.items():
            idx = len(entries)
            if isinstance(val, dict):
                entries.append({"name": name, "type": 1, "data": b"", "children": []})
                entries[parent_idx]["children"].append(idx)
                add(idx, val)
            else:
                entries.append({"name": name, "type": 2, "data": val, "children": []})
                entries[parent_idx]["children"].append(idx)
    add(0, tree)

    # sibling links: sorted chain via right-sibling pointers (valid ordering, degenerate tree)
    for e in entries:
        e.setdefault("left", NOSTREAM)
        e.setdefault("right", NOSTREAM)
        e.setdefault("child", NOSTREAM)
    for e in entries:
        kids = sorted(e["children"], key=lambda i: _key(entries[i]["name"]))
        if kids:
            e["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                entries[a]["right"] = b

    # lay out stream data in sectors
    sectors, fat = [], []

    def alloc(data):
        if not data:
            return ENDOFCHAIN
        n = (len(data) + SECTOR - 1) // SECTOR
        start = len(sectors)
        for i in range(n):
            sectors.append(data[i * SECTOR:(i + 1) * SECTOR].ljust(SECTOR, b"\x00"))
            fat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        return start
    # small streams (< 4096 bytes) live in the mini stream: 64-byte mini sectors inside the root entry
    mini, minifat = bytearray(), []
    for e in entries:
        if e["type"] == 2 and 0 < len(e["data"]) < 4096:
            n = (len(e["data"]) + 63) // 64
            start = len(minifat)
            mini += e["data"].ljust(n * 64, b"\x00")
            minifat += [start + i + 1 if i < n - 1 else ENDOFCHAIN for i in range(n)]
            e["start"] = start
        elif e["type"] == 2:
            e["start"] = alloc(e["data"]) if e["data"] else ENDOFCHAIN
        else:
            e["start"] = ENDOFCHAIN
    root = entries[0]
    root["start"] = alloc(bytes(mini)) if mini else ENDOFCHAIN
    root["mini_size"] = len(mini)
    minifat_start, n_minifat = ENDOFCHAIN, 0
    if minifat:
        minifat += [FREESECT] * ((-len(minifat)) % 128)
        mf = b"".join(struct.pack("<I", v) for v in minifat)
        minifat_start = alloc(mf)
        n_minifat = len(mf) // SECTOR

    # directory sectors
    def dirent(e):
        name = e["name"].encode("utf-16-le") + b"\x00\x00"
        d = name.ljust(64, b"\x00")
        d += struct.pack("<HBB", len(name), e["type"], 1)
        d += struct.pack("<III", e["left"], e["right"], e["child"])
        d += b"\x00" * 16 + struct.pack("<I", 0) + b"\x00" * 16
        size = len(e["data"]) if e["type"] == 2 else e.get("mini_size", 0)
        d += struct.pack("<IQ", e["start"], size)
        return d
    dir_bytes = b"".join(dirent(e) for e in entries)
    pad = (-len(entries)) % 4
    dir_bytes += (b"\x00" * 64 + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
                  + b"\x00" * 36 + struct.pack("<IQ", 0, 0)) * pad
    dir_start = alloc(dir_bytes)

    # FAT sectors (may need several); entries per FAT sector = 128
    n_fat = 1
    while True:
        total = len(fat) + n_fat
        if (total + 127) // 128 <= n_fat:
            break
        n_fat += 1
    fat_start = len(fat)
    fat += [FATSECT] * n_fat
    fat += [FREESECT] * ((-len(fat)) % 128)
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    for i in range(n_fat):
        sectors.append(fat_bytes[i * SECTOR:(i + 1) * SECTOR])

    hdr = bytearray(512)
    hdr[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    struct.pack_into("<HHHHH", hdr, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", hdr, 44, n_fat)
    struct.pack_into("<I", hdr, 48, dir_start)
    struct.pack_into("<I", hdr, 56, 4096)
    struct.pack_into("<II", hdr, 60, minifat_start, n_minifat)
    struct.pack_into("<II", hdr, 68, ENDOFCHAIN, 0)
    for i in range(109):
        struct.pack_into("<I", hdr, 76 + 4 * i, fat_start + i if i < n_fat else FREESECT)
    return bytes(hdr) + b"".join(sectors)


def msg(subject, sender_name, sender_addr, body, html="", headers="", attachments=()):
    """A minimal Outlook .msg with the properties the checker reads."""
    u = lambda s: s.encode("utf-16-le")  # noqa: E731
    tree = {
        "__substg1.0_0037001F": u(subject),
        "__substg1.0_0C1A001F": u(sender_name),
        "__substg1.0_0C1F001F": u(sender_addr),
        "__substg1.0_1000001F": u(body),
        "__properties_version1.0": b"\x00" * 32,
    }
    if html:
        tree["__substg1.0_10130102"] = html.encode("utf-8")
    if headers:
        tree["__substg1.0_007D001F"] = u(headers)
    for i, (name, data) in enumerate(attachments):
        tree[f"__attach_version1.0_#{i:08X}"] = {
            "__substg1.0_3707001F": u(name),
            "__substg1.0_37010102": data,
            "__properties_version1.0": b"\x00" * 8,
        }
    return build(tree)
