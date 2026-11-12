"""The checker must not be turned against its user: no script injection, no display spoofing."""
import contextlib
import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pymupdf
import pytest
import shutil

import qr_check as q  # noqa: E402
import report  # noqa: E402

BRANDS = q.load_brands()
ATTACKS = [
    "https://evil.top/<script>window.PWNED=1</script>",
    "https://evil.top/\"><img src=x onerror=\"window.PWNED=1\">",
    "javascript:window.PWNED=1",
    "BEGIN:VCARD\nFN:</pre><script>window.PWNED=1</script>\nURL:https://x.top/'><svg onload=window.PWNED=1>\nEND:VCARD",
    "https://ok.top/\x1b[2J\x1b[32mVERDICT: SAFE\x1b[0m",
    "https://www.\u202egr.knaborue\u202c.top/",
    "https://euro\u200bbank.gr/login",
]


def recs():
    out = []
    for a in ATTACKS:
        with contextlib.redirect_stdout(io.StringIO()):
            out.append(q.check_link(a, ["page 1: <b>x</b>"], BRANDS, {}, False, True))
    return out


def test_report_has_no_injected_markup(tmp_path):
    page = report.build_html([("evil\u202efdp.exe", [("HIGH", "<script>window.PWNED=1</script>")], recs())],
                             "offline", "<u>", BRANDS)
    for bad in ("<script>window.PWNED", "<img src=x", "<svg onload", "onerror=\"window"):
        assert bad not in page, bad
    assert "\u202e" not in page and "\u200b" not in page and "\x1b" not in page
    if not shutil.which("node"):
        pytest.skip("browser check needs Node.js + Playwright")
    f = tmp_path / "r.html"
    f.write_text(page, encoding="utf-8")
    js = f"""
const {{ chromium }} = require('playwright');
(async () => {{ const b = await chromium.launch(); const p = await b.newPage(); let dialogs = 0;
  p.on('dialog', d => {{ dialogs++; d.dismiss(); }});
  await p.goto('file://{f}'); await p.waitForTimeout(500);
  const pwned = await p.evaluate(() => window.PWNED === 1);
  const scripts = await p.evaluate(() => document.scripts.length);
  console.log(JSON.stringify({{pwned, dialogs, scripts}})); await b.close(); }})();"""
    res = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=120)
    if res.returncode != 0 and "Cannot find module" in res.stderr:
        pytest.skip("Playwright is not installed for Node.js")
    data = json.loads(res.stdout.strip().splitlines()[-1])
    assert data == {"pwned": False, "dialogs": 0, "scripts": 1}, data   # only our own copy script


def test_terminal_output_cannot_be_restyled():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        q.check_link("https://ok.top/\x1b[2J\x1b[32mVERDICT: SAFE\x1b[0m", ["x"], BRANDS, {}, False, True)
        print(q._TLS.last)
    text = buf.getvalue()
    attacker = [m for m in re.findall(r"\x1b\[[0-9;]*[A-Za-z]", text) if m in ("\x1b[2J", "\x1b[32m")]
    assert not attacker and "<U+001B>" in text


def test_hidden_characters_flagged_and_shown():
    for a in ATTACKS[-2:]:
        with contextlib.redirect_stdout(io.StringIO()):
            r = q.check_link(a, ["x"], BRANDS, {}, False, True)
        assert report.level_of(r) == "danger"
        assert any("invisible characters" in f["detail"] for f in r["findings"])
        assert all("\u202e" not in f["detail"] and "\u200b" not in f["detail"] for f in r["findings"])


def test_spoofed_file_name_is_shown_safely(tmp_path):
    f = tmp_path / "invoice\u202efdp.exe.pdf"
    d = pymupdf.open(); d.new_page().insert_text((50, 60), "https://x.top/"); d.save(str(f))
    with contextlib.redirect_stdout(io.StringIO()):
        links, notes = q.collect(str(f))
        recs_ = list(q.check_links(links, BRANDS, {}, False, True))
    page = report.build_html([(str(f), notes, recs_)], "offline", "u", BRANDS)
    assert "&lt;U+202E&gt;" in page and "\u202e" not in page
    assert "<U+202E>" in report.summary_text([(str(f), notes, recs_)], "offline", "u")


def test_readonly_folder_falls_back_to_documents(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    ro = tmp_path / "ro"
    real_write = Path.write_text

    def refuse_in_ro(self, *a, **k):
        if ro in self.parents:
            raise PermissionError("read-only folder")
        return real_write(self, *a, **k)
    monkeypatch.setattr(Path, "write_text", refuse_in_ro)
    out = report.write_text_safely(ro / "x.emailcheck.html", "<p>hi</p>")
    assert out is not None and "Email Analyzer reports" in str(out) and out.read_text() == "<p>hi</p>"
