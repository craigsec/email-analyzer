"""New file types and full email checks: every attack sample must be caught, legit mail must stay clean."""
import contextlib
import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspectors  # noqa: E402
import qr_check as q  # noqa: E402
import report  # noqa: E402
import samples_lib as S  # noqa: E402

BRANDS = q.load_brands()


def run(tmp_path, name, data, brands=None):
    f = tmp_path / name
    f.write_bytes(data)
    if brands is not None:
        orig = q.load_brands
        q.load_brands = lambda: brands
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            links, notes = q.collect(str(f))
            recs = list(q.check_links(links, brands or BRANDS, {}, False, True))
    finally:
        if brands is not None:
            q.load_brands = orig
    text = " ".join(m for _, m in notes)
    return links, notes, recs, text, report.file_level(notes, recs)


def run_in_memory(name, data):
    """Same checks as run(), but the sample never touches the disk. Used for attack samples: on a PC with
    Microsoft Defender the file is blocked between writing and reading (seen with dde.docx, Nov 2026), and the
    test must check our detection, not Defender's. For these file types collect_file() does nothing more than
    analyze(), so no coverage is lost; reading from disk is covered by the other tests here."""
    ctx = inspectors.Ctx(None)
    with contextlib.redirect_stdout(io.StringIO()):
        inspectors.analyze(name, data, "", 0, ctx, top=True)
        links = {}
        for text, where in ctx.items:
            links.setdefault(text.strip(), []).append(where)
        recs = list(q.check_links(links, BRANDS, {}, False, True))
    text = " ".join(m for _, m in ctx.notes)
    return links, ctx.notes, recs, text, report.file_level(ctx.notes, recs)


def test_phishing_email_everything_caught(tmp_path):
    links, notes, recs, t, lvl = run(tmp_path, "phish.eml", S.phish_eml())
    assert lvl == "danger"
    for must in ("calls themselves 'Eurobank Security'", "replies go to 'eurobank.helpdesk@gmail.com'",
                 "could NOT be verified", "shows 'www.eurobank.gr' but really goes to", "double extension",
                 "login page sent as a file", "HTML smuggling", "attachedTemplate", "Windows shortcut"):
        assert must in t, must
    assert "https://m365-mfa-verify.sbs/auth" in links                     # QR code in the email body
    assert any("picture in the email body" in w for w in links["https://m365-mfa-verify.sbs/auth"])


def test_outlook_msg(tmp_path):
    links, notes, recs, t, lvl = run(tmp_path, "phish.msg", S.phish_msg())
    assert lvl == "danger"
    for must in ("calls themselves 'Microsoft 365'", "replies go to", "could NOT be verified", "contains macros",
                 "picture that contains program code", "shows 'account.microsoft.com'"):
        assert must in t, must
    assert any("voicemail-m365.top" in u for u in links)


def test_bec_lookalike_of_our_company(tmp_path):
    brands = BRANDS + [{"name": "Our company", "domains": ["acmeshipping.com"], "keywords": ["acmeshipping"]}]
    links, notes, recs, t, lvl = run(tmp_path, "bec.eml", S.bec_eml(), brands)
    assert lvl == "danger"
    assert "new bank details" in t and "our company name" in t
    assert "acme-shipping-gr.com" in t


def test_legit_email_stays_clean(tmp_path):
    links, notes, recs, t, lvl = run(tmp_path, "dhl.eml", S.legit_eml())
    assert lvl in ("known", "clean"), [n for n in notes if n[0] in ("HIGH", "MEDIUM")]
    assert "sender verified" in t


@pytest.mark.parametrize("name,builder,must", [
    ("remote.docx", lambda: S.docx(remote_template="https://office-templates.top/t.dotm"), "remote template"),
    ("unc.docx", lambda: S.docx(unc="\\\\185.220.101.44\\s\\a.png"), "Windows password hash"),
    ("macro.docm", lambda: S.docx(macro=True), "contains macros"),
    ("dde.docx", lambda: S.docx(dde=True), "DDE command"),
    ("dde.xlsx", S.xlsx_dde, "DDE command"),
    ("pkg.docx", lambda: S.docx(packaged=("update.exe", S.FAKE_EXE)), "'update.exe' is a Windows program"),
    ("old.doc", S.legacy_doc_with_macros, "contains macros"),
    ("login.html", S.html_login_smuggle, "HTML smuggling"),
    ("redirect.htm", S.html_obfuscated_redirect, "scrambled script"),
    ("voice.svg", S.svg_script, "picture that contains program code"),
    ("locked.zip", lambda: S.zip_of([("a.pdf", b"%PDF-1.4")], encrypted=True), "password-protected ZIP"),
    ("disk.iso", lambda: S.iso_of([("Invoice.exe", S.FAKE_EXE)]), "'Invoice.exe' is a Windows program"),
    ("invoice.pdf", lambda: S.FAKE_EXE, "named .pdf but is really a Windows program"),
    ("box.zip", lambda: S.zip_of([("scan.pdf.js", b"WScript.Shell")]), "double extension"),
])
def test_attack_files(name, builder, must):
    links, notes, recs, t, lvl = run_in_memory(name, builder())
    assert must in t, t
    assert lvl == "danger" or (name == "redirect.htm" and lvl in ("danger", "warn"))


def test_qr_and_links_inside_office(tmp_path):
    links, *_ = run(tmp_path, "q.docx", S.docx(qr="https://qr-in-docx.top/", hyperlink="https://pay-portal.cfd/x"))
    assert "https://qr-in-docx.top/" in links and "https://pay-portal.cfd/x" in links


def test_nested_depth_and_zip_bomb_limits(tmp_path):
    data = S.zip_of([("x.txt", b"https://deep.top/x")])
    for i in range(8):
        data = S.zip_of([(f"layer{i}.zip", data)])
    links, notes, *_ = run(tmp_path, "nest.zip", data)
    assert any("nested too deeply" in m for _, m in notes)
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.txt", b"0" * (60 * 1024 * 1024))
    links, notes, *_ = run(tmp_path, "bomb.zip", buf.getvalue())
    assert any("zip bomb" in m for _, m in notes)


def test_pdf_polyglot_and_false_pdf_detection():
    z = S.zip_of([("a.pdf", b"%PDF-1.4 tiny")])
    assert inspectors.sniff(z) == "zip"
    assert inspectors.sniff(b"garbage\n%PDF-1.7\n1 0 obj") == "pdf"


def test_schema_addresses_are_not_links(tmp_path):
    links, *_ = run(tmp_path, "v.svg", S.svg_script())
    assert not any("w3.org" in u for u in links)
