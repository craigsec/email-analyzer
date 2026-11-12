"""'Found in' lines must be fully Greek in Greek mode (2.3). Before, they showed e.g. 'page 1: QR Code (rendered page)'."""
import contextlib
import io
import re
from pathlib import Path

import pytest

import i18n
import inspectors
import qr_check as q
import samples_lib as S

ENGLISH_LEFT = re.compile(r"\b(page|rendered|embedded|link|address|loaded|attachment|email body|picture|image|"
                          r"clickable|written|external|redirect|sends|resource|form|document|text|shows|"
                          r"action|automatic|runs|opens|program|file)\b", re.I)
SAMPLES = Path(__file__).parent / "samples"


@pytest.fixture
def greek():
    old = i18n.language()
    i18n.set_language("el")
    yield
    i18n.set_language(old)


def wheres_from(name, data):
    ctx = inspectors.Ctx(None)
    with contextlib.redirect_stdout(io.StringIO()):
        inspectors.analyze(name, data, "", 0, ctx, top=True)
    return [w for _, w in ctx.items]


def all_real_wheres():
    out = []
    for name, data in [("phish.eml", S.phish_eml()), ("phish.msg", S.phish_msg()), ("bec.eml", S.bec_eml()),
                       ("dhl.eml", S.legit_eml()), ("login.html", S.html_login_smuggle()),
                       ("redirect.htm", S.html_obfuscated_redirect()), ("voice.svg", S.svg_script()),
                       ("q.docx", S.docx(qr="https://qr-in-docx.top/", hyperlink="https://pay-portal.cfd/x")),
                       ("remote.docx", S.docx(remote_template="https://office-templates.top/t.dotm")),
                       ("dde.xlsx", S.xlsx_dde())]:
        out += wheres_from(name, data)
    with contextlib.redirect_stdout(io.StringIO()):
        for pdf in ("fake_phish.pdf", "QR_Test_Breaker.pdf", "QR_Test_HardMode.pdf"):
            items, _ = q.extract_from_pdf(str(SAMPLES / pdf), notes=[])
            out += [w for _, w in items]
    return out


def leftover(greek_text):
    without_names = re.sub(r"'[^']*'", "", greek_text)
    return ENGLISH_LEFT.findall(without_names)


def test_every_real_location_is_greek(greek):
    wheres = all_real_wheres()
    assert len(wheres) > 20                     # the samples really produce locations
    bad = {w: i18n.where(w) for w in wheres if leftover(i18n.where(w))}
    assert not bad, bad


@pytest.mark.parametrize("en", [
    "page 2: QR Code (rendered page)", "page 1: clickable link", "page 3: URL written in text",
    "email body: address in the text", "email body: link in email (shows 'Click here')",
    "attachment 'a.zip' > 'b.docx' > link in document", "attachment 'x.docx' > attachedTemplate loaded when the document opens",
    "'r.rtf' > link in RTF text", "link in text", "image: QRCode", "QRCode (picture)", "external workbook link",
    "image loaded from the internet", "external oleObject", "address written in document", "address found in document",
    "QRCode in a picture inside the document", "QRCode in a picture inside the web page",
    "resource loaded by the SVG picture", "form in the web page sends typed data here",
    "automatic redirect in the web page", "script redirect in the email", "script in the web page sends data here",
    "address in the SVG picture", "attachment 'picture in the email body (png)' > image: QRCode",
    "PDF link action", "PDF automatic JavaScript/Launch (runs a program) action",
    "PDF SubmitForm (sends typed data to a website) action", "PDF GoToR (opens another file) action",
    "PDF automatic GoToE (opens an embedded file) action",
])
def test_each_phrase(greek, en):
    assert not leftover(i18n.where(en)), i18n.where(en)


def test_quoted_names_are_never_changed(greek):
    out = i18n.where("attachment 'page 1 link in document.pdf' > page 2: clickable link")
    assert "'page 1 link in document.pdf'" in out
    assert out.startswith("συνημμένο ")


def test_dates_in_greek(greek):
    from datetime import datetime
    when = datetime(2026, 11, 11, 17, 56)
    assert i18n.date(when) == "11 Νοε 2026 17:56"
    assert i18n.date(when, long=True) == "11 Νοεμβρίου 2026, 17:56"


def test_english_mode_is_untouched():
    old = i18n.language()
    i18n.set_language("en")
    try:
        assert i18n.where("page 2: QR Code (rendered page)") == "page 2: QR Code (rendered page)"
    finally:
        i18n.set_language(old)
