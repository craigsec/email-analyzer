"""Verdict accuracy: real-world legitimate QR links vs phishing patterns.
Run offline (no keys), so only the address-based checks are measured."""
import base64
import contextlib
import io
import sys
from pathlib import Path

import pytest

import qr_check as q  # noqa: E402
import report  # noqa: E402

BRANDS = q.load_brands()
OK = {"known", "clean", "info"}


def verdict(text):
    with contextlib.redirect_stdout(io.StringIO()):
        rec = q.check_link(text, ["test"], BRANDS, {}, False, True)
    return report.level_of(rec), rec


b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")  # noqa: E731

LEGIT = [
    # Microsoft 365
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile&state=OpenIdConnect.AuthenticationProperties%3DABC",
    "https://aka.ms/mfasetup",
    "https://mysignins.microsoft.com/security-info",
    "https://teams.microsoft.com/l/meetup-join/19%3ameeting_NjQ4ZTI5%40thread.v2/0?context=%7b%22Tid%22%3a%2272f988bf%22%2c%22Oid%22%3a%22abc%22%7d",
    "https://forms.office.com/r/AbCdEf12Gh",
    "https://outlook.office.com/mail/inbox",
    "https://account.microsoft.com/security",
    # Microsoft Safe Links wrapping a real bank link (what you get copying from Outlook)
    "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.eurobank.gr%2Fel%2Fidiotes&data=05%7C02%7Cuser%40corp.com%7Cabc%7C0%7C0%7C638&sdata=Xyz%3D&reserved=0",
    # Greek banks
    "https://www.eurobank.gr/el/idiotes/logariasmoi", "https://ebanking.eurobank.gr/",
    "https://www.nbg.gr/el/idiwtes", "https://ibank.nbg.gr/",
    "https://www.piraeusbank.gr/el/idiwtes", "https://www.winbank.gr/",
    "https://www.alpha.gr/el/idiotes", "https://myalpha.alpha.gr/",
    # everyday legit QR targets
    "https://www.google.com/maps/place/Kifisia/@38.07,23.81,14z",
    "https://maps.app.goo.gl/AbCdEfGh123",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "https://youtu.be/dQw4w9WgXcQ",
    "https://wa.me/302101234567",
    "https://www.linkedin.com/company/example-maritime/",
    "https://www.maersk.com/tracking/123456789",
    "https://www.msc.com/en/track-a-shipment?agencyPath=grc",
    "https://www.dhl.com/gr-en/home/tracking.html?tracking-id=1234567890",
    "https://www.fedex.com/fedextrack/?trknbr=123456789012",
    "https://www.navarino.gr/", "https://www.navtor.com/support",
    "https://na3.docusign.net/Signing/EmailStart.aspx?a=8a1b2c3d-1111-2222-3333-444455556666&etti=24&acct=abc",
    "https://www.paypal.com/paypalme/example",
    "https://www.gov.gr/", "https://www1.aade.gr/taxisnet/",
    "https://www.nbg.gr/en/individuals?utm_source=qr&utm_medium=print&utm_campaign=autumn",
    "HTTPS://WWW.ALPHA.GR/",
    "https://shop.example.com/p?id=dGhpcyBpcyBqdXN0IHRleHQgbm8gbGluaw",
    "https://example.com/download/report.zip",
    # non-link QR content that is normal
    "BEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nORG:Example Maritime\nURL:https://www.navtor.com\nEND:VCARD",
    "tel:+302101234567", "mailto:it@example.com", "Plain text note",
]

PHISH = [
    "https://eurobank-gr.secure-login.top/auth",
    "https://www.eurobanks.gr/login",
    "https://eur0bank.gr/login",
    "https://eurobank.gr-login.com/",
    "https://eurobank.gr.verify-account.cfd/",
    "https://piraeus-bank.gr/winbank",
    "https://piraeusbnak.gr/winbank",
    "https://alph\u03b1.gr/login",                       # Greek alpha
    "https://www.\u0435urobank.gr/login",                 # Cyrillic e
    "https://xn--eurbank-r1a.gr/",
    "https://microsoft-365-verify.com/login",
    "https://login-microsoftonline.com.ru/common",
    "https://login.microsoftonline.com.session-renew.icu/x",
    "https://office365-securelogin.web.app/",
    "https://m365-auth.secure-team.workers.dev/",
    "https://sharepoint-docs-view.top/file",
    "https://eurobank.gr@185.220.101.44/login",
    "http://3115156780/eurobank",
    "http://0xb9.0xdc.0x65.0x2c/nbg",
    "https://pay-portal.cfd\\@www.eurobank.gr/login",
    "https://www.google.com/url?q=https%3A%2F%2Fm365-mfa-verify.sbs%2Fauth",
    "https://www.google.com/amp/s/m365-verify.icu/login",
    "https://redirect.trackmail.example/r?d=" + b64("https://m365-signin.cfd/auth"),
    "https://www.bing.com/ck/a?!&&p=abc&u=a1" + b64("https://outlook-verify.top/") + "&ntb=1",
    "https://northwind.com.remit-portal.top/inv?r=" + b64("uid=c.test@corp.example"),
    "data:text/html;base64," + base64.b64encode(b"<form action='https://x.top'>password</form>").decode(),
    "javascript:alert(1)",
    "https://www.\u202egr.knaborue\u202c.top/",          # right-to-left override spoof
    "https://euro\u200bbank.gr/login",                    # zero-width space
]

SUSPICIOUS_OR_WORSE = [
    "https://bit.ly/3xQmR7t", "https://qrco.de/bfXyZ1",
    "https://pub-abc123.r2.dev/index.html",
    "https://ipfs.io/ipfs/QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o",
    "WIFI:T:WPA;S:Free-Guest;P:x;;",
]

# one weak signal: shown as LOW RISK with its reason, but not enough alone to call it suspicious.
# Together with other signals (unverified sender, scam wording...) the score still crosses the line.
WEAK_SIGNAL_ONLY = [
    "https://docs.google.com/forms/d/e/1FAIpQLSc123/viewform",
    "https://contoso-my.sharepoint.com/:b:/g/personal/x/abc",
    "https://1drv.ms/b/s!AbCdEf",
    "http://nasa.gov",
    "https://cablestore.shop/orders/5521",
]


@pytest.mark.parametrize("url", LEGIT)
def test_legit_not_flagged(url):
    lv, rec = verdict(url)
    bad = [f["detail"] for f in rec.get("findings", []) if f["level"] in ("HIGH", "MEDIUM")]
    assert lv in OK, f"{lv}: {bad}"


@pytest.mark.parametrize("url", PHISH)
def test_phish_is_dangerous(url):
    lv, rec = verdict(url)
    assert lv == "danger", f"{lv}: {[f['detail'] for f in rec.get('findings', [])]}"


@pytest.mark.parametrize("url", WEAK_SIGNAL_ONLY)
def test_single_weak_signal_is_low_risk_not_suspicious(url):
    lv, rec = verdict(url)
    assert lv == "minor", f"{lv}: {[f['detail'] for f in rec.get('findings', [])]}"
    assert 0 < rec["score"] < q.SUSPICIOUS_AT and any(f["level"] == "LOW" for f in rec["findings"])


@pytest.mark.parametrize("url", SUSPICIOUS_OR_WORSE)
def test_needs_a_look(url):
    lv, rec = verdict(url)
    assert lv in ("warn", "danger"), f"{lv}: {[f['detail'] for f in rec.get('findings', [])]}"
