"""Engine unit tests: unwrapping, tenants, block lists, parsing helpers, redaction, payloads."""
import base64
import contextlib
import io
import sys
from pathlib import Path
from urllib.parse import quote

import qr_check as q  # noqa: E402
import report  # noqa: E402

BRANDS = q.load_brands()


def check(text, brands=BRANDS):
    with contextlib.redirect_stdout(io.StringIO()):
        return q.check_link(text, ["test"], brands, {}, False, True)


def test_safelinks_wrapping_phish_is_dangerous():
    r = check("https://eur01.safelinks.protection.outlook.com/?url=" + quote("https://eurobank-gr.verify.top/x", safe="")
              + "&data=05%7C02&reserved=0")
    assert report.level_of(r) == "danger"
    assert r["checked_url"] == "https://eurobank-gr.verify.top/x"


def test_proofpoint_v3_and_v2_unwrap():
    r3 = check("https://urldefense.com/v3/__https://m365-login.top/auth__;!!ABC123$")
    assert r3["checked_url"] == "https://m365-login.top/auth" and report.level_of(r3) == "danger"
    r2 = check("https://urldefense.proofpoint.com/v2/url?u=https-3A__m365-2Dlogin.top_auth&d=DwMF&c=x")
    assert r2["checked_url"] == "https://m365-login.top/auth" and report.level_of(r2) == "danger"


def test_own_sharepoint_tenant_trusted_other_tenants_not():
    brands = BRANDS + [{"name": "Our company", "domains": ["ourco-my.sharepoint.com", "ourco.sharepoint.com"],
                        "keywords": []}]
    assert report.level_of(check("https://ourco-my.sharepoint.com/:b:/g/personal/a/b", brands)) == "known"
    assert report.level_of(check("https://evilco-my.sharepoint.com/:b:/g/personal/a/b", brands)) == "minor"   # weak signal on its own


def test_block_list_uses_real_destinations_and_skips_platforms():
    recs = [check("https://eur01.safelinks.protection.outlook.com/?url=" + quote("https://evil-pay.top/x", safe="")),
            check("https://www.google.com/url?q=https%3A%2F%2Fm365-mfa.sbs%2F"),
            check("https://pub-abc.r2.dev/login"),
            check("https://bit.ly/abc"),
            check("http://3115156780/x"),
            check("https://www.eurobank.gr/")]
    domains, urls = report.block_lists([("f.pdf", [], recs)], BRANDS)
    assert domains == ["evil-pay.top", "m365-mfa.sbs", "pub-abc.r2.dev", "185.173.133.44"], domains
    assert "https://www.eurobank.gr/" not in urls


def test_numeric_ip_forms():
    assert q.numeric_ip("3115156780") == "185.173.133.44"
    assert q.numeric_ip("0xb9.0xdc.0x65.0x2c") == "185.220.101.44"
    assert q.numeric_ip("0271.0.0.1") == "185.0.0.1"
    assert q.numeric_ip("185.220.101.44") == "185.220.101.44"
    for not_ip in ("abc.de", "cafe.be", "example.com", "1.2.3.4.5", "99999999999", ""):
        assert q.numeric_ip(not_ip) is None


def test_browser_parse_backslash_and_unicode():
    url, parts, host, notes, uni = q.browser_parse("https://evil.top\\@www.eurobank.gr/x")
    assert host == "evil.top" and "backslash" in notes
    _, _, host, _, uni = q.browser_parse("https://www.\u0435urobank.gr/")
    assert uni and host.startswith("www.xn--")


def test_email_detection_and_redaction_roundtrip():
    tok = base64.urlsafe_b64encode(b"uid=v.ictim@corp.example&x=1").decode().rstrip("=")
    for url in ("https://x.top/?e=v.ictim%40corp.example", "https://x.top/a#" + tok, "https://x.top/?u=v.ictim@corp.example"):
        found = q.find_emails(url)
        assert "v.ictim@corp.example" in found
        red = q.redact(url, found)
        assert "v.ictim" not in red and "v.ictim" not in str(q.find_emails(red))
        assert q.find_emails(red), "dummy address should replace the real one"


def test_payload_types():
    lv = lambda t: [x[0] for x in q.classify_payload(t)[0]]  # noqa: E731
    assert lv("WIFI:T:WPA;S:Cafe\\;Guest;P:x;;") == ["MEDIUM"]
    assert "Cafe\\;Guest" in q.classify_payload("WIFI:T:WPA;S:Cafe\\;Guest;P:x;;")[0][0][1]
    assert lv("tel:+302100000000") == ["INFO"]
    assert lv("SMSTO:+30690000:hi") == ["MEDIUM"]
    assert lv("intent://scan/#Intent;end") == ["HIGH"]
    assert lv("javascript:alert(1)") == ["HIGH"]
    f, urls = q.classify_payload("BEGIN:VCARD\nURL:https://a.example\nEND:VCARD")
    assert urls == ["https://a.example"] and f[0][0] == "INFO"


def test_defang():
    d = report.defang("visit https://evil.top/x and evil.top or mail a.b@c.top")
    assert "https://" not in d and "evil.top" not in d and "@c.top" not in d
    assert "hxxps://evil[.]top/x" in d and "a[.]b[@]c[.]top" in d
    assert report.defang("Domain ends in .top, a TLD") == "Domain ends in .top, a TLD"


def test_block_list_never_suggests_legit_sites():
    recs = [check("http://nasa.gov"), check("https://bit.ly/x"), check("https://docs.google.com/forms/d/x/viewform"),
            check("https://news.example-shipping.com/track?e=user%40corp.example"),
            check("https://www.google.com/url?q=https%3A%2F%2Fwww.eurobank.gr%2F")]
    domains, _ = report.block_lists([("f.pdf", [], recs)], BRANDS)
    assert domains == [], domains


def test_email_alone_is_minor_with_other_flags_dangerous():
    assert report.level_of(check("https://news.example-shipping.com/track?e=user%40corp.example")) == "minor"
    assert report.level_of(check("https://login-check.top/track?e=user%40corp.example")) == "danger"
