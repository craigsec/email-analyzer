"""v2.1: nothing goes online without opt-in, the weighted risk score, pasted-email input."""
import contextlib
import io
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest
import requests

import qr_check as q  # noqa: E402
import report  # noqa: E402

BRANDS = q.load_brands()


def check(text, keys=None, scan=False):
    with contextlib.redirect_stdout(io.StringIO()):
        return q.check_link(text, ["test"], BRANDS, keys or {}, scan, True)


def run_file(tmp_path, name, data, pasted=False):
    f = tmp_path / name
    f.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    with contextlib.redirect_stdout(io.StringIO()):
        links, notes = q.collect(str(f), pasted=pasted)
        recs = list(q.check_links(links, BRANDS, {}, False, True))
    return links, notes, recs, " ".join(m for _, m in notes)


def mail(frm, subject, body, auth="dmarc=pass", html=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "user@corp.example", subject
    m["Authentication-Results"] = f"mx.corp.example; spf=pass; {auth} header.from={frm.split('@')[-1].strip('>')}"
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m.as_bytes()


@pytest.fixture
def wire(monkeypatch):
    """Record every attempt to reach the internet and refuse it."""
    calls = []

    def refuse(method, url, **kw):
        calls.append(url)
        raise requests.ConnectionError("no network in tests")
    for name in ("request",):
        monkeypatch.setattr(requests, name, refuse)
    monkeypatch.setattr(requests, "get", lambda url, **kw: refuse("GET", url))
    monkeypatch.setattr(requests, "post", lambda url, **kw: refuse("POST", url))
    q._RDAP_CACHE.clear()
    q._VT_CACHE.clear()
    q.set_network(False, False)
    yield calls
    q.set_network(False, False)


# ---------------------------------------------------------------- offline
def test_offline_makes_no_network_calls_even_with_keys(wire, tmp_path):
    keys = {"VT_API_KEY": "x", "URLSCAN_API_KEY": "y"}
    rec = check("https://brand-new-domain-example.com/login", keys, scan=True)
    run_file(tmp_path, "m.eml", mail("Bob <bob@some-unknown-sender.com>", "Hi", "see https://another-unknown.net/x"))
    assert wire == []
    assert any("online lookups are off" in f["detail"] for f in rec["findings"])
    assert "virustotal_domain" not in rec and "urlscan" not in rec


def test_lookups_opt_in_only_sends_domain_and_live_stays_off(wire):
    q.set_network(lookups=True, live=False)
    check("https://brand-new-domain-example.com/login?secret=abc", {"VT_API_KEY": "x", "URLSCAN_API_KEY": "y"}, scan=True)
    assert wire and all("urlscan" not in u for u in wire)
    assert all("secret" not in u and "/login" not in u for u in wire)      # the full link never leaves


def test_live_needs_its_own_switch(wire):
    q.set_network(lookups=False, live=True)
    check("https://brand-new-domain-example.com/x", {"URLSCAN_API_KEY": "y"}, scan=True)
    assert wire and all("urlscan.io" in u for u in wire)


def test_network_context_restores_policy(wire):
    with q.network(lookups=True):
        assert q.network_allowed("lookups")
    assert not q.network_allowed("lookups") and not q.network_allowed("live")


# ------------------------------------------------------------------ score
def test_score_is_sum_of_parts_and_explained():
    rec = check("http://bit.ly/abc")
    assert rec["score"] == q.WEIGHTS["MEDIUM"] + q.WEIGHTS["LOW"] == sum(p["points"] for p in rec["score_parts"])
    assert report.level_of(rec) == "warn"


def test_weak_signals_add_up():
    f = [(q.LOW, "a"), (q.LOW, "b")]
    assert q.overall(f).startswith("LOW RISK")
    assert q.overall(f + [(q.LOW, "c")]).startswith("SUSPICIOUS")
    assert q.overall([(q.MED, "a"), (q.MED, "b"), (q.MED, "c")]).startswith("LIKELY")
    assert q.overall([(q.HIGH, "a")]).startswith("LIKELY")
    assert q.score_findings([(q.LOW, "same"), (q.LOW, "same")])[0] == q.WEIGHTS["LOW"]   # counted once
    assert q.score_findings([(q.HIGH, "a"), (q.HIGH, "b")])[0] == 100                     # capped


def test_file_score_counts_notes_plus_worst_link_only(tmp_path):
    html = "".join(f"<a href='http://site{i}.example.org/'>x</a>" for i in range(30))
    links, notes, recs, _ = run_file(tmp_path, "many.eml", mail("News <n@newsletter-example.org>", "News", "x", html=html))
    assert len(recs) == 30
    score, parts = report.file_score(notes, recs)
    assert score == q.WEIGHTS["LOW"] and report.file_level(notes, recs) == "minor"     # 30 http links != alarm


LEGIT_MAILS = {
    "gmail supplier": mail("Giorgos Supplies <gsupplies@gmail.com>", "Invoice 2231", "Please find attached invoice 2231."),
    "no dmarc + http": mail("Sales <sales@aegean-chandlers.gr>", "Price list", "See http://www.aegean-chandlers.gr/prices",
                            auth="dmarc=none"),
    "port agent in Piraeus": mail("Nikos <n.papas@portagent-piraeus.gr>", "Port DA", "x",
                                  html="<a href='https://portagent-my.sharepoint.com/:b:/g/personal/n/E1'>DA.pdf</a>"),
    "newsletter tracker": mail("News <news@marineinsight.com>", "Weekly", "x",
                               html="<a href='https://marineinsight.com/unsub?u=user@corp.example'>Unsubscribe</a>"),
    "gift card promo": mail("Shop <news@public.gr>", "Offers", "Give a gift card this Christmas https://www.public.gr/gc"),
}


@pytest.mark.parametrize("name", LEGIT_MAILS)
def test_ordinary_business_mail_is_not_suspicious(tmp_path, name):
    links, notes, recs, t = run_file(tmp_path, "m.eml", LEGIT_MAILS[name])
    assert report.file_level(notes, recs) in ("minor", "known", "clean", "info"), report.score_lines(notes, recs)


def test_weak_signals_plus_real_one_still_dangerous(tmp_path):
    m = mail("HR <hr@corp-example.com>", "Salary review", "x", auth="dmarc=fail",
             html="<a href='https://hr-docs-my.sharepoint.com/:x:/g/personal/x/E1'>Review.xlsx</a>")
    links, notes, recs, t = run_file(tmp_path, "m.eml", m)
    assert report.file_level(notes, recs) == "danger"


# ------------------------------------------------- detection fixes found by samples
def test_email_address_in_query_is_not_a_hidden_website():
    rec = check("https://inv.example.org/view?u=c.user@corp.example")
    assert "hidden_destinations" not in rec


def test_file_name_as_link_text_is_not_a_lying_link(tmp_path):
    html = ("<a href='https://files.example.org/x'>DA.pdf</a> <a href='https://files.example.org/y'>report.zip</a>"
            "<a href='https://evil-example.top/z'>www.eurobank.gr</a>")
    links, notes, recs, t = run_file(tmp_path, "m.eml", mail("A <a@example.org>", "s", "x", html=html))
    assert "shows 'da.pdf'" not in t.lower() and "shows 'report.zip'" not in t.lower()
    assert "shows 'www.eurobank.gr' but really goes to 'evil-example.top'" in t


def test_disguised_brand_word_inside_longer_name():
    assert report.level_of(check("https://micros0ft-login.com/owa")) == "danger"
    assert report.level_of(check("https://0utlook-webmail.net/")) == "danger"
    assert report.level_of(check("https://scout-lookup.com/")) in ("clean", "known")     # two innocent words
    assert report.level_of(check("https://www.portagent-piraeus.gr/")) in ("clean", "known")
    assert report.level_of(check("https://piraeus-bank.gr/winbank")) == "danger"


# ------------------------------------------------------------------ paste
def test_pasted_source_with_headers_is_a_full_email_check(tmp_path):
    raw = mail("Eurobank Security <alerts@eurobank-secure.top>", "Verify", "Your mailbox will expire, verify your account "
               "https://eurobank-secure.top/login", auth="dmarc=fail").decode()
    links, notes, recs, t = run_file(tmp_path, "p.txt", "\n\n  " + raw, pasted=True)
    assert "could NOT be verified" in t and "calls themselves 'Eurobank Security'" in t
    assert report.file_level(notes, recs) == "danger"


def test_pasted_body_only_checks_wording_links_and_link_text(tmp_path):
    body = ("Dear customer,\nyour password will expire today. Please verify your account here:\n"
            "www.eurobank.gr/login <https://eurobank-gr.secure-login.top/auth>\nΕυχαριστούμε")
    links, notes, recs, t = run_file(tmp_path, "p.txt", body, pasted=True)
    assert "no email headers" in t and "asks you to verify your account" in t
    assert "shows 'www.eurobank.gr' but really goes to 'eurobank-gr.secure-login.top'" in t
    assert "https://eurobank-gr.secure-login.top/auth" in links
    assert report.file_level(notes, recs) == "danger"


def test_pasted_html_body_and_harmless_text(tmp_path):
    links, notes, recs, t = run_file(tmp_path, "p.txt", "<html><body><a href='https://x-login.cfd/a'>www.nbg.gr</a></body></html>",
                                     pasted=True)
    assert "shows 'www.nbg.gr' but really goes to" in t and "https://x-login.cfd/a" in links
    links, notes, recs, t = run_file(tmp_path, "p2.txt", "Good day,\nsee you at the meeting tomorrow.\nRegards", pasted=True)
    assert report.file_level(notes, recs) in ("clean", "info") and report.file_score(notes, recs)[0] == 0


def test_report_shows_score(tmp_path):
    links, notes, recs, t = run_file(tmp_path, "m.eml", LEGIT_MAILS["no dmarc + http"])
    page = report.build_html([(str(tmp_path / "m.eml"), notes, recs)], "offline check", "tester", BRANDS)
    assert "risk score 20/100" in page and "LOW RISK" in page
    assert "risk score 20/100" in report.summary_text([(str(tmp_path / "m.eml"), notes, recs)], "offline check", "tester")


# ------------------------------------- found on a real reported email (11 Nov 2026)
SL = "https://eur06.safelinks.protection.outlook.com/?url={}&amp;data=05%7C02%7Cuser%40corp.example&amp;reserved=0"


def test_safelinks_rewriting_is_not_a_lying_link(tmp_path):
    html = f"<a href='{SL.format('http%3A%2F%2Fwww.omikron.gr%2F')}'>www.omikron.gr</a>"
    links, notes, recs, t = run_file(tmp_path, "m.eml", mail("A <a@omikron.gr>", "s", "x", html=html))
    assert "really goes to" not in t
    assert report.file_level(notes, recs) in ("minor", "clean", "known")
    html = f"<a href='{SL.format('https%3A%2F%2Fevil-example.top%2Fx')}'>www.omikron.gr</a>"
    links, notes, recs, t = run_file(tmp_path, "m2.eml", mail("A <a@omikron.gr>", "s", "x", html=html))
    assert "shows 'www.omikron.gr' but really goes to 'evil-example.top'" in t


def test_file_named_link_that_opens_a_web_page(tmp_path):
    lure = SL.format("https%3A%2F%2Fritecode.ir%2Fzxc%2Fdocument-access-v6.html")
    html = (f"<a href='{lure}'>Omikron\r\nElectronics Ltd #066774 - Quote.pdf</a>"
            "<a href='https://www.example.org/files/Brochure.pdf'>Brochure.pdf</a>"
            "<a href='https://contoso-my.sharepoint.com/:b:/g/personal/x/E1'>Offer.pdf</a>")
    links, notes, recs, t = run_file(tmp_path, "m.eml", mail("Sales <sales@omikron.gr>", "Quote", "x", html=html))
    assert "labelled as a file" in t and "opens a web page on 'ritecode.ir'" in t
    assert t.count("labelled as a file") == 1                      # real .pdf link and SharePoint link not flagged
    assert report.file_level(notes, recs) in ("warn", "danger")
