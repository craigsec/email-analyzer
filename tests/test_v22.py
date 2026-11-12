"""v2.2: Greek/English, shared brand list, sender-added 'verified' headers, Outlook pickup, what-to-do lines."""
import ast
import contextlib
import io
import subprocess
from email.message import EmailMessage
from pathlib import Path

import pytest

import appconfig
import email_check
import i18n
import outlook_grab
import qr_check as q
import report
import samples_lib as S

from conftest import APP_DIR as ROOT
BRANDS = q.load_brands()


def run_bytes(tmp_path, name, data):
    f = tmp_path / name
    f.write_bytes(data)
    with contextlib.redirect_stdout(io.StringIO()):
        links, notes = q.collect(str(f))
        recs = list(q.check_links(links, BRANDS, {}, False, True))
    return f, notes, recs


@pytest.fixture
def greek():
    i18n.set_language("el")
    yield
    i18n.set_language(None)


# ------------------------------------------------------------------ language
def test_every_interface_text_has_greek():
    """Every fixed T("...") text in the app and the report must have a Greek entry."""
    missing = []
    for fname in ("qr_gui.pyw", "report.py"):
        for node in ast.walk(ast.parse((ROOT / fname).read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "T" and node.args:
                stack = [node.args[0]]
                while stack:
                    a = stack.pop()
                    if isinstance(a, ast.IfExp):
                        stack += [a.body, a.orelse]
                    elif isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value not in i18n.UI_EL:
                        missing.append(a.value)
    assert not missing, missing


def test_every_sample_warning_has_greek(tmp_path):
    msgs = set()
    samples = {"p.eml": S.phish_eml(), "b.eml": S.bec_eml(), "l.eml": S.legit_eml(), "p.msg": S.phish_msg(),
               "m.docm": S.docx(macro=True), "login.html": S.html_login_smuggle(), "v.svg": S.svg_script(),
               "disk.iso": S.iso_of([("Invoice.exe", S.FAKE_EXE)]), "locked.zip": S.zip_of([("a.pdf", b"%PDF-1.4")], encrypted=True)}
    for name, data in samples.items():
        _, notes, recs = run_bytes(tmp_path, name, data)
        msgs |= {report.sentence(m) for _, m in notes} | {r["verdict"] for r in report.flatten(recs)}
        msgs |= {f["detail"] for r in report.flatten(recs) for f in r["findings"]}
    assert len(msgs) > 60
    assert i18n.untranslated(msgs) == []


def test_english_is_untouched_and_unknown_text_is_never_lost(greek):
    assert i18n.msg("some brand new warning nobody translated") == "some brand new warning nobody translated"
    assert i18n.msg("Plain http, not https. No real bank login page uses this.").startswith("Απλό http")
    out = i18n.msg("attachment 'a.zip' > 'b.html' is a web page sent as a file. Opening it runs in your browser; businesses rarely send these.")
    assert "'b.html'" in out and "ιστοσελίδα" in out
    i18n.set_language("en")
    assert i18n.msg("Plain http, not https. No real bank login page uses this.").startswith("Plain http")
    assert i18n.T("Browse files") == "Browse files"


def test_greek_report_and_summary(tmp_path, greek):
    f, notes, recs = run_bytes(tmp_path, "p.eml", S.phish_eml())
    page = report.build_html([(str(f), notes, recs)], "offline check", "tester", BRANDS)
    text = report.summary_text([(str(f), notes, recs)], "offline check", "tester")
    for must in ("ΕΠΙΚΙΝΔΥΝΟ", "Τι να κάνετε:", "Μην ανοίξετε τίποτα"):
        assert must in page and must in text
    assert "<html lang='el'>" in page and "eurobank-alerts[.]top" in text      # still defanged


def test_what_to_do_line_in_english_report(tmp_path):
    f, notes, recs = run_bytes(tmp_path, "p.eml", S.phish_eml())
    page = report.build_html([(str(f), notes, recs)], "offline check", "tester", BRANDS)
    assert "What to do:" in page and "Report it to ICT" in page
    assert "What to do:" in report.summary_text([(str(f), notes, recs)], "offline check", "tester")
    assert set(i18n.ACTIONS) == {"danger", "warn", "minor", "known", "clean", "info"}


# ------------------------------------------------------------ shared brand list
@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(appconfig, "FILE", tmp_path / "config.txt")
    monkeypatch.setattr(appconfig, "CACHE", tmp_path / "banks.shared-cache.txt")
    return tmp_path


def test_shared_brand_list_then_cached_copy_then_local(cfg):
    share = cfg / "share"
    share.mkdir()
    (share / "banks.txt").write_text("Shared Bank | sharedbank.example | sharedbank\n", encoding="utf-8")
    appconfig.save({"SHARED_BANK_LIST": str(share / "banks.txt")})
    assert any(b["name"] == "Shared Bank" for b in q.load_brands()) and appconfig.brand_list_state()[0] == "shared"
    (share / "banks.txt").unlink()                                   # laptop away from the office
    assert any(b["name"] == "Shared Bank" for b in q.load_brands()) and appconfig.brand_list_state()[0] == "cached"
    (cfg / "banks.shared-cache.txt").unlink()
    assert any(b["name"] == "Eurobank" for b in q.load_brands()) and appconfig.brand_list_state()[0] == "local-fallback"
    appconfig.save({"SHARED_BANK_LIST": ""})
    assert any(b["name"] == "Eurobank" for b in q.load_brands()) and appconfig.brand_list_state()[0] == "local"


def test_shared_list_must_look_like_a_brand_list(cfg):
    bad = cfg / "notalist.txt"
    bad.write_text("hello", encoding="utf-8")
    appconfig.save({"SHARED_BANK_LIST": str(bad)})
    assert any(b["name"] == "Eurobank" for b in q.load_brands())      # falls back, never an empty list


def test_config_save_keeps_comments_and_other_lines(cfg):
    (cfg / "config.txt").write_text("# my comment\nORG_NAME=Example ICT\nLANGUAGE=auto\n", encoding="utf-8")
    appconfig.save({"LANGUAGE": "el"})
    text = (cfg / "config.txt").read_text(encoding="utf-8")
    assert "# my comment" in text and "ORG_NAME=Example ICT" in text and "LANGUAGE=el" in text


# ------------------------------------------------------- sender-added "verified"
def _mail(headers):
    m = EmailMessage()
    for k, v in headers:
        m[k] = v
    m["From"], m["Subject"] = "Bank <info@some-bank.example>", "hello"
    m.set_content("hello")
    return m


PASS = "spf=pass; dkim=pass; dmarc=pass header.from=some-bank.example"
FAIL = "spf=fail; dmarc=fail header.from=some-bank.example"


def test_receiving_server_result_is_used_sender_added_one_is_not(cfg, tmp_path):
    genuine = _mail([("Authentication-Results", FAIL), ("Received", "from a by mx.corp"), ("Authentication-Results", PASS)])
    assert email_check.parse_auth(genuine)["dmarc"] == "fail"          # the topmost one counts, not the sender's
    injected = _mail([("Received", "from b by mx.corp"), ("Received", "from a by b"), ("Authentication-Results", PASS)])
    assert email_check.parse_auth(injected) == {"untrusted": "it sits below every delivery line, where only the sender could have put it"}
    _, notes, recs = run_bytes(tmp_path, "i.eml", bytes(injected))
    t = " ".join(m for _, m in notes)
    assert "was ignored" in t and "sender verified: the email really came" not in t


def test_trusted_authserv_setting(cfg):
    appconfig.save({"TRUSTED_AUTHSERV": "mx.corp.example"})
    m = _mail([("Authentication-Results", "evil.example; dmarc=pass"), ("Received", "from a by b"),
               ("Authentication-Results", "mx.corp.example; dmarc=fail")])
    assert email_check.parse_auth(m)["dmarc"] == "fail"
    m2 = _mail([("Authentication-Results", "evil.example; dmarc=pass"), ("Received", "from a by b")])
    assert "untrusted" in email_check.parse_auth(m2)


# ---------------------------------------------------------------- outlook
def test_outlook_output_is_parsed_strictly(tmp_path):
    (tmp_path / "Outlook-email-1-01.msg").write_bytes(b"x")
    assert outlook_grab.parse_output("OK:Outlook-email-1-01.msg\n", tmp_path) == [str(tmp_path / "Outlook-email-1-01.msg")]
    # a path outside the folder, or a file type other than .msg, is never accepted
    with pytest.raises(outlook_grab.OutlookError):
        outlook_grab.parse_output("OK:..\\..\\evil.exe\nOK:missing.msg\n", tmp_path)
    with pytest.raises(outlook_grab.OutlookError) as e:
        outlook_grab.parse_output("ERR:NOTHING_SELECTED\n", tmp_path)
    assert e.value.code == "NOTHING_SELECTED" and "selected" in e.value.reason("en") and e.value.reason("el") != e.value.reason("en")


def test_outlook_grab_runs_one_fixed_command(tmp_path, monkeypatch):
    monkeypatch.setattr(outlook_grab, "is_windows", lambda: True)
    seen = {}

    def fake_run(cmd, env=None, **kw):
        seen["cmd"], seen["env"] = cmd, env
        (Path(env["EA_DIR"]) / f"{env['EA_PREFIX']}-01.msg").write_bytes(b"x")
        return subprocess.CompletedProcess(cmd, 0, stdout=f"OK:{env['EA_PREFIX']}-01.msg\n", stderr="")
    files = outlook_grab.grab_selected(tmp_path / "o", run=fake_run)
    assert len(files) == 1 and files[0].endswith("-01.msg")
    assert seen["cmd"][0] == "powershell.exe" and seen["cmd"][-1] == outlook_grab.SCRIPT     # nothing user-supplied in the command
    assert str(tmp_path) not in outlook_grab.SCRIPT and seen["env"]["EA_DIR"] == str(tmp_path / "o")

    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)
    with pytest.raises(outlook_grab.OutlookError) as e:
        outlook_grab.grab_selected(tmp_path / "o", run=boom)
    assert e.value.code == "TIMEOUT"


def test_outlook_grab_refuses_outside_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(outlook_grab, "is_windows", lambda: False)
    with pytest.raises(outlook_grab.OutlookError) as e:
        outlook_grab.grab_selected(tmp_path)
    assert e.value.code == "NOT_WINDOWS"
