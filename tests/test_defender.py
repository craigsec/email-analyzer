"""When Microsoft Defender (or Windows) will not let us read a file (2.3).
Real behaviour, measured on a company PC in Nov 2026 with the harmless DDE sample: Windows error 5
("access denied") at once, file removed by Defender about 6 seconds later. Everything here is simulated:
no real blocked file is needed, so these tests pass on any PC."""
from pathlib import Path

import pytest

import i18n
import inspectors as I
import report


def fake_sleep_then(action):
    calls = []

    def sleep(_):
        calls.append(1)
        if len(calls) == 2:
            action()
    return sleep, calls


def test_access_denied_then_removed_is_dangerous(tmp_path):
    f = tmp_path / "invoice.docx"
    f.write_bytes(b"x")
    sleep, _ = fake_sleep_then(f.unlink)          # Defender removes it after a moment
    lvl, text = I.read_refused(f, open_error=lambda p: 5, sleep=sleep)
    assert lvl == I.HIGH and text == I.DEFENDER_REMOVED


def test_virus_code_is_dangerous_without_waiting(tmp_path):
    f = tmp_path / "a.docx"
    f.write_bytes(b"x")
    sleep, calls = fake_sleep_then(lambda: None)
    for code in (I.ERROR_VIRUS_INFECTED, I.ERROR_VIRUS_DELETED):
        assert I.read_refused(f, open_error=lambda p, c=code: c, sleep=sleep) == (I.HIGH, I.DEFENDER_VIRUS)
    assert not calls


def test_access_denied_that_stays_is_medium_not_dangerous(tmp_path):
    # could be Defender, could be a folder without rights: say so honestly, do not claim malware
    f = tmp_path / "a.docx"
    f.write_bytes(b"x")
    sleep, calls = fake_sleep_then(lambda: None)
    assert I.read_refused(f, open_error=lambda p: 5, sleep=sleep) == (I.MED, I.READ_REFUSED)
    assert len(calls) == I.BLOCK_WAIT * 2           # it did wait the whole time (in 0.5 s steps)


def test_file_open_in_another_program_is_not_a_warning(tmp_path):
    f = tmp_path / "a.xlsx"
    f.write_bytes(b"x")
    with pytest.raises(RuntimeError, match="open in another program"):
        I.read_refused(f, open_error=lambda p: I.ERROR_SHARING_VIOLATION)


def test_readable_after_all_means_try_again(tmp_path):
    f = tmp_path / "a.docx"
    f.write_bytes(b"x")
    assert I.read_refused(f, open_error=lambda p: 0) is None


def test_whole_check_turns_red_when_defender_removes_the_file(tmp_path, monkeypatch):
    f = tmp_path / "Payment advice.docx"
    f.write_bytes(b"PK")
    real_read = Path.read_bytes

    def blocked(self):
        if self == f:
            raise PermissionError(13, "Permission denied")
        return real_read(self)
    monkeypatch.setattr(Path, "read_bytes", blocked)
    monkeypatch.setattr(I, "windows_open_error", lambda p: 5)
    monkeypatch.setattr("time.sleep", lambda s: f.unlink() if f.exists() else None)
    items, notes = I.collect_file(str(f))
    assert items == [] and notes == [(I.HIGH, I.DEFENDER_REMOVED)]
    assert report.file_level(notes, []) == "danger"


def test_whole_check_is_suspicious_when_reading_is_refused(tmp_path, monkeypatch):
    f = tmp_path / "a.docx"
    f.write_bytes(b"PK")
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(PermissionError(13, "denied")))
    monkeypatch.setattr(I, "windows_open_error", lambda p: 5)
    monkeypatch.setattr("time.sleep", lambda s: None)
    items, notes = I.collect_file(str(f))
    assert notes == [(I.MED, I.READ_REFUSED)]
    assert report.file_level(notes, []) == "warn"     # never "no red flags" for a file that was not checked


def test_file_gone_before_reading(tmp_path):
    with pytest.raises(RuntimeError, match="no longer exists"):
        I.collect_file(str(tmp_path / "vanished.docx"))


def test_defender_messages_have_greek():
    msgs = [I.DEFENDER_REMOVED, I.DEFENDER_VIRUS, I.READ_REFUSED, I.FILE_IN_USE, I.FILE_GONE]
    assert i18n.untranslated(msgs) == []
