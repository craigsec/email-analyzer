"""Drag and drop: what was dragged in decides what happens (2.3).
The type lists below were recorded on a real Windows PC in Nov 2026 with a drag probe."""
import re
from pathlib import Path

import i18n
import outlook_grab as og
from conftest import APP_DIR

CLASSIC = ("RenPrivateSourceFolder RenPrivateLatestMessages RenPrivateMessages RenPrivateItem FileGroupDescriptor "
           "FileGroupDescriptorW FileNameW FileContents {Object Descriptor} CF_TEXT CF_UNICODETEXT Csv DragImageBits "
           "DragContext",)
NEW_OUTLOOK = ("DragContext DragImageBits chromium/x-renderer-taint chromium/x-drag-id CF_HDROP "
               "{Chromium Web Custom MIME Data Format}",)
CLASSIC_TEXT = ("From\tSubject\tReceived\tSize\tCategories\t\n"
                "notifications@example.com\tNode 2 Status Warning Alert\t1:54 PM\t48 KB\t\t")


def test_classic_outlook_drag_is_recognised():
    assert og.classify_drag(CLASSIC) == "classic"


def test_new_outlook_drag_is_recognised():
    assert og.classify_drag(NEW_OUTLOOK) == "chromium"


def test_real_files_always_win():
    assert og.classify_drag(NEW_OUTLOOK, has_files=True) == "files"
    assert og.classify_drag(CLASSIC, has_files=True) == "files"


def test_plain_text_never_reaches_outlook():
    # text or a link dragged from Word or a page must not trigger "check whatever Outlook has selected"
    assert og.classify_drag(("CF_TEXT CF_UNICODETEXT",)) == "other"
    assert og.classify_drag("") == "other"
    assert og.classify_drag(None) == "other"


def test_dragged_subject_is_read_from_outlooks_table():
    assert og.dragged_subjects(CLASSIC_TEXT) == ["Node 2 Status Warning Alert"]


def test_several_dragged_emails():
    text = "From\tSubject\nA\tFirst\nB\tSecond\n"
    assert og.dragged_subjects(text) == ["First", "Second"]


def test_no_subject_column_means_nothing_to_compare():
    assert og.dragged_subjects("From\tReceived\nA\t1:54 PM") == []
    assert og.dragged_subjects("") == []
    assert og.same_email([], ["anything"])          # nothing to compare: trust Outlook, as before


def test_same_email_matches_ignoring_spacing_and_case():
    assert og.same_email(["Node 2  Status Warning Alert"], ["node 2 status warning alert"])


def test_different_email_is_caught():
    assert not og.same_email(["Invoice 4411 overdue"], ["Lunch on Friday"])
    assert not og.same_email(["Invoice 4411 overdue"], [])


def test_partial_selection_mismatch_is_caught():
    # two dragged, but Outlook hands over one of them plus a third one
    assert not og.same_email(["First", "Second"], ["First", "Third"])


def test_new_drag_messages_have_greek():
    src = (APP_DIR / "qr_gui.pyw").read_text(encoding="utf-8")
    keys = ["This email can't be read from the new Outlook",
            "That wasn't a file or an email from Outlook (classic)",
            "Outlook handed over a different email",
            "Could not get the email from Outlook",
            "From Outlook (classic), or a saved file.\nDon't open it first."]
    for k in keys:
        assert k in i18n.UI_EL, k
    # every multi-line T(...) message added for 2.3 must be a key too (compares the source text)
    body = re.search(r"_new_outlook_notice\(self\):.*?T\(\"This.*?\),\s*T\((.*?)\)\)", src, re.S).group(1)
    joined = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', body)).encode().decode("unicode_escape").encode("latin-1").decode("utf-8")
    assert joined in i18n.UI_EL
