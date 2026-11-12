"""Small window helpers that need no window (2.3)."""
import importlib.machinery
import importlib.util
from pathlib import Path

from conftest import APP_DIR

_loader = importlib.machinery.SourceFileLoader("qr_gui_for_tests",
                                               str(APP_DIR / "qr_gui.pyw"))
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
gui = importlib.util.module_from_spec(_spec)
_loader.exec_module(gui)


def test_long_folder_keeps_drive_and_last_two_folders():
    p = r"C:\Users\Someone\AppData\Local\Temp\claude\0123456789abcdef\scratchpad\kit\tests\samples"
    assert gui.short_folder(Path(p)) == r"C:\…\tests\samples"


def test_short_folder_is_left_alone():
    assert gui.short_folder(Path(r"C:\Users\me\Desktop")) == r"C:\Users\me\Desktop"


def test_outlook_pickup_folder_stays_recognisable():
    p = Path(r"C:\Users\Someone.Long.Name\OneDrive - Company\Documents\Email Analyzer reports\Outlook")
    assert gui.short_folder(p).endswith(r"Email Analyzer reports\Outlook")


def test_network_share():
    p = Path(r"\\fileserver\ict\shared\incoming\suspicious\2026\november\week-46")
    out = gui.short_folder(p)
    assert out.endswith(r"november\week-46") and "…" in out
