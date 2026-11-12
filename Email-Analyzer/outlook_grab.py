"""
Take the email that is selected in Outlook, without the user saving it first.

Classic Outlook for Windows only: it is asked (through its normal automation interface, by a small
PowerShell command) to save the selected message(s) as .msg files into our reports folder. Nothing is
opened and nothing is sent. The "new Outlook" and Outlook on the web have no such interface; for those,
drag the email to the desktop or use "Paste email text".

When an email is dragged from Outlook straight into the window, the window calls this too: the email
being dragged is the one that is selected.
"""
import os
import subprocess
from datetime import datetime
from pathlib import Path

MAX_EMAILS = 10
OL_MSG_UNICODE = 9      # Outlook's number for the .msg format

# The folder and name prefix are passed in environment variables, never pasted into the command text.
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try { $ol = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application') }
catch { Write-Output 'ERR:NOT_RUNNING'; exit 2 }
try {
    $explorer = $ol.ActiveExplorer()
    if ($null -eq $explorer) { Write-Output 'ERR:NO_WINDOW'; exit 3 }
    $sel = $explorer.Selection
    if ($sel.Count -lt 1) { Write-Output 'ERR:NOTHING_SELECTED'; exit 4 }
    $n = 0
    foreach ($item in $sel) {
        if ($n -ge [int]$env:EA_MAX) { break }
        if ($item.Class -ne 43) { continue }     # 43 = a mail message (not a meeting or contact)
        $n++
        $path = Join-Path $env:EA_DIR ('{0}-{1:D2}.msg' -f $env:EA_PREFIX, $n)
        $item.SaveAs($path, __FORMAT__)
        Write-Output ('OK:{0}-{1:D2}.msg' -f $env:EA_PREFIX, $n)
    }
    if ($n -eq 0) { Write-Output 'ERR:NOT_AN_EMAIL'; exit 5 }
} catch { Write-Output ('ERR:FAILED ' + $_.Exception.Message); exit 6 }
""".replace("__FORMAT__", str(OL_MSG_UNICODE))

REASONS = {
    "NOT_WINDOWS": ("this only works on Windows with classic Outlook.",
                    "λειτουργεί μόνο σε Windows με το κλασικό Outlook."),
    "NOT_RUNNING": ("classic Outlook is not open (the new Outlook cannot do this: drag the email to the desktop, or use Paste email text).",
                    "το κλασικό Outlook δεν είναι ανοιχτό (το νέο Outlook δεν το υποστηρίζει: σύρετε το email στην επιφάνεια εργασίας ή χρησιμοποιήστε την Επικόλληση κειμένου email)."),
    "NO_WINDOW": ("no Outlook window is open.", "δεν υπάρχει ανοιχτό παράθυρο Outlook."),
    "NOTHING_SELECTED": ("no email is selected in Outlook. Click the email once, then try again.",
                         "δεν έχει επιλεγεί email στο Outlook. Κάντε ένα κλικ στο email και δοκιμάστε ξανά."),
    "NOT_AN_EMAIL": ("the selected item is not an email.", "το επιλεγμένο στοιχείο δεν είναι email."),
    "TIMEOUT": ("Outlook did not answer in time. Check for a question window in Outlook, then try again.",
                "το Outlook δεν απάντησε εγκαίρως. Ελέγξτε για παράθυρο ερώτησης στο Outlook και δοκιμάστε ξανά."),
    "FAILED": ("Outlook refused. Save the email to the desktop and drop that file instead.",
               "το Outlook αρνήθηκε. Αποθηκεύστε το email στην επιφάνεια εργασίας και σύρετε το αρχείο."),
}


class OutlookError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail

    def reason(self, lang="en"):
        en, el = REASONS.get(self.code, REASONS["FAILED"])
        return el if lang == "el" else en


def parse_output(text, folder):
    """Turn the command's output into file paths, or raise OutlookError."""
    files, err = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("OK:"):
            name = Path(line[3:]).name            # a bare file name only, whatever came back
            if name.lower().endswith(".msg") and (Path(folder) / name).is_file():
                files.append(str(Path(folder) / name))
        elif line.startswith("ERR:") and err is None:
            code, _, detail = line[4:].partition(" ")
            err = OutlookError(code if code in REASONS else "FAILED", detail)
    if files:
        return files
    raise err or OutlookError("FAILED", text.strip()[:200])


def is_windows():
    return os.name == "nt"


# ------------------------------------------------------------------ what was dragged in
# Measured on a real PC (Nov 2026):
#   classic Outlook offers  RenPrivateMessages, FileGroupDescriptorW ... and CF_TEXT holding a small
#                           tab-separated table: "From<TAB>Subject<TAB>Received...", one row per email.
#   the new Outlook offers  chromium/x-drag-id, chromium/x-renderer-taint ... (it is a Chromium app)
#                           and the drop never completes, so the window used to show nothing at all.
def classify_drag(types, has_files=False):
    """'files', 'classic' (classic Outlook email), 'chromium' (new Outlook or a web browser) or 'other'."""
    t = " ".join(types) if isinstance(types, (list, tuple)) else str(types or "")
    if has_files:
        return "files"
    if "RenPrivateMessages" in t or "RenPrivateItem" in t:
        return "classic"
    if "chromium/" in t.lower():
        return "chromium"
    return "other"


def _norm_subject(s):
    return " ".join(str(s or "").split()).casefold()


def dragged_subjects(text):
    """Subjects of the emails classic Outlook says are being dragged (from its CF_TEXT table).
    Returns [] when the table has no Subject column (a customised view): then nothing can be compared."""
    lines = [l for l in str(text or "").splitlines() if l.strip()]
    if len(lines) < 2:
        return []
    head = [h.strip().casefold() for h in lines[0].split("\t")]
    if "subject" not in head:
        return []
    i = head.index("subject")
    return [cols[i].strip() for cols in (l.split("\t") for l in lines[1:]) if len(cols) > i]


def same_email(dragged, grabbed):
    """True when what Outlook handed over is what was dragged. With nothing to compare, trust it."""
    if not dragged:
        return True
    want = {_norm_subject(s) for s in dragged}
    return all(_norm_subject(g) in want for g in grabbed) and bool(grabbed)


def grab_selected(folder, timeout=40, run=subprocess.run):
    """Save the email(s) selected in Outlook into `folder`. Returns the .msg paths. Raises OutlookError."""
    if not is_windows():
        raise OutlookError("NOT_WINDOWS")
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, EA_DIR=str(folder), EA_MAX=str(MAX_EMAILS),
               EA_PREFIX=f"Outlook-email-{datetime.now():%Y%m%d-%H%M%S}")
    try:
        done = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", SCRIPT],
                   env=env, capture_output=True, text=True, timeout=timeout,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise OutlookError("TIMEOUT")
    except Exception as e:
        raise OutlookError("FAILED", e.__class__.__name__)
    return parse_output(done.stdout or "", folder)
