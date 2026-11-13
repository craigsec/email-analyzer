"""
English and Greek for Email Analyzer.

The checks always produce ENGLISH text (that is what the tests and the saved .json use). Greek is added
only when something is shown: the window, the report, the ticket summary.

  T("Browse files")          -> a fixed piece of interface text, looked up in UI_EL
  msg("Plain http, not ...") -> a warning from the checks, matched against MESSAGES_EL
Anything without a Greek entry is shown in English, so a missing translation can never hide a warning.

Language: environment variable EMAIL_ANALYZER_LANG, else LANGUAGE in config.txt, else Greek on a Greek
Windows and English everywhere else.
"""
import os
import re

_LANG = None


def _detect():
    env = os.environ.get("EMAIL_ANALYZER_LANG", "").strip().lower()
    if env in ("en", "el"):
        return env
    try:
        import appconfig
        cfg = appconfig.get("LANGUAGE").strip().lower()
    except Exception:
        cfg = ""
    if cfg in ("en", "el"):
        return cfg
    try:
        if os.name == "nt":
            import ctypes
            if (ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF) == 0x08:   # Greek
                return "el"
        else:
            import locale
            if (locale.getlocale()[0] or "").lower().startswith(("el", "greek")):
                return "el"
    except Exception:
        pass
    return "en"


def language():
    global _LANG
    if _LANG is None:
        _LANG = _detect()
    return _LANG


def set_language(code):
    """'en', 'el', or None to detect again."""
    global _LANG
    _LANG = code if code in ("en", "el") else None


# ------------------------------------------------------------------ what to do
ACTIONS = {
    "danger": ("Do not open anything in it and do not reply. Report it to ICT, then delete it.",
               "Μην ανοίξετε τίποτα και μην απαντήσετε. Αναφέρετέ το στο ICT και μετά διαγράψτε το."),
    "warn": ("Do not open links or attachments yet. Ask ICT to check it first.",
             "Μην ανοίξετε ακόμη συνδέσμους ή συνημμένα. Ζητήστε πρώτα έλεγχο από το ICT."),
    "minor": ("Only weak signals. Probably fine, but if you did not expect this email, confirm with the sender by phone.",
              "Μόνο ασθενείς ενδείξεις. Πιθανότατα εντάξει, αλλά αν δεν περιμένατε αυτό το email, επιβεβαιώστε τηλεφωνικά με τον αποστολέα."),
    "known": ("Nothing suspicious found. If it asks for money, a password or new bank details, still confirm by phone.",
              "Δεν βρέθηκε κάτι ύποπτο. Αν ζητά χρήματα, κωδικό ή νέα τραπεζικά στοιχεία, επιβεβαιώστε πάντως τηλεφωνικά."),
    "clean": ("Nothing suspicious found. That is not a guarantee: if it asks for money, a password or new bank details, confirm by phone.",
              "Δεν βρέθηκε κάτι ύποπτο. Αυτό δεν είναι εγγύηση: αν ζητά χρήματα, κωδικό ή νέα τραπεζικά στοιχεία, επιβεβαιώστε τηλεφωνικά."),
    "info": ("No links or QR codes found. Read any warnings shown for the file itself.",
             "Δεν βρέθηκαν σύνδεσμοι ή κωδικοί QR. Διαβάστε τυχόν προειδοποιήσεις για το ίδιο το αρχείο."),
}


def action(level):
    en, el = ACTIONS.get(level, ACTIONS["clean"])
    return el if language() == "el" else en


# ------------------------------------------------------------------ interface text
UI_EL = {
    # verdict labels
    "DANGEROUS": "ΕΠΙΚΙΝΔΥΝΟ", "SUSPICIOUS": "ΥΠΟΠΤΟ", "LOW RISK": "ΧΑΜΗΛΟΣ ΚΙΝΔΥΝΟΣ", "KNOWN SITE": "ΓΝΩΣΤΟΣ ΙΣΤΟΤΟΠΟΣ",
    "NO FLAGS": "ΧΩΡΙΣ ΕΝΔΕΙΞΕΙΣ", "NOT A LINK": "ΔΕΝ ΕΙΝΑΙ ΣΥΝΔΕΣΜΟΣ", "PROBABLY OURS": "ΜΑΛΛΟΝ ΔΙΚΟ ΜΑΣ", "PARKED": "ΑΝΕΝΕΡΓΟ",
    "dangerous": "επικίνδυνα", "suspicious": "ύποπτα", "low risk": "χαμηλού κινδύνου", "known site": "γνωστοί ιστότοποι",
    "no flags": "χωρίς ενδείξεις", "not a link": "όχι σύνδεσμοι", "ok": "εντάξει",
    # banner titles
    "Dangerous: do not open, report to ICT": "Επικίνδυνο: μην το ανοίξετε, αναφέρετέ το στο ICT",
    "Dangerous: do not open, report and block": "Επικίνδυνο: μην το ανοίξετε, αναφορά και αποκλεισμός",
    "Suspicious: needs a closer look": "Ύποπτο: χρειάζεται προσεκτικότερο έλεγχο",
    "Low risk: only minor flags": "Χαμηλός κίνδυνος: μόνο μικρές ενδείξεις",
    "Links go to known legitimate sites": "Οι σύνδεσμοι οδηγούν σε γνωστούς νόμιμους ιστότοπους",
    "No red flags found": "Δεν βρέθηκαν ενδείξεις κινδύνου", "No web links found": "Δεν βρέθηκαν σύνδεσμοι",
    "No QR codes or links found": "Δεν βρέθηκαν κωδικοί QR ή σύνδεσμοι",
    "No QR codes or links found.": "Δεν βρέθηκαν κωδικοί QR ή σύνδεσμοι.",
    "Ready": "Έτοιμο", "Ready.": "Έτοιμο.", "Checking...": "Έλεγχος...", "Starting...": "Εκκίνηση...", "Done.": "Ολοκληρώθηκε.",
    "What to do": "Τι να κάνετε", "What to do:": "Τι να κάνετε:",
    # header and sidebar
    "Cybersecurity Tool  ·  Email, attachment and link phishing check": "Εργαλείο Κυβερνοασφάλειας  ·  Έλεγχος email, συνημμένων και συνδέσμων για phishing",
    "Check files": "Έλεγχος αρχείων", "Domain watch": "Παρακολούθηση domain", "Bank list": "Λίστα τραπεζών",
    "Settings": "Ρυθμίσεις", "Help": "Βοήθεια",
    "Drop an email or attachment": "Σύρετε εδώ email ή συνημμένο",
    "From Outlook (classic), or a saved file.\nDon't open it first.": "Από το κλασικό Outlook ή αποθηκευμένο αρχείο.\nΜην το ανοίξετε πρώτα.",
    "Browse files": "Επιλογή αρχείων", "Paste email text": "Επικόλληση κειμένου email",
    "Check selected Outlook email": "Έλεγχος email από το Outlook",
    "CHECK OPTIONS": "ΕΠΙΛΟΓΕΣ ΕΛΕΓΧΟΥ", "Online lookups (domain age)": "Online αναζητήσεις (ηλικία domain)",
    "Off: nothing leaves this PC.\nOn: only the domain name is sent.": "Κλειστό: τίποτα δεν φεύγει από το PC.\nΑνοιχτό: μόνο το όνομα του domain.",
    "Live scan (urlscan.io)": "Ζωντανή σάρωση (urlscan.io)",
    "On: urlscan.io opens the link on its own servers.": "Ανοιχτό: το urlscan.io ανοίγει τον σύνδεσμο στους δικούς του διακομιστές.",
    "Add a urlscan.io key in Settings to turn this on.": "Προσθέστε κλειδί urlscan.io στις Ρυθμίσεις για να ενεργοποιηθεί.",
    "PDF password (only if locked)": "Κωδικός PDF (μόνο αν είναι κλειδωμένο)", "usually given in the email": "συνήθως αναφέρεται στο email",
    "Check again": "Επανέλεγχος", "CONNECTIONS": "ΣΥΝΔΕΣΕΙΣ",
    "connected": "συνδεδεμένο", "no key": "χωρίς κλειδί",
    "Brand list: shared": "Λίστα τραπεζών: κοινόχρηστη", "Brand list: this PC": "Λίστα τραπεζών: αυτού του PC",
    "Brand list: last shared copy": "Λίστα τραπεζών: τελευταίο κοινόχρηστο αντίγραφο",
    "Brand list: shared list not reachable": "Λίστα τραπεζών: η κοινόχρηστη δεν είναι προσβάσιμη",
    "Links are never opened on this PC": "Οι σύνδεσμοι δεν ανοίγουν ποτέ σε αυτό το PC",
    # main area
    "Drop a suspicious email or attachment to begin.": "Σύρετε ένα ύποπτο email ή συνημμένο για να ξεκινήσετε.",
    "No file checked yet": "Δεν έχει ελεγχθεί αρχείο ακόμη",
    "1.  Drag the suspicious email straight from Outlook (classic) into this window, or click “Check selected Outlook email”.\n"
    "2.  Saved files work too: drag them in, or right-click > Send to > Email Analyzer.\n"
    "3.  Red means dangerous: report it to ICT and do not open the link.\n"
    "4.  Click “Open report” for a readable copy you can copy from and attach to the ticket.":
        "1.  Σύρετε το ύποπτο email απευθείας από το κλασικό Outlook σε αυτό το παράθυρο ή πατήστε «Έλεγχος email από το Outlook».\n"
        "2.  Και τα αποθηκευμένα αρχεία δουλεύουν: σύρετέ τα ή δεξί κλικ > Αποστολή προς > Email Analyzer.\n"
        "3.  Κόκκινο σημαίνει επικίνδυνο: αναφέρετέ το στο ICT και μην ανοίξετε τον σύνδεσμο.\n"
        "4.  Πατήστε «Άνοιγμα αναφοράς» για ευανάγνωστο αντίγραφο που μπορείτε να επισυνάψετε στο ticket.",
    "Open report": "Άνοιγμα αναφοράς", "Copy ticket summary": "Αντιγραφή σύνοψης", "Show in folder": "Εμφάνιση στον φάκελο",
    "Clear": "Καθαρισμός", "Copy": "Αντιγραφή", "Details": "Λεπτομέρειες",
    "Found in:": "Βρέθηκε σε:", "QR code(s) or link(s) found": "κωδικοί QR ή σύνδεσμοι",
    "file(s)": "αρχείο(α)", "link(s)": "σύνδεσμος(οι)", "Risk score": "Βαθμός κινδύνου", "risk score": "βαθμός κινδύνου",
    "offline check": "έλεγχος εκτός σύνδεσης", "live scan (urlscan.io)": "ζωντανή σάρωση (urlscan.io)",
    "online lookups": "online αναζητήσεις",
    "live scan on, about 30 seconds per link": "ζωντανή σάρωση, περίπου 30 δευτερόλεπτα ανά σύνδεσμο",
    "online lookups on, links are not visited": "online αναζητήσεις, οι σύνδεσμοι δεν ανοίγουν",
    "offline check, nothing is sent to the internet": "έλεγχος εκτός σύνδεσης, τίποτα δεν στέλνεται στο internet",
    "Each warning adds points (HIGH {h}, MEDIUM {m}, LOW {l}). From {s} suspicious, from {d} dangerous. "
    "Only the worst link counts, plus everything about the email or file itself.":
        "Κάθε προειδοποίηση προσθέτει πόντους (ΥΨΗΛΗ {h}, ΜΕΣΑΙΑ {m}, ΧΑΜΗΛΗ {l}). Από {s} ύποπτο, από {d} επικίνδυνο. "
        "Μετράει μόνο ο χειρότερος σύνδεσμος, μαζί με όσα αφορούν το ίδιο το email ή αρχείο.",
    "Nothing added points.": "Τίποτα δεν πρόσθεσε πόντους.",
    "Check domain age now": "Έλεγχος ηλικίας domain τώρα",
    "The age of the domains was not checked. A domain registered days ago is one of the strongest signs of phishing. "
    "This sends only the domain names to rdap.org.":
        "Η ηλικία των domain δεν ελέγχθηκε. Domain που καταχωρήθηκε πριν από λίγες ημέρες είναι από τις ισχυρότερες ενδείξεις phishing. "
        "Στέλνονται μόνο τα ονόματα των domain στο rdap.org.",
    "{n} more reason(s). Turn on Details or open the report.": "{n} ακόμη λόγος(οι). Ενεργοποιήστε τις Λεπτομέρειες ή ανοίξτε την αναφορά.",
    "Done. “Open report” gives a copy for the ticket.": "Έτοιμο. Το «Άνοιγμα αναφοράς» δίνει αντίγραφο για το ticket.",
    "Ticket summary copied. Paste it into the ticket.": "Η σύνοψη αντιγράφηκε. Επικολλήστε τη στο ticket.",
    "Link copied in safe form (hxxps, [.]), it cannot be clicked.": "Ο σύνδεσμος αντιγράφηκε σε ασφαλή μορφή (hxxps, [.]), δεν μπορεί να πατηθεί.",
    "Settings saved.": "Οι ρυθμίσεις αποθηκεύτηκαν.",
    "Settings saved. Close and reopen the app to change the language.": "Οι ρυθμίσεις αποθηκεύτηκαν. Κλείστε και ανοίξτε ξανά την εφαρμογή για αλλαγή γλώσσας.",
    "LIVE SCAN  ·  urlscan.io": "ΖΩΝΤΑΝΗ ΣΑΡΩΣΗ  ·  urlscan.io", "Lands on:": "Καταλήγει σε:", "Page title:": "Τίτλος σελίδας:",
    "Open full urlscan report  ↗": "Άνοιγμα πλήρους αναφοράς urlscan  ↗",
    # outlook
    "Asking Outlook for the selected email...": "Λήψη του επιλεγμένου email από το Outlook...",
    "Could not get the email from Outlook: {why}": "Δεν ήταν δυνατή η λήψη του email από το Outlook: {why}",
    "Could not get the email from Outlook": "Δεν ήταν δυνατή η λήψη του email από το Outlook",
    "This email can't be read from the new Outlook": "Αυτό το email δεν διαβάζεται από το νέο Outlook",
    "The new Outlook doesn't hand emails to other programs, so nothing was checked.\n\n"
    "Do one of these instead:\n"
    "1.  Open Outlook (classic) from the Start menu and drag the email from there.\n"
    "2.  In the new Outlook, drag the email onto your desktop first, then drag that file in here.\n"
    "3.  Click “Paste email text”.\n\n"
    "The same goes for Outlook on the web in a browser.":
        "Το νέο Outlook δεν δίνει email σε άλλα προγράμματα, οπότε δεν ελέγχθηκε τίποτα.\n\n"
        "Κάντε ένα από τα παρακάτω:\n"
        "1.  Ανοίξτε το Outlook (classic) από το μενού Έναρξη και σύρετε το email από εκεί.\n"
        "2.  Στο νέο Outlook, σύρετε πρώτα το email στην επιφάνεια εργασίας και μετά σύρετε εκείνο το αρχείο εδώ.\n"
        "3.  Πατήστε «Επικόλληση κειμένου email».\n\n"
        "Το ίδιο ισχύει για το Outlook στο web μέσα από browser.",
    "That wasn't a file or an email from Outlook (classic)": "Αυτό δεν ήταν αρχείο ή email από το κλασικό Outlook",
    "Nothing was checked.\n\nDrag in a saved file or an email from Outlook (classic), or click “Paste email text”.":
        "Δεν ελέγχθηκε τίποτα.\n\nΣύρετε εδώ ένα αποθηκευμένο αρχείο ή ένα email από το κλασικό Outlook, ή πατήστε «Επικόλληση κειμένου email».",
    "Outlook handed over a different email": "Το Outlook έδωσε διαφορετικό email",
    "You dragged “{want}”, but the email selected in Outlook is “{got}”. "
    "Nothing was checked, so the two cannot be mixed up.\n\n"
    "Click the email once in Outlook (classic), then drag it in again or click “Check selected Outlook email”.":
        "Σύρατε το «{want}», αλλά στο Outlook είναι επιλεγμένο το «{got}». "
        "Δεν ελέγχθηκε τίποτα, ώστε να μη μπερδευτούν τα δύο.\n\n"
        "Κάντε ένα κλικ στο email στο κλασικό Outlook και σύρετέ το ξανά ή πατήστε «Έλεγχος email από το Outlook».",
    # paste dialog
    "Best: the full message source, headers included (Outlook: open the email > File > Properties >\n"
    "copy \"Internet headers\", then paste the body under them). Body text alone also works,\n"
    "but then the sender cannot be checked. The text is only read, never opened or run.":
        "Ιδανικά: ολόκληρος ο κώδικας του μηνύματος με τις κεφαλίδες (Outlook: ανοίξτε το email > Αρχείο > Ιδιότητες >\n"
        "αντιγράψτε τις «Κεφαλίδες Internet» και επικολλήστε το σώμα από κάτω). Δουλεύει και μόνο το κείμενο,\n"
        "αλλά τότε δεν ελέγχεται ο αποστολέας. Το κείμενο μόνο διαβάζεται, δεν ανοίγει ούτε εκτελείται.",
    "Check": "Έλεγχος", "Cancel": "Άκυρο", "Save": "Αποθήκευση", "Paste from clipboard": "Επικόλληση από το πρόχειρο",
    # settings dialog
    "Keys are stored on this PC only, in keys.txt.": "Τα κλειδιά αποθηκεύονται μόνο σε αυτό το PC, στο keys.txt.",
    "urlscan.io API key": "Κλειδί API urlscan.io", "VirusTotal API key (optional)": "Κλειδί API VirusTotal (προαιρετικό)",
    "Needed for live scans and screenshots. urlscan.io > Profile > API keys.": "Χρειάζεται για ζωντανές σαρώσεις και στιγμιότυπα. urlscan.io > Profile > API keys.",
    "Adds domain reputation. virustotal.com > profile > API key.": "Προσθέτει φήμη domain. virustotal.com > profile > API key.",
    "Show keys": "Εμφάνιση κλειδιών", "Language": "Γλώσσα",
    "Shared brand list (path to one banks.txt for everybody)": "Κοινόχρηστη λίστα τραπεζών (διαδρομή προς ένα banks.txt για όλους)",
    "Leave empty to use this PC's own list. Example: \\\\server\\ict\\banks.txt": "Αφήστε κενό για τη λίστα αυτού του PC. Παράδειγμα: \\\\server\\ict\\banks.txt",
    # domain watch
    "WATCHED DOMAINS": "DOMAIN ΥΠΟ ΠΑΡΑΚΟΛΟΥΘΗΣΗ",
    "One per line: our own domains and key partners\n(e.g. our bank, port agents, charterers).":
        "Ένα ανά γραμμή: τα δικά μας domain και βασικοί συνεργάτες\n(π.χ. τράπεζα, πράκτορες, ναυλωτές).",
    "Check for lookalikes": "Έλεγχος για απομιμήσεις",
    "Builds every typo and lookalike an attacker\ncould register and checks which exist.\nNeeds internet. Takes 1 to 3 minutes.\nRun it monthly.":
        "Δημιουργεί κάθε παραλλαγή που θα μπορούσε\nνα καταχωρήσει ένας επιτιθέμενος και ελέγχει ποιες υπάρχουν.\nΧρειάζεται internet. Διαρκεί 1 έως 3 λεπτά.\nΕκτελέστε το κάθε μήνα.",
    "Lookalike domain watch": "Παρακολούθηση απομιμήσεων domain",
    "Add our domains on the left, then click “Check for lookalikes”.": "Προσθέστε τα domain μας αριστερά και πατήστε «Έλεγχος για απομιμήσεις».",
    "Copy block list": "Αντιγραφή λίστας αποκλεισμού",
    # report
    "Email Analyzer report": "Αναφορά Email Analyzer", "Checked": "Ελέγχθηκε", "by": "από",
    "links shown here cannot be clicked": "οι σύνδεσμοι εδώ δεν μπορούν να πατηθούν",
    "Quick copy": "Γρήγορη αντιγραφή", "Ticket summary": "Σύνοψη για ticket", "Domains to block": "Domain προς αποκλεισμό",
    "All links, defanged": "Όλοι οι σύνδεσμοι, απενεργοποιημένοι", "Results": "Αποτελέσματα", "For the ticket": "Για το ticket",
    "Everything copied is safe to paste: links cannot be clicked.": "Ό,τι αντιγράφεται είναι ασφαλές για επικόλληση: οι σύνδεσμοι δεν πατιούνται.",
    "Ticket summary (text)": "Σύνοψη για ticket (κείμενο)",
    "All dangerous and suspicious links": "Όλοι οι επικίνδυνοι και ύποπτοι σύνδεσμοι",
    "For Defender > Tenant Allow/Block List. Real banks, Microsoft, Google, link shorteners and file-sharing sites are left out on purpose.":
        "Για Defender > Tenant Allow/Block List. Πραγματικές τράπεζες, Microsoft, Google, συντομευτές συνδέσμων και υπηρεσίες κοινής χρήσης αρχείων παραλείπονται σκόπιμα.",
    "Paste into the ticket. Links are defanged so nobody can click them.": "Επικολλήστε στο ticket. Οι σύνδεσμοι είναι απενεργοποιημένοι ώστε να μην πατηθούν.",
    "Exactly as found, made unclickable.": "Ακριβώς όπως βρέθηκαν, χωρίς δυνατότητα κλικ.",
    "A clean result is not proof of safety. If in doubt, treat it as phishing.": "Ένα καθαρό αποτέλεσμα δεν αποδεικνύει ασφάλεια. Σε αμφιβολία, θεωρήστε το phishing.",
    "(links are defanged: hxxp and [.] so they cannot be clicked)": "(οι σύνδεσμοι είναι απενεργοποιημένοι: hxxp και [.] ώστε να μην πατιούνται)",
    "File:": "Αρχείο:", "Overall:": "Συνολικά:", "Score made of:": "Ο βαθμός προκύπτει από:", "found in:": "βρέθηκε σε:",
    "checked by": "έλεγχος από", "Open full urlscan report": "Άνοιγμα πλήρους αναφοράς urlscan",
}


_MONTHS_EL = ["Ιανουαρίου", "Φεβρουαρίου", "Μαρτίου", "Απριλίου", "Μαΐου", "Ιουνίου", "Ιουλίου",
              "Αυγούστου", "Σεπτεμβρίου", "Οκτωβρίου", "Νοεμβρίου", "Δεκεμβρίου"]
_MON_EL = ["Ιαν", "Φεβ", "Μαρ", "Απρ", "Μαΐ", "Ιουν", "Ιουλ", "Αυγ", "Σεπ", "Οκτ", "Νοε", "Δεκ"]


def date(when, long=False):
    """'11 Nov 2026 17:56' / '11 November 2026, 17:56' in the current language (2.3: was always English)."""
    if language() == "el":
        month = (_MONTHS_EL if long else _MON_EL)[when.month - 1]
        return f"{when.day} {month} {when:%Y}{',' if long else ''} {when:%H:%M}"
    return f"{when:%d %B %Y, %H:%M}" if long else f"{when:%d %b %Y %H:%M}"


def T(text, **kw):
    """Interface text in the current language. {name} placeholders are filled from keyword arguments."""
    out = UI_EL.get(text, text) if language() == "el" else text
    return out.format(**kw) if kw else out


# ------------------------------------------------------------------ warnings from the checks
# English template -> Greek template. {} in the English marks a changing part; {0} {1}... in the Greek
# puts those parts back. More specific templates must come before more general ones.
_M = [
    # verdicts
    ("LIKELY FAKE / MALICIOUS - do not open, report and block", "ΠΙΘΑΝΟΤΑΤΑ ΨΕΥΤΙΚΟ / ΚΑΚΟΒΟΥΛΟ - μην το ανοίξετε, αναφορά και αποκλεισμός"),
    ("SUSPICIOUS - verify before anyone opens it", "ΥΠΟΠΤΟ - επαληθεύστε πριν το ανοίξει οποιοσδήποτε"),
    ("LOW RISK - minor flags only, not enough on their own. Judge it together with the rest of the email.",
     "ΧΑΜΗΛΟΣ ΚΙΝΔΥΝΟΣ - μόνο μικρές ενδείξεις, όχι αρκετές από μόνες τους. Κρίνετέ το μαζί με το υπόλοιπο email."),
    ("Domain matches a known legitimate site. A compromised real site (watering hole) is not ruled out; check the urlscan verdict.",
     "Το domain ταιριάζει με γνωστό νόμιμο ιστότοπο. Δεν αποκλείεται παραβιασμένος πραγματικός ιστότοπος· ελέγξτε το αποτέλεσμα urlscan."),
    ("No red flags from these checks. That is not proof it is safe.", "Καμία ένδειξη κινδύνου από αυτούς τους ελέγχους. Αυτό δεν αποδεικνύει ότι είναι ασφαλές."),
    ("Not a web link. Check the content by hand.", "Δεν είναι σύνδεσμος ιστού. Ελέγξτε το περιεχόμενο χειροκίνητα."),
    # files Windows will not let us read (2.3)
    ("Microsoft Defender blocked this file and then removed it: it found something dangerous in it. "
     "Do not open it or any copy of it (for example the original attachment in the email). Report it to ICT.",
     "Το Microsoft Defender μπλόκαρε αυτό το αρχείο και μετά το αφαίρεσε: βρήκε κάτι επικίνδυνο μέσα του. "
     "Μην ανοίξετε ούτε αυτό ούτε κανένα αντίγραφό του (π.χ. το αρχικό συνημμένο στο email). Αναφέρετέ το στο ICT."),
    ("Microsoft Defender blocked this file: Windows reports that it contains a virus or unwanted software. "
     "Do not open it or any copy of it (for example the original attachment in the email). Report it to ICT.",
     "Το Microsoft Defender μπλόκαρε αυτό το αρχείο: τα Windows αναφέρουν ότι περιέχει ιό ή ανεπιθύμητο λογισμικό. "
     "Μην ανοίξετε ούτε αυτό ούτε κανένα αντίγραφό του (π.χ. το αρχικό συνημμένο στο email). Αναφέρετέ το στο ICT."),
    ("Windows refused to let this file be read, so it was not checked. This is usually Microsoft Defender "
     "blocking something dangerous: look in Windows Security > Protection history. "
     "Do not open it until ICT has looked at it.",
     "Τα Windows δεν επέτρεψαν την ανάγνωση αυτού του αρχείου, οπότε δεν ελέγχθηκε. Συνήθως αυτό σημαίνει ότι το "
     "Microsoft Defender μπλοκάρει κάτι επικίνδυνο: δείτε στην Ασφάλεια των Windows > Ιστορικό προστασίας. "
     "Μην το ανοίξετε μέχρι να το εξετάσει το ICT."),
    ("This file is open in another program, so it could not be read. Close it there and check again.",
     "Αυτό το αρχείο είναι ανοιχτό σε άλλο πρόγραμμα και δεν διαβάστηκε. Κλείστε το εκεί και ελέγξτε ξανά."),
    ("This file no longer exists, so it was not checked. If nobody deleted it, Microsoft Defender probably "
     "removed it: do not open any copy of it and report it to ICT.",
     "Αυτό το αρχείο δεν υπάρχει πια, οπότε δεν ελέγχθηκε. Αν δεν το διέγραψε κανείς, πιθανότατα το αφαίρεσε το "
     "Microsoft Defender: μην ανοίξετε κανένα αντίγραφό του και αναφέρετέ το στο ICT."),
    # links
    ("Plain http, not https. No real bank login page uses this.", "Απλό http, όχι https. Καμία πραγματική σελίδα σύνδεσης τράπεζας δεν το χρησιμοποιεί."),
    ("Could not read a website name from this link. Malformed links are a trick to confuse scanners; treat it as suspicious.",
     "Δεν διαβάστηκε όνομα ιστότοπου από αυτόν τον σύνδεσμο. Οι κακοσχηματισμένοι σύνδεσμοι είναι τέχνασμα για να μπερδεύουν τους σαρωτές· θεωρήστε τον ύποπτο."),
    ("Link is malformed (stray [ or ] in the address). Browsers may read it differently from scanners; treat it as suspicious.",
     "Ο σύνδεσμος είναι κακοσχηματισμένος (αδέσποτο [ ή ] στη διεύθυνση). Οι browsers μπορεί να τον διαβάσουν αλλιώς από τους σαρωτές· θεωρήστε τον ύποπτο."),
    ("Link contains invisible characters ({}). They are used to make an address look different from where it really goes.",
     "Ο σύνδεσμος περιέχει αόρατους χαρακτήρες ({0}). Χρησιμοποιούνται ώστε μια διεύθυνση να φαίνεται διαφορετική από τον πραγματικό προορισμό."),
    ("Link contains a backslash. Phones and browsers treat it as '/', so it really goes to {}, whatever the rest of the address seems to say.",
     "Ο σύνδεσμος περιέχει ανάποδη κάθετο. Κινητά και browsers τη διαβάζουν ως '/', άρα πηγαίνει στην πραγματικότητα στο {0}, ό,τι κι αν δείχνει η υπόλοιπη διεύθυνση."),
    ("Link uses the user@host trick: the browser ignores '{}' and really goes to {}.",
     "Ο σύνδεσμος χρησιμοποιεί το τέχνασμα user@host: ο browser αγνοεί το '{0}' και πηγαίνει στην πραγματικότητα στο {1}."),
    ("'{}' is an IP address in disguise. It really means {}.", "Το '{0}' είναι μεταμφιεσμένη διεύθυνση IP. Στην πραγματικότητα σημαίνει {1}."),
    ("Link goes to a raw IP address ({}), not a domain. Banks never do this.", "Ο σύνδεσμος πηγαίνει σε σκέτη διεύθυνση IP ({0}), όχι σε domain. Οι τράπεζες δεν το κάνουν ποτέ."),
    ("Domain uses foreign letters that look like normal ones: it shows as '{}' but is really '{}', an imitation of {} ({}).",
     "Το domain χρησιμοποιεί ξένα γράμματα που μοιάζουν με κανονικά: εμφανίζεται ως '{0}' αλλά είναι στην πραγματικότητα '{1}', απομίμηση του {2} ({3})."),
    ("Domain uses foreign letters that look like normal ones: it shows as '{}' but is really '{}'.",
     "Το domain χρησιμοποιεί ξένα γράμματα που μοιάζουν με κανονικά: εμφανίζεται ως '{0}' αλλά είναι στην πραγματικότητα '{1}'."),
    ("Punycode domain (looks like '{}'). Often used to fake a brand with lookalike letters.",
     "Domain τύπου punycode (μοιάζει με '{0}'). Χρησιμοποιείται συχνά για απομίμηση επωνυμίας με παρόμοια γράμματα."),
    ("{} is a Google Maps share link.", "Το {0} είναι σύνδεσμος κοινοποίησης Google Maps."),
    ("{} is a YouTube short link.", "Το {0} είναι σύντομος σύνδεσμος YouTube."),
    ("{} is a WhatsApp chat link.", "Το {0} είναι σύνδεσμος συνομιλίας WhatsApp."),
    ("{} is a link shortener. The real destination is hidden; see the urlscan result for where it lands.",
     "Το {0} είναι συντομευτής συνδέσμων. Ο πραγματικός προορισμός είναι κρυμμένος· δείτε στο αποτέλεσμα urlscan πού καταλήγει."),
    ("Hosted on free/cheap web hosting ({}). Common for phishing pages, never used by banks for login.",
     "Φιλοξενείται σε δωρεάν/φθηνή φιλοξενία ({0}). Συνηθισμένο για σελίδες phishing, ποτέ για σύνδεση σε τράπεζα."),
    ("File-sharing link ({}). Legit service, but often abused to host a fake login page or form. Check who shared it before anyone signs in.",
     "Σύνδεσμος κοινής χρήσης αρχείων ({0}). Νόμιμη υπηρεσία, αλλά συχνά καταχράται για ψεύτικες σελίδες σύνδεσης ή φόρμες. Ελέγξτε ποιος το μοιράστηκε πριν συνδεθεί κανείς."),
    ("Domain ends in .{}, a TLD heavily used for throwaway phishing sites.", "Το domain τελειώνει σε .{0}, κατάληξη που χρησιμοποιείται πολύ για πρόχειρους ιστότοπους phishing."),
    ("Domain ends in .{}, a cheap ending used by many throwaway sites (and by many real shops and events).",
     "Το domain τελειώνει σε .{0}, φθηνή κατάληξη που χρησιμοποιούν πολλοί πρόχειροι ιστότοποι (αλλά και πολλά πραγματικά καταστήματα και εκδηλώσεις)."),
    ("Hostname is dressed up to look like '{}', but the real site is {}.", "Το όνομα είναι φτιαγμένο ώστε να μοιάζει με '{0}', αλλά ο πραγματικός ιστότοπος είναι {1}."),
    ("Unusually deep subdomain chain ({}). Often used to push the real domain out of view on a phone screen.",
     "Ασυνήθιστα μακριά αλυσίδα subdomain ({0}). Χρησιμοποιείται συχνά ώστε το πραγματικό domain να μη φαίνεται στην οθόνη του κινητού."),
    ("{} belongs to {}, but anyone can host files or pages there, so the domain alone proves nothing. Check the screenshot and who shared it.",
     "Το {0} ανήκει στη {1}, αλλά οποιοσδήποτε μπορεί να φιλοξενήσει εκεί αρχεία ή σελίδες, άρα το domain από μόνο του δεν αποδεικνύει τίποτα. Ελέγξτε το στιγμιότυπο και ποιος το μοιράστηκε."),
    ("Real domain {} matches your known list for {}.", "Το πραγματικό domain {0} ταιριάζει με τη γνωστή λίστα σας για {1}."),
    ("Hostname starts with the real {} domain '{}' as a decoy, but the site is actually {}.",
     "Το όνομα ξεκινά με το πραγματικό domain της {0} '{1}' ως δόλωμα, αλλά ο ιστότοπος είναι στην πραγματικότητα {2}."),
    ("Hostname contains a disguised spelling of '{}' (swapped characters), and the real domain is {}, not {}. Classic fake {} page.",
     "Το όνομα περιέχει μεταμφιεσμένη γραφή του '{0}' (αλλαγμένοι χαρακτήρες) και το πραγματικό domain είναι {1}, όχι {2}. Κλασική ψεύτικη σελίδα {3}."),
    ("Hostname contains '{}' but the real domain is {}, not {}. Classic fake {} page.",
     "Το όνομα περιέχει '{0}' αλλά το πραγματικό domain είναι {1}, όχι {2}. Κλασική ψεύτικη σελίδα {3}."),
    ("'{}' is a lookalike of {} ({}) using swapped characters.", "Το '{0}' είναι απομίμηση του {1} ({2}) με αλλαγμένους χαρακτήρες."),
    ("'{}' is spelled very close to {} ({}). Likely typosquat.", "Το '{0}' γράφεται σχεδόν όπως το {1} ({2}). Πιθανή απομίμηση με ορθογραφικό λάθος."),
    ("Link path mentions '{}' but the site is {}, not one of {}'s domains.", "Η διαδρομή του συνδέσμου αναφέρει '{0}' αλλά ο ιστότοπος είναι {1}, όχι κάποιο από τα domain της {2}."),
    ("Content is {}+ characters, longer than any real QR code holds. Only the first part was analysed; treat it as suspicious.",
     "Το περιεχόμενο έχει {0}+ χαρακτήρες, περισσότερους από όσους χωρά πραγματικός κωδικός QR. Αναλύθηκε μόνο το πρώτο μέρος· θεωρήστε το ύποπτο."),
    ("Rewritten by {}. The real destination is {}, and that is what was checked.", "Ξαναγράφτηκε από {0}. Ο πραγματικός προορισμός είναι {1}, και αυτός ελέγχθηκε."),
    ("Link hides a second address inside it ({}). {} is being used as a stepping stone (open redirect).",
     "Ο σύνδεσμος κρύβει μέσα του δεύτερη διεύθυνση ({0}). Το {1} χρησιμοποιείται ως ενδιάμεσος σταθμός (open redirect)."),
    ("Link carries the recipient's email address ({}). Personalised phishing lure; opening it confirms the address to the attacker.",
     "Ο σύνδεσμος περιέχει τη διεύθυνση email του παραλήπτη ({0}). Εξατομικευμένο δόλωμα phishing· το άνοιγμα επιβεβαιώνει τη διεύθυνση στον επιτιθέμενο."),
    ("Link carries the recipient's email address ({}). Newsletters do this too, but a phishing link would use it to confirm the address.",
     "Ο σύνδεσμος περιέχει τη διεύθυνση email του παραλήπτη ({0}). Το κάνουν και τα newsletters, αλλά ένας σύνδεσμος phishing θα το χρησιμοποιούσε για να επιβεβαιώσει τη διεύθυνση."),
    ("Domain {} was registered {} days ago ({}).", "Το domain {0} καταχωρήθηκε πριν από {1} ημέρες ({2})."),
    ("Domain {} is only {} days old ({}).", "Το domain {0} έχει ηλικία μόλις {1} ημερών ({2})."),
    ("Domain {} registered {} ({} days ago).", "Το domain {0} καταχωρήθηκε στις {1} (πριν από {2} ημέρες)."),
    ("Domain age for {}: not checked (online lookups are off).", "Ηλικία του domain {0}: δεν ελέγχθηκε (οι online αναζητήσεις είναι κλειστές)."),
    ("Domain age for {}: {}.", "Ηλικία του domain {0}: {1}."),
    ("VirusTotal: {} engines flag {} as malicious.", "VirusTotal: {0} μηχανές χαρακτηρίζουν το {1} κακόβουλο."),
    ("VirusTotal: {} malicious / {} suspicious for {}.", "VirusTotal: {0} κακόβουλο / {1} ύποπτο για το {2}."),
    ("VirusTotal has never seen this domain ({}). Brand-new or rarely used.", "Το VirusTotal δεν έχει δει ποτέ αυτό το domain ({0}). Ολοκαίνουργιο ή σπάνια χρησιμοποιούμενο."),
    ("VirusTotal: no engines flag {}.", "VirusTotal: καμία μηχανή δεν επισημαίνει το {0}."),
    ("Link redirects and lands on {} ({}).", "Ο σύνδεσμος ανακατευθύνει και καταλήγει στο {0} ({1})."),
    ("urlscan verdict: MALICIOUS (score {}).", "Αποτέλεσμα urlscan: ΚΑΚΟΒΟΥΛΟ (βαθμός {0})."),
    ("Page title: {}", "Τίτλος σελίδας: {0}"),
    ("This link could not be fully checked ({}). Treat it as suspicious.", "Αυτός ο σύνδεσμος δεν ελέγχθηκε πλήρως ({0}). Θεωρήστε τον ύποπτο."),
    # QR payloads
    ("QR holds a whole web page (data: link) instead of a website address. There is no site to look up, which is exactly why attackers use it.",
     "Ο κωδικός QR περιέχει ολόκληρη ιστοσελίδα (σύνδεσμος data:) αντί για διεύθυνση ιστότοπου. Δεν υπάρχει ιστότοπος για έλεγχο, και γι' αυτό ακριβώς το χρησιμοποιούν οι επιτιθέμενοι."),
    ("The hidden page contains a form or script, typical of a credential grab.", "Η κρυφή σελίδα περιέχει φόρμα ή script, τυπικό για υποκλοπή κωδικών."),
    ("QR contains script code, not an address.", "Ο κωδικός QR περιέχει κώδικα script, όχι διεύθυνση."),
    ("QR joins the phone to a Wi-Fi network '{}'. A fake network can watch or redirect traffic. Only join networks ICT has announced.",
     "Ο κωδικός QR συνδέει το κινητό στο δίκτυο Wi-Fi '{0}'. Ένα ψεύτικο δίκτυο μπορεί να παρακολουθεί ή να ανακατευθύνει την κίνηση. Συνδέεστε μόνο σε δίκτυα που έχει ανακοινώσει το ICT."),
    ("QR adds a contact card to the phone. The web link inside it is checked separately below.", "Ο κωδικός QR προσθέτει επαφή στο κινητό. Ο σύνδεσμος που περιέχει ελέγχεται ξεχωριστά παρακάτω."),
    ("QR adds a contact card to the phone.", "Ο κωδικός QR προσθέτει επαφή στο κινητό."),
    ("QR prepares a text message to {}. Premium-rate and scam numbers use this. Check the number is genuine before sending.",
     "Ο κωδικός QR ετοιμάζει μήνυμα SMS προς {0}. Το χρησιμοποιούν αριθμοί υψηλής χρέωσης και απάτες. Ελέγξτε ότι ο αριθμός είναι γνήσιος πριν στείλετε."),
    ("QR starts a call or email to {}. Check it is genuine.", "Ο κωδικός QR ξεκινά κλήση ή email προς {0}. Ελέγξτε ότι είναι γνήσιο."),
    ("QR tries to open or install an app on the phone.", "Ο κωδικός QR προσπαθεί να ανοίξει ή να εγκαταστήσει εφαρμογή στο κινητό."),
    ("QR contains plain text, not a link.", "Ο κωδικός QR περιέχει απλό κείμενο, όχι σύνδεσμο."),
    # PDF
    ("PDF contains hidden actions: {}. Normal invoices and statements do not need these.", "Το PDF περιέχει κρυφές ενέργειες: {0}. Τα κανονικά τιμολόγια και αντίγραφα κίνησης δεν τις χρειάζονται."),
    ("hidden attachment is damaged and could not be opened.", "το κρυφό συνημμένο είναι κατεστραμμένο και δεν άνοιξε."),
    ("PDF was password-protected (unlocked with the supplied password). Locking a PDF is a common trick to get it past email scanners.",
     "Το PDF ήταν κλειδωμένο με κωδικό (ξεκλειδώθηκε με τον κωδικό που δόθηκε). Το κλείδωμα PDF είναι συνηθισμένο τέχνασμα για να περάσει από τους σαρωτές email."),
    ("hidden attachment is password-protected and could not be checked.", "το κρυφό συνημμένο είναι κλειδωμένο με κωδικό και δεν ελέγχθηκε."),
    ("PDF is damaged or malformed and has no readable pages. Some viewers still show content the checker cannot read. Treat as suspicious.",
     "Το PDF είναι κατεστραμμένο ή κακοσχηματισμένο και δεν έχει αναγνώσιμες σελίδες. Κάποια προγράμματα δείχνουν παρ' όλα αυτά περιεχόμενο που ο έλεγχος δεν διαβάζει. Θεωρήστε το ύποπτο."),
    ("PDF is damaged or malformed. Some viewers still show content the checker cannot read. Treat as suspicious.",
     "Το PDF είναι κατεστραμμένο ή κακοσχηματισμένο. Κάποια προγράμματα δείχνουν παρ' όλα αυτά περιεχόμενο που ο έλεγχος δεν διαβάζει. Θεωρήστε το ύποπτο."),
    ("PDF has {} pages; only the first {} were checked.", "Το PDF έχει {0} σελίδες· ελέγχθηκαν μόνο οι πρώτες {1}."),
    ("{}: contains a hidden attached file '{}'. Attackers hide the real lure inside attachments of attachments.",
     "{0}: περιέχει κρυφό συνημμένο αρχείο '{1}'. Οι επιτιθέμενοι κρύβουν το πραγματικό δόλωμα μέσα σε συνημμένα συνημμένων."),
    ("This file could not be opened as a PDF. It may be damaged, or not really a PDF. Damaged files are a known trick to slip past scanners, so treat it as suspicious.",
     "Το αρχείο δεν άνοιξε ως PDF. Μπορεί να είναι κατεστραμμένο ή να μην είναι πραγματικά PDF. Τα κατεστραμμένα αρχεία είναι γνωστό τέχνασμα για να ξεφεύγουν από σαρωτές, άρα θεωρήστε το ύποπτο."),
    ("PDF is password-protected. That alone is a common trick to get past email scanners. Treat as suspicious. If the email gives the password, run again with --password <pw>.",
     "Το PDF είναι κλειδωμένο με κωδικό. Αυτό και μόνο είναι συνηθισμένο τέχνασμα για να περάσει από τους σαρωτές email. Θεωρήστε το ύποπτο. Αν το email δίνει τον κωδικό, γράψτε τον στο πεδίο «Κωδικός PDF» και πατήστε «Επανέλεγχος»."),
    # files
    ("{} is {}. Opening it can run code on the PC. Business documents are never sent like this.",
     "Το {0} είναι {1}. Το άνοιγμά του μπορεί να εκτελέσει κώδικα στο PC. Επαγγελματικά έγγραφα δεν στέλνονται ποτέ έτσι."),
    ("{} has a double extension: it looks like {} but is really {}.", "Το {0} έχει διπλή επέκταση: μοιάζει με {1} αλλά είναι στην πραγματικότητα {2}."),
    ("{} hides its real extension behind many spaces.", "Το {0} κρύβει την πραγματική του επέκταση πίσω από πολλά κενά."),
    ("{} uses a hidden right-to-left character to fake its file type.", "Το {0} χρησιμοποιεί κρυφό χαρακτήρα δεξιά-προς-αριστερά για να παραποιήσει τον τύπο του."),
    ("{} is named {} but is really {}. Disguised files are a common trick.", "Το {0} ονομάζεται {1} αλλά είναι στην πραγματικότητα {2}. Τα μεταμφιεσμένα αρχεία είναι συνηθισμένο τέχνασμα."),
    ("files are nested too deeply; the innermost ones were not checked.", "τα αρχεία είναι φωλιασμένα σε υπερβολικό βάθος· τα εσωτερικότερα δεν ελέγχθηκαν."),
    ("the archive unpacks to far more data than it should (zip bomb). Checking stopped there; treat it as suspicious.",
     "το αρχείο αποσυμπιέζεται σε πολύ περισσότερα δεδομένα από όσα θα έπρεπε (zip bomb). Ο έλεγχος σταμάτησε εκεί· θεωρήστε το ύποπτο."),
    ("{} is two file types at once ({} and a PDF). Such 'polyglot' files are built to fool scanners.",
     "Το {0} είναι δύο τύποι αρχείου ταυτόχρονα ({1} και PDF). Τέτοια αρχεία «polyglot» φτιάχνονται για να ξεγελούν τους σαρωτές."),
    ("{} is {}, which this tool cannot open. Unusual for business email; ask ICT before opening it.",
     "Το {0} είναι {1}, που αυτό το εργαλείο δεν μπορεί να ανοίξει. Ασυνήθιστο για επαγγελματικό email· ρωτήστε το ICT πριν το ανοίξετε."),
    ("RTF document contains an embedded object that can run when opened (a known exploit technique).",
     "Το έγγραφο RTF περιέχει ενσωματωμένο αντικείμενο που μπορεί να εκτελεστεί στο άνοιγμα (γνωστή τεχνική επίθεσης)."),
    ("{} could not be fully checked ({}). Treat it as suspicious.", "Το {0} δεν ελέγχθηκε πλήρως ({1}). Θεωρήστε το ύποπτο."),
    ("{} is a damaged ZIP archive.", "Το {0} είναι κατεστραμμένο αρχείο ZIP."),
    ("archive holds {} files; only the first {} were checked.", "το αρχείο περιέχει {0} αρχεία· ελέγχθηκαν μόνο τα πρώτα {1}."),
    ("{} is a password-protected ZIP. Locked archives are used to hide malware from email scanners.",
     "Το {0} είναι ZIP κλειδωμένο με κωδικό. Τα κλειδωμένα αρχεία χρησιμοποιούνται για να κρύβουν κακόβουλο λογισμικό από τους σαρωτές email."),
    ("'{}' is very large ({} MB) and was not unpacked.", "Το '{0}' είναι πολύ μεγάλο ({1} MB) και δεν αποσυμπιέστηκε."),
    ("'{}' is a zip bomb (compresses {}:1).", "Το '{0}' είναι zip bomb (συμπίεση {1}:1)."),
    ("'{}' could not be unpacked.", "Το '{0}' δεν αποσυμπιέστηκε."),
    ("{} is a disk image (ISO/IMG). Attackers send these because files inside skip Windows' internet-download warnings.",
     "Το {0} είναι εικόνα δίσκου (ISO/IMG). Οι επιτιθέμενοι τα στέλνουν επειδή τα αρχεία μέσα τους παρακάμπτουν τις προειδοποιήσεις λήψης των Windows."),
    ("the disk image could not be opened, so its contents were not checked.", "η εικόνα δίσκου δεν άνοιξε, άρα το περιεχόμενό της δεν ελέγχθηκε."),
    ("This file is empty (0 bytes). Damaged or empty files are a known trick; treat it as suspicious.", "Το αρχείο είναι κενό (0 bytes). Τα κατεστραμμένα ή κενά αρχεία είναι γνωστό τέχνασμα· θεωρήστε το ύποπτο."),
    ("This file could not be opened as a picture. It may be damaged or not really an image.", "Το αρχείο δεν άνοιξε ως εικόνα. Μπορεί να είναι κατεστραμμένο ή να μην είναι πραγματικά εικόνα."),
    ("Nothing was pasted.", "Δεν επικολλήθηκε τίποτα."),
    # email
    ("the email carries a 'sender verified' result that was ignored: {}. A sender can add a fake result to look trustworthy, so the sender counts as NOT verified.",
     "το email φέρει αποτέλεσμα «επαληθευμένος αποστολέας» που αγνοήθηκε: {0}. Ένας αποστολέας μπορεί να προσθέσει ψεύτικο αποτέλεσμα για να φαίνεται αξιόπιστος, άρα ο αποστολέας θεωρείται ΜΗ επαληθευμένος."),
    ("no delivery headers in this file, so the sender cannot be verified (normal for emails saved from Sent items or forwarded as text).",
     "δεν υπάρχουν κεφαλίδες παράδοσης σε αυτό το αρχείο, άρα ο αποστολέας δεν μπορεί να επαληθευτεί (φυσιολογικό για email από τα Απεσταλμένα ή προωθημένα ως κείμενο)."),
    ("the sender could NOT be verified: {} did not confirm this email came from them (DMARC/compauth failed). Strong sign of a spoofed sender.",
     "ο αποστολέας ΔΕΝ επαληθεύτηκε: το {0} δεν επιβεβαίωσε ότι το email προήλθε από αυτό (αποτυχία DMARC/compauth). Ισχυρή ένδειξη πλαστού αποστολέα."),
    ("sender verified: the email really came from {} (DMARC passed). That proves who sent it, not that they are trustworthy.",
     "ο αποστολέας επαληθεύτηκε: το email προήλθε πράγματι από το {0} (επιτυχία DMARC). Αυτό αποδεικνύει ποιος το έστειλε, όχι ότι είναι αξιόπιστος."),
    ("{} does not protect its name (no DMARC result), so anyone could have sent this in its name.",
     "το {0} δεν προστατεύει το όνομά του (χωρίς αποτέλεσμα DMARC), άρα οποιοσδήποτε θα μπορούσε να το έχει στείλει στο όνομά του."),
    ("the sending server is not one {} allows (SPF {}).", "ο διακομιστής αποστολής δεν είναι από αυτούς που επιτρέπει το {0} (SPF {1})."),
    ("the email's digital signature is invalid (DKIM {}); it may have been altered.", "η ψηφιακή υπογραφή του email δεν είναι έγκυρη (DKIM {0})· μπορεί να έχει αλλοιωθεί."),
    ("authentication results: {}", "αποτελέσματα ελέγχου ταυτότητας: {0}"),
    ("the sender's name shows '{}' but the email really came from '{}'. A common way to fake a sender.",
     "το όνομα αποστολέα δείχνει '{0}' αλλά το email προήλθε στην πραγματικότητα από '{1}'. Συνηθισμένος τρόπος παραποίησης αποστολέα."),
    ("the sender calls themselves '{}' but writes from a free mail account '{}', not a {} address.",
     "ο αποστολέας αυτοαποκαλείται '{0}' αλλά γράφει από δωρεάν λογαριασμό email '{1}', όχι από διεύθυνση {2}."),
    ("the sender calls themselves '{}' but writes from '{}', not a {} address.", "ο αποστολέας αυτοαποκαλείται '{0}' αλλά γράφει από '{1}', όχι από διεύθυνση {2}."),
    ("the sender uses our company name ('{}') but writes from '{}'. Internal staff never email from outside addresses.",
     "ο αποστολέας χρησιμοποιεί το όνομα της εταιρείας μας ('{0}') αλλά γράφει από '{1}'. Το προσωπικό δεν στέλνει ποτέ από εξωτερικές διευθύνσεις."),
    ("sender's domain {} is on the known list ({}).", "το domain του αποστολέα {0} είναι στη γνωστή λίστα ({1})."),
    ("the sender's domain {} was registered only {} days ago ({}). New domains are a hallmark of fraud.",
     "το domain του αποστολέα {0} καταχωρήθηκε μόλις πριν από {1} ημέρες ({2}). Τα νέα domain είναι χαρακτηριστικό απάτης."),
    ("the sender's domain {} is less than a year old ({}).", "το domain του αποστολέα {0} έχει ηλικία μικρότερη του έτους ({1})."),
    ("age of the sender's domain {}: not checked (online lookups are off).", "ηλικία του domain του αποστολέα {0}: δεν ελέγχθηκε (οι online αναζητήσεις είναι κλειστές)."),
    ("sent from a free mail account ({}). Fine for private mail, unusual for suppliers, banks or agents.",
     "στάλθηκε από δωρεάν λογαριασμό email ({0}). Εντάξει για προσωπική αλληλογραφία, ασυνήθιστο για προμηθευτές, τράπεζες ή πράκτορες."),
    ("replies go to '{}', not to the sender ({}). Attackers use this so your answer reaches them.",
     "οι απαντήσεις πηγαίνουν στο '{0}', όχι στον αποστολέα ({1}). Οι επιτιθέμενοι το κάνουν ώστε η απάντησή σας να φτάσει σε αυτούς."),
    ("the technical sender (Return-Path) is {}. Normal for mailing services; suspicious if the From address claims to be a person.",
     "ο τεχνικός αποστολέας (Return-Path) είναι {0}. Φυσιολογικό για υπηρεσίες μαζικής αποστολής· ύποπτο αν η διεύθυνση «Από» παριστάνει πρόσωπο."),
    ("first server that handled this email: {} ({} servers in total).", "πρώτος διακομιστής που χειρίστηκε το email: {0} ({1} διακομιστές συνολικά)."),
    ("sender's own IP address (X-Originating-IP): {}", "διεύθυνση IP του αποστολέα (X-Originating-IP): {0}"),
    ("the email {} (\"{}\"). Always confirm bank changes by phone, using a number you already have, never one from the email.",
     "το email {0} («{1}»). Επιβεβαιώνετε πάντα τις αλλαγές τραπεζικών στοιχείων τηλεφωνικά, σε αριθμό που ήδη έχετε, ποτέ σε αριθμό από το email."),
    ("the email {} (\"{}\").", "το email {0} («{1}»)."),
    ("Subject: {}", "Θέμα: {0}"), ("From: {}", "Από: {0}"), ("sent {}", "στάλθηκε {0}"),
    ("{} attachment(s): {}", "{0} συνημμένο(α): {1}"),
    ("contains an attached email '{}' that could not be opened here; save it separately and check it.",
     "περιέχει συνημμένο email '{0}' που δεν άνοιξε εδώ· αποθηκεύστε το χωριστά και ελέγξτε το."),
    ("a link shows '{}' but really goes to '{}'. Classic phishing trick.", "ένας σύνδεσμος δείχνει '{0}' αλλά πηγαίνει στην πραγματικότητα στο '{1}'. Κλασικό τέχνασμα phishing."),
    ("a link is labelled as a file ('{}') but opens a web page on '{}', not that file. Fake 'shared document' links work this way.",
     "ένας σύνδεσμος έχει ετικέτα αρχείου ('{0}') αλλά ανοίγει ιστοσελίδα στο '{1}', όχι το αρχείο. Έτσι δουλεύουν οι ψεύτικοι σύνδεσμοι «κοινόχρηστου εγγράφου»."),
    ("pasted text has no email headers, so the sender could not be checked. For a full check paste the message source (Outlook: File > Properties > Internet headers, then the body under it) or drop the saved .msg / .eml file.",
     "το επικολλημένο κείμενο δεν έχει κεφαλίδες email, άρα ο αποστολέας δεν ελέγχθηκε. Για πλήρη έλεγχο επικολλήστε τον κώδικα του μηνύματος (Outlook: Αρχείο > Ιδιότητες > Κεφαλίδες Internet και από κάτω το σώμα) ή σύρετε το αποθηκευμένο αρχείο .msg / .eml."),
    # html / svg
    ("{} is a login page sent as a file (it mentions '{}'). Real companies never email you a page to type your password into.",
     "Το {0} είναι σελίδα σύνδεσης σταλμένη ως αρχείο (αναφέρει '{1}'). Οι πραγματικές εταιρείες δεν σας στέλνουν ποτέ σελίδα για να γράψετε τον κωδικό σας."),
    ("{} is a login page sent as a file. Real companies never email you a page to type your password into.",
     "Το {0} είναι σελίδα σύνδεσης σταλμένη ως αρχείο. Οι πραγματικές εταιρείες δεν σας στέλνουν ποτέ σελίδα για να γράψετε τον κωδικό σας."),
    ("{} builds a file inside your browser and downloads it (HTML smuggling). This is how malware gets past email scanners.",
     "Το {0} δημιουργεί αρχείο μέσα στον browser σας και το κατεβάζει (HTML smuggling). Έτσι περνά το κακόβουλο λογισμικό από τους σαρωτές email."),
    ("{} carries a hidden file to download.", "Το {0} περιέχει κρυφό αρχείο προς λήψη."),
    ("{} contains scrambled script that hides what the page really does.", "Το {0} περιέχει συγκαλυμμένο script που κρύβει τι κάνει πραγματικά η σελίδα."),
    ("{} has the recipient's email address filled in, a sign of a targeted lure.", "Το {0} έχει προσυμπληρωμένη τη διεύθυνση email του παραλήπτη, ένδειξη στοχευμένου δολώματος."),
    ("{} is a picture that contains program code. Opening it in a browser can redirect you to a phishing page (SVG phishing).",
     "Το {0} είναι εικόνα που περιέχει κώδικα προγράμματος. Το άνοιγμα σε browser μπορεί να σας ανακατευθύνει σε σελίδα phishing (SVG phishing)."),
    ("{} is a picture with a hidden web page inside it.", "Το {0} είναι εικόνα με κρυφή ιστοσελίδα μέσα της."),
    ("{} is a web page sent as a file. Opening it runs in your browser; businesses rarely send these.",
     "Το {0} είναι ιστοσελίδα σταλμένη ως αρχείο. Το άνοιγμα την εκτελεί στον browser σας· οι επιχειρήσεις σπάνια στέλνουν τέτοια."),
    # office
    ("{} is a damaged Office document.", "Το {0} είναι κατεστραμμένο έγγραφο Office."),
    ("{} is a damaged Office file.", "Το {0} είναι κατεστραμμένο αρχείο Office."),
    ("{} contains macros (code that runs if you click 'Enable content'). Do not enable it. Real invoices and statements never need macros.",
     "Το {0} περιέχει μακροεντολές (κώδικας που εκτελείται αν πατήσετε «Ενεργοποίηση περιεχομένου»). Μην το ενεργοποιήσετε. Τα πραγματικά τιμολόγια δεν χρειάζονται ποτέ μακροεντολές."),
    ("{} contains macros (code that runs if you click 'Enable content'). Do not enable it.",
     "Το {0} περιέχει μακροεντολές (κώδικας που εκτελείται αν πατήσετε «Ενεργοποίηση περιεχομένου»). Μην το ενεργοποιήσετε."),
    ("{} connects to a network share ({}) when opened. This can leak your Windows password hash to the attacker.",
     "Το {0} συνδέεται σε κοινόχρηστο φάκελο δικτύου ({1}) όταν ανοίγει. Αυτό μπορεί να διαρρεύσει το hash του κωδικού Windows στον επιτιθέμενο."),
    ("{} loads content from the internet when opened ({}). This 'remote template' trick downloads malware after the file passes scanners.",
     "Το {0} φορτώνει περιεχόμενο από το internet όταν ανοίγει ({1}). Το τέχνασμα «απομακρυσμένου προτύπου» κατεβάζει κακόβουλο λογισμικό αφού το αρχείο περάσει τους σαρωτές."),
    ("{} fetches a {} from the internet when opened (tells the sender you opened it).", "Το {0} κατεβάζει {1} από το internet όταν ανοίγει (ενημερώνει τον αποστολέα ότι το ανοίξατε)."),
    ("{} links to an outside workbook ({}).", "Το {0} συνδέεται με εξωτερικό βιβλίο εργασίας ({1})."),
    ("{} contains a DDE command that can start programs on the PC when the document opens.", "Το {0} περιέχει εντολή DDE που μπορεί να ξεκινήσει προγράμματα στο PC όταν ανοίξει το έγγραφο."),
    ("{} contains a DDE command that can start programs on the PC.", "Το {0} περιέχει εντολή DDE που μπορεί να ξεκινήσει προγράμματα στο PC."),
    ("{} has a file packed inside it: '{}'.", "Το {0} έχει αρχείο πακεταρισμένο μέσα του: '{1}'."),
    ("{} has an embedded object '{}'.", "Το {0} έχει ενσωματωμένο αντικείμενο '{1}'."),
    ("{} is a password-protected Office file, so it cannot be checked. Locking files is a common trick to get past scanners.",
     "Το {0} είναι αρχείο Office κλειδωμένο με κωδικό, άρα δεν μπορεί να ελεγχθεί. Το κλείδωμα αρχείων είναι συνηθισμένο τέχνασμα για να περνούν από σαρωτές."),
    ("{} contains embedded objects.", "Το {0} περιέχει ενσωματωμένα αντικείμενα."),
    # domain watch
    ("Uses the same name servers as your real domain: probably registered by your company.", "Χρησιμοποιεί τους ίδιους name servers με το πραγματικό σας domain: μάλλον καταχωρήθηκε από την εταιρεία σας."),
]

# changing parts that are themselves English phrases
_PARTS_EL = {
    "the sending domain": "το domain αποστολής", "the domain": "το domain",
    "asks you to use new bank details": "ζητά να χρησιμοποιήσετε νέα τραπεζικά στοιχεία",
    "talks about changed bank account numbers": "αναφέρει αλλαγή αριθμών τραπεζικού λογαριασμού",
    "pushes for an urgent payment": "πιέζει για επείγουσα πληρωμή",
    "threatens that your account will expire": "απειλεί ότι ο λογαριασμός σας θα λήξει",
    "asks you to verify your account": "ζητά να επαληθεύσετε τον λογαριασμό σας",
    "asks you to scan a QR code": "ζητά να σαρώσετε κωδικό QR", "mentions gift cards": "αναφέρει δωροκάρτες",
    "asks for secrecy": "ζητά μυστικότητα", "says a file was shared with you": "λέει ότι μοιράστηκαν αρχείο μαζί σας",
    "a PDF": "PDF", "an Office document": "έγγραφο Office", "a ZIP archive": "αρχείο ZIP", "an Office/Outlook file": "αρχείο Office/Outlook",
    "a disk image": "εικόνα δίσκου", "a picture": "εικόνα", "a web page": "ιστοσελίδα", "an SVG picture": "εικόνα SVG",
    "an email": "email", "an RTF document": "έγγραφο RTF", "a Windows program": "πρόγραμμα Windows",
    "a Windows shortcut": "συντόμευση Windows", "a OneNote file": "αρχείο OneNote", "a 7-Zip archive": "αρχείο 7-Zip",
    "a RAR archive": "αρχείο RAR", "a compressed file": "συμπιεσμένο αρχείο", "plain text": "απλό κείμενο",
    "an unknown file type": "άγνωστος τύπος αρχείου", "image": "εικόνα", "audio": "ήχο", "video": "βίντεο",
    "it sits below every delivery line, where only the sender could have put it":
        "βρίσκεται κάτω από όλες τις γραμμές παράδοσης, όπου μόνο ο αποστολέας θα μπορούσε να το έχει βάλει",
    "none of them was written by your own mail server (TRUSTED_AUTHSERV in config.txt)":
        "κανένα δεν γράφτηκε από τον δικό σας διακομιστή email (TRUSTED_AUTHSERV στο config.txt)",
}

# labels in front of a warning that say where it was found
_PREFIX_EL = [("Hidden destination: ", "Κρυφός προορισμός: "), ("Landing page: ", "Σελίδα προορισμού: "),
              ("Worst link: ", "Χειρότερος σύνδεσμος: "), ("sender's domain: ", "domain αποστολέα: "),
              ("Sender's domain: ", "Domain αποστολέα: "), ("email body: ", "σώμα email: "), ("Email body: ", "Σώμα email: "),
              ("attachment '", "συνημμένο '"), ("Attachment '", "Συνημμένο '"), ("page ", "σελίδα "), ("Page ", "Σελίδα ")]


# ------------------------------------------------------------------ where a link was found (2.3)
# "page 2: QR Code (rendered page)", "attachment 'a.zip' > 'b.docx' > link in document", "email body: address in
# the text" ... are built from a fixed set of phrases in the checkers. Names in quotes are never translated.
_LOC = {"email": "στο email", "web page": "στην ιστοσελίδα", "SVG picture": "στην εικόνα SVG"}
_NOM = {"email": "το email", "web page": "η ιστοσελίδα", "SVG picture": "η εικόνα SVG"}
_W = r"(email|web page|SVG picture)"
_WHERE_EL = [   # longest / most specific first
    (r"\bpage (\d+)", r"σελίδα \1"),
    (r"\brendered page\b", "απόδοση σελίδας"),
    (r"\bembedded image\b", "ενσωματωμένη εικόνα"),
    (r"\bclickable link\b", "σύνδεσμος για κλικ"),
    (r"\bURL written in text\b", "διεύθυνση γραμμένη στο κείμενο"),
    (r"\bemail body\b", "σώμα email"),
    (r"\baddress in the text\b", "διεύθυνση στο κείμενο"),
    (r"\blink in RTF text\b", "σύνδεσμος σε κείμενο RTF"),
    (r"\blink in text\b", "σύνδεσμος στο κείμενο"),
    (r"\blink in document\b", "σύνδεσμος στο έγγραφο"),
    (r"\baddress written in document\b", "διεύθυνση γραμμένη στο έγγραφο"),
    (r"\baddress found in document\b", "διεύθυνση που βρέθηκε στο έγγραφο"),
    (r"\bexternal workbook link\b", "εξωτερικός σύνδεσμος βιβλίου εργασίας"),
    (r"\b(\w+) loaded when the document opens\b",
     lambda m: _PARTS_EL.get(m.group(1), m.group(1)) + " που φορτώνεται όταν ανοίγει το έγγραφο"),
    (r"\b(\w+) loaded from the internet\b",
     lambda m: _PARTS_EL.get(m.group(1), m.group(1)) + " που φορτώνεται από το internet"),
    (r"\bin a picture inside the document\b", "σε εικόνα μέσα στο έγγραφο"),
    (r"\bexternal (\w+)", r"εξωτερικό \1"),
    (r"\blink in " + _W, lambda m: "σύνδεσμος " + _LOC[m.group(1)]),
    (r"\bresource loaded by the " + _W, lambda m: "πόρος που φορτώνει " + _NOM[m.group(1)]),
    (r"\bform in the " + _W + " sends typed data here", lambda m: "φόρμα " + _LOC[m.group(1)] + " στέλνει εδώ ό,τι πληκτρολογηθεί"),
    (r"\bautomatic redirect in the " + _W, lambda m: "αυτόματη ανακατεύθυνση " + _LOC[m.group(1)]),
    (r"\bscript redirect in the " + _W, lambda m: "ανακατεύθυνση με script " + _LOC[m.group(1)]),
    (r"\bscript in the " + _W + " sends data here", lambda m: "script " + _LOC[m.group(1)] + " στέλνει δεδομένα εδώ"),
    (r"\baddress in the " + _W, lambda m: "διεύθυνση " + _LOC[m.group(1)]),
    (r"\bin a picture inside the " + _W, lambda m: "σε εικόνα μέσα " + _LOC[m.group(1)]),
    # PDF actions: "PDF [automatic ]JavaScript/Launch (runs a program) action", "PDF link action"
    (r"\(runs a program\)", "(εκτελεί πρόγραμμα)"),
    (r"\(sends typed data to a website\)", "(στέλνει ό,τι πληκτρολογηθεί σε ιστότοπο)"),
    (r"\(opens another file\)", "(ανοίγει άλλο αρχείο)"),
    (r"\(opens an embedded file\)", "(ανοίγει ενσωματωμένο αρχείο)"),
    (r"\bPDF (automatic )?(.+?) action\b",
     lambda m: ("αυτόματη " if m.group(1) else "") + "ενέργεια PDF: " + ("σύνδεσμος" if m.group(2) == "link" else m.group(2))),
    (r"\(shows ", "(εμφανίζει "),
    (r"\((?:picture|image)\)", "(εικόνα)"),
    (r"(^|; |> )image: ", r"\1εικόνα: "),
    (r"\bQR ?Code\b", "κωδικός QR"),
    (r"\battachment (?=\x00)", "συνημμένο "),
]
_WHERE_EL = [(re.compile(a), b) for a, b in _WHERE_EL]


def where(text):
    """'Found in' text in the current language. Quoted names (files, link labels) stay exactly as they are."""
    if language() != "el" or not text:
        return text
    text = text.replace("'picture in the email body (", "'εικόνα στο σώμα του email (")
    quoted = []

    def keep(m):
        quoted.append(m.group(0))
        return f"\x00{len(quoted) - 1}\x00"
    out = re.sub(r"'[^']*'", keep, text)
    for rx, el in _WHERE_EL:
        out = rx.sub(el, out)
    return re.sub(r"\x00(\d+)\x00", lambda m: quoted[int(m.group(1))], out)


# what may stand in front of a warning: "attachment 'a.zip' > 'b.docx' > ", "email body: ", "page 3: ", "Worst link: "
_WHERE = r"(?:(?:attachment )?'[^']*' > |[A-Za-z][A-Za-z' ]{0,24}(?: \d+)?: )*?"


def _compile(template):
    parts = re.split(r"\{\}", template)
    return re.compile("^(?P<pre>" + _WHERE + ")" + "(.+?)".join(re.escape(p) for p in parts) + "$", re.S | re.I)


_COMPILED = None


def _cap(s):
    return s[:1].upper() + s[1:] if s else s


def msg(text):
    """A warning from the checks in the current language. Unknown text comes back unchanged."""
    global _COMPILED
    if language() != "el" or not text:
        return text
    if _COMPILED is None:
        _COMPILED = [(_compile(en), el) for en, el in _M]
    for rx, el in _COMPILED:
        m = rx.match(text)
        if not m:
            continue
        groups = [_PARTS_EL.get(g, g) for g in m.groups()[1:]]
        if groups:                   # the subject of the sentence is often "attachment 'name'"
            groups[0] = re.sub(r"^attachment '", "συνημμένο '", groups[0], flags=re.I)
        pre = m.group("pre")
        for a, b in _PREFIX_EL:
            pre = pre.replace(a, b)
        out = el.format(*groups)
        if pre:                      # "attachment 'x' > Το 'y' είναι..." reads fine; keep the sentence as written
            return pre + out
        return _cap(out) if text[:1].isupper() or out[:1].isupper() else out
    return text


def untranslated(messages):
    """For the tests: which of these English warnings have no Greek yet."""
    old = language()
    set_language("el")
    try:
        return sorted({m for m in messages if msg(m) == m})
    finally:
        set_language(old)
