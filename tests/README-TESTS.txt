Email Analyzer test suite (for ICT)
======================================
Run after ANY change to qr_check.py, report.py, banks.txt or the libraries.

  cd Developer
  pip install pytest hypothesis qrcode      (plus the program's libraries: see HANDOVER.txt, job D)
  python -m pytest -q tests

The tests find the program in Developer\Email-Analyzer (see conftest.py).
Set EMAIL_ANALYZER_APP to another Email-Analyzer folder to test a copy elsewhere.

What is covered (221 tests; 220 pass, the browser check is skipped without Node.js):
  test_accuracy.py  real-world legitimate links must not be flagged; phishing patterns must be
                    DANGEROUS; risky-but-legit platforms must be SUSPICIOUS
  test_engine.py    Safe Links / Proofpoint unwrapping, own SharePoint tenant, block list rules,
                    IP disguises, hidden email detection and redaction, QR payload types
  test_fuzz.py      thousands of random hostile inputs, corrupted PDFs, attachment bombs,
                    oversized files: nothing may crash or hang
  test_offline_score_paste.py
                    nothing goes online without the switches (even with API keys saved), the risk
                    score and its thresholds, ordinary business mail stays below SUSPICIOUS,
                    pasted emails with and without headers
  test_v22.py       Greek/English coverage, shared brand list, sender-added 'verified' headers,
                    Outlook pickup, what-to-do lines
  test_security.py  report cannot run injected script, hidden characters cannot fake the display,
                    reports still save when the attachment's folder is read-only
                    (the browser part needs Node.js + Playwright, otherwise it is skipped)
  test_files.py     every attack sample is caught, legitimate mail stays clean. Attack samples are
                    checked in memory so Microsoft Defender cannot block them mid-test.
  test_defender.py  (2.3) files Defender blocks or removes are DANGEROUS; a file open in another
                    program is not a warning. Simulated: no real blocked file is needed.
  test_drag.py      (2.3) what classic and new Outlook send when dragging (recorded on a real PC),
                    the dragged-subject check, new messages have Greek
  test_where_greek.py
                    (2.3) every "found in" line from the samples is fully Greek in Greek mode
  test_gui_helpers.py
                    (2.3) shortened folder names under each file
