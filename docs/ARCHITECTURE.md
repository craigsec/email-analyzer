# Email Analyzer — Architecture & Maintainer Notes

Version 2.3. For anyone maintaining or extending this tool.

## What this is

A Windows desktop tool that checks a suspicious email or attachment and
returns a verdict, a plain "what to do," a 0–100 risk score, and every
reason behind that score. It sits *next to* Microsoft Defender, not in
place of it. It never opens a link and never runs an attachment. It sends
nothing to the internet unless a switch is turned on.

It started as a QR-code checker ("QR Link Inspector") for links hidden in
PDFs and grew into a full email checker. That's why a few file names still
say `qr_` (`qr_check.py`, `qr_gui.pyw`, `qr_inspector.ico`) — they were left
alone on purpose, since renaming them adds risk for no benefit.

Nothing is compiled. It's plain Python you can read and change.

## Layout

```
Email-Analyzer/          the program — plain Python, edit here
  qr_gui.pyw             the window
  qr_check.py            CLI + link checks + risk score + PDF/QR reading
  inspectors.py          works out what a file really is, routes it
  email_check.py         emails: sender, auth results, scam wording
  web_check.py           HTML/SVG, and the links inside an email body
  office_check.py        Word, Excel, PowerPoint
  domain_watch.py        the "Domain watch" page (lookalike domains)
  report.py              the HTML report and the ticket summary
  i18n.py                English and Greek
  appconfig.py           reads config.txt, handles the shared brand list
  outlook_grab.py        pulls the selected email out of classic Outlook
  banks.txt, config.txt, keys.txt, watch_domains.txt   data files you edit
tests/                   220+ automated tests and sample attack files
Email-Analyzer-Setup.iss, Build-Setup.bat, fetch-*.ps1   installer build chain
```

To work on this with an AI assistant, hand it this whole repo and this file.

## How an email flows through the code

```
window / command line / Outlook pickup
      |
inspectors.py     looks at the file's content (never its name), decides what it is
      |
email_check.py / web_check.py / office_check.py / PDF+QR in qr_check.py
      |           (files inside files go back through inspectors.py, up to 4 levels deep)
      |
two lists come out:  notes = warnings about the email/file itself
                      items = every link and QR code found, with where it was found
      |
qr_check.py       scores every link
      |
report.py         adds it up: all notes + the WORST link = the score for the email
      |
window, HTML report, ticket summary   (i18n.py translates for display)
```

Every warning is a pair: `(LEVEL, "English sentence explaining why")`.
`LEVEL` is `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `GOOD`. Only `HIGH`, `MEDIUM`,
and `LOW` add points.

## Why it's built this way (read before changing behaviour)

- **Every warning says why.** A flag with no explanation is useless to a
  colleague and can't be audited. Never add a check that only says
  "suspicious."
- **Rules, not guesswork.** Each check is a fixed rule you can read. No
  machine learning. The same email always gives the same result.
- **Offline by default.** Every web request goes through one function,
  `qr_check._http()`. Any new online check should go through it too — never
  call `requests` directly.
  - "Online lookups" = domain age (rdap.org) and VirusTotal. Only the
    domain name is sent.
  - "Live scan" = urlscan.io visits the link from its own servers.
  - The price: with lookups off, a brand-new domain isn't recognised as
    new. That's why the "Check domain age now" button exists.
- **The score.** `HIGH` = 70, `MEDIUM` = 25, `LOW` = 10. 25+ is suspicious,
  70+ is dangerous. Early versions made a single weak signal enough to flag
  an email amber, and most ordinary business mail came out amber — people
  stop reading amber. `LOW` exists for things that are common in honest
  mail too (plain http, a Gmail sender, no DMARC, a SharePoint link, a
  `.shop` address). One `LOW` alone means little; three together, or one
  next to a real warning, cross the line.
- **Only the worst link counts** for an email, so a newsletter with 30
  ordinary links doesn't add up to an alarm.
- **The engine speaks English.** Tests and the saved `.json` rely on the
  English wording. Greek is added only on display (`i18n.py`). A warning
  with no Greek translation is shown in English, never dropped.
- **Hostile input.** Everything checked is treated as a potential attack:
  size limits, depth limits, hidden characters shown as `<U+202E>`-style
  markers, links defanged (`hxxps`, `[.]`) in anything copied out. Keep it
  that way — never add code that opens, runs, or fetches what's being
  checked.

## Routine jobs

**Add a bank, supplier, or partner** — edit `banks.txt`:
`Name | real domains (comma separated) | brand words to watch for`. Keep
watch-words specific — a generic word like "piraeus" once flagged every
honest site that happened to contain it; `piraeusbank` is the right level
of specificity.

**Make it stricter or more relaxed** — `WEIGHTS`, `DANGER_AT`, and
`SUSPICIOUS_AT` at the top of `qr_check.py`. Change them there and nowhere
else. To change one warning's severity, find its sentence in the code and
change its level. Then run the tests — some of them pin the current
policy.

**Add a new warning:**
1. Add it in the checker it belongs to: `notes.append((MED, f"{where}plain sentence why"))`.
2. Add its Greek line to the `_M` list in `i18n.py` (same sentence, `{}`
   where a value changes).
3. Add a test — one sample that must trigger it, one honest sample that
   must not. `test_every_sample_warning_has_greek` fails if you forget
   step 2 for a warning the samples produce.

**Run the tests** (after any change, before every build):
```
cd Email-Analyzer
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt pytest hypothesis qrcode
.venv\Scripts\python -m pytest -q ../tests
```
`tests/conftest.py` locates the app via `EMAIL_ANALYZER_APP` or by its
default relative path. All tests should pass without internet, and with
Defender switched on. One GUI-layout test needs a real display and is
skipped elsewhere.

**Release a new version:** bump `APP_VERSION` in `qr_gui.pyw`,
`$Version` in `setup/install.ps1`, and `AppVersion` in
`Email-Analyzer-Setup.iss` together; confirm `keys.txt` is empty before
packaging (anyone who installs the build gets whatever is in it); run the
tests; build.

**Security updates for the libraries** — PyMuPDF, Pillow, and zxing-cpp all
read hostile files with the user's own rights. When any of them ship a
security fix, bump the version in `requirements.txt` and rebuild. This is
the tool's own main attack surface — worth checking a few times a year.

## What has and hasn't been exercised

Versions 2.0–2.2 were developed without a Windows machine or a screen to
test on. Version 2.3 was the first run and fixed against a real Windows 11
PC with Defender on and both classic and new Outlook. What that turned up
is fixed, with the reasoning in code comments near each fix (search for
"2.3"), and pinned by tests. Still open:
- The upgrade path from the earliest "QR Link Inspector" branding — needs
  a machine that still has that version installed.
- A native-Greek-speaker read-through of the translated strings.

## Known limits and open items

- **Thresholds are young** — tuned on a small set of written sample
  emails plus a handful of real ones. Running a larger batch of real
  reported phishing through it and re-tuning the weights is the single
  highest-value next step.
- **No malware scanning of attachments.** It flags dangerous types,
  macros, and tricks only; when Defender blocks a file first, the tool
  reports that and calls it dangerous. Never add a Defender exclusion to
  make a file readable for testing.
- **7-Zip and RAR archives aren't opened** — flagged, not inspected.
- **"Sender verified" trusts the result the receiving mail server wrote
  into the email.** A result the sender added themselves is ignored, but a
  `.eml` built by hand from scratch can still fake the whole chain — this
  tool is for mail that actually arrived in a mailbox.
- A file named like a document (`Quote.pdf`) that opens a web page
  elsewhere is scored `MEDIUM`, not `HIGH`, because legitimate vendors do
  this too.
- One known false-negative left on purpose: a very close lookalike domain
  can still slip under the look-alike rule if tightening the rule would
  cause more false positives than it prevents — the tradeoff is
  deliberate, documented in the code where it applies.
- The new Outlook and Outlook on the web can't hand over an email to a
  desktop app directly (drag to desktop, or paste the email text, works
  around it). If Microsoft changes what the new Outlook's drag payload
  looks like, `outlook_grab.classify_drag` is the one place to update.
- API keys sit in plain text in `keys.txt` on each machine. Fine for a
  handful of workstations; reconsider before rolling this out widely.
- Ideas not built yet: attachment file-hash lookup against VirusTotal,
  opening 7z/RAR, reply-chain hijack detection, a central log of results.

## Rules that keep it safe

- Never commit or ship a `keys.txt` with real keys in it.
- A shared brand list must be read-only for end users — whoever can edit
  it can mark a fake site as trusted.
- New online checks go through `qr_check._http()` so the offline promise
  stays true.
- Never show attacker-controlled text without `qr_check.visible()`, and
  never put a clickable link from a checked email into a report
  (`report.defang()`).
- Don't open a real suspicious file on your own machine without the tool,
  "just to see what it is."
