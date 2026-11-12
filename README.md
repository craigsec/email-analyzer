<p align="center">
  <img src="Email-Analyzer/qr_inspector.png" width="96" alt="Email Analyzer icon">
</p>

<h1 align="center">Email Analyzer</h1>

<p align="center">
  A Windows desktop tool that checks a suspicious email or attachment<br>
  and tells you, in plain language, whether it's safe to open.
</p>

---

## What it does

Drag a suspicious email straight out of Outlook, or drop a saved
`.msg`/`.eml`/PDF/Office file, and Email Analyzer tells you what it found,
why, and what to do about it — without ever opening the attachment, running
a macro, or visiting a link on your machine.

It checks:

- **who really sent it** — spoofed display names, mismatched reply-to
  addresses, lookalikes of your own domain or your partners', brand-new
  domains
- **whether the sender was verified** (SPF/DKIM/DMARC), explained in plain
  words instead of raw header jargon
- **scam language** — changed bank details, urgent payments, password
  expiry, requests for secrecy
- **links that lie** — anchor text showing one address while the href
  points somewhere else, QR codes hidden inside a PDF or image
- **every attachment**, including files nested inside ZIPs and Office
  documents: macros, remote template injection, DDE, hidden embedded
  programs, double extensions, fake login pages, HTML smuggling, SVGs with
  embedded script, disk images

Every verdict comes with a 0–100 risk score and a plain-English reason for
every point of it — no black-box "trust me," and no machine learning
making a different call on the same input twice.

## Where it came from

This started as a one-off: a checker for QR codes hidden inside PDF
attachments, the trick phishing kits were using to get a dangerous link
past a mail filter and onto someone's phone camera instead. That's still
visible in a few filenames (`qr_check.py`, `qr_gui.pyw`) — left alone on
purpose, because renaming them later would've added risk for no benefit.

It grew from there into a full email, link, and attachment analyzer: sender
verification, scam-language detection, Office/PDF/HTML/SVG inspection,
and a lookalike-domain watcher, built out one real phishing report at a
time.

## How it's built

- **Rules you can read, not a model you have to trust.** Every check is a
  fixed, auditable rule. The same input always produces the same output.
- **Offline by default.** Nothing leaves the machine unless you flip a
  switch. Every outbound request — domain-age lookups, VirusTotal,
  urlscan.io — funnels through one function, so the offline guarantee is
  enforceable, not just a promise in the docs.
- **Every warning explains itself.** A flag with no reason attached is
  useless to the person reading the report and impossible to audit, so
  the rule is: no silent flags, ever.
- **Scored, not binary.** `HIGH`/`MEDIUM`/`LOW` weighted findings, with
  only the worst link on a page counted — so a newsletter with thirty
  ordinary links doesn't read as an alarm, and one real red flag can't get
  diluted by a wall of harmless ones.
- **Built for the mailbox, not the lab.** Hidden Unicode tricks, nested
  archives up to four levels deep, locked PDFs, nine different file
  formats — all treated as hostile input with size and depth limits,
  because the whole point is handling what actually lands in someone's
  inbox.
- **Bilingual.** English and Greek, with a test that fails the build if a
  warning the sample files produce has no Greek translation.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design
rationale, the data flow through the checkers, and the known limitations
— written the way I'd want it written for whoever picks this up next.

## Tech stack

Python · CustomTkinter (desktop UI) · PyMuPDF (PDF parsing) · zxing-cpp
(QR decoding) · Pillow · dnspython (lookalike-domain watching) · Inno
Setup (offline Windows installer) · pytest + Hypothesis (220+ tests,
sample attack files included)

## Running it

```
cd Email-Analyzer
pip install -r requirements.txt
python qr_gui.pyw          # the desktop window (Windows)
python qr_check.py --paste # command line, any OS: paste an email, Ctrl+Z, Enter
```

Everything works with no API keys at all — the offline checks (sender
verification, scam wording, link structure, attachment inspection) run
fully locally. Two optional switches turn on network lookups:
[urlscan.io](https://urlscan.io) and [VirusTotal](https://virustotal.com)
free-tier API keys go in `Email-Analyzer/keys.txt` if you want domain-age
checks and live link scanning.

Full user guide: [`Email-Analyzer/README.txt`](Email-Analyzer/README.txt)
(English) / [`Email-Analyzer/README-EL.txt`](Email-Analyzer/README-EL.txt)
(Greek, short form).

## Building the installer

`Build-Setup.bat` on Windows produces a single offline `.exe` — Python and
every dependency bundled in, so the machine it's installed on needs no
internet connection. See [`HOW-TO-BUILD.txt`](HOW-TO-BUILD.txt).

## Testing

```
pip install -r Email-Analyzer/requirements.txt pytest hypothesis qrcode
python -m pytest tests
```

206 tests, synthetic phishing/legitimate sample emails included, no
network access required. The GUI-layout tests need a real Windows display
and are skipped elsewhere (noted in `docs/ARCHITECTURE.md`).

## License

MIT — see [`LICENSE`](LICENSE).
