EMAIL ANALYZER
==============

WHAT IT DOES
------------
Checks suspicious EMAILS and ATTACHMENTS without opening them, and watches for
lookalike domains registered to impersonate us. Two pages, top of the window:

  Check files    drag an email STRAIGHT FROM OUTLOOK into the window, or click
                 "Check selected Outlook email". Saved files work too (.msg / .eml,
                 PDF, Word, Excel, PowerPoint, web page, SVG, ZIP, ISO, picture).
                 Or click "Paste email text" and paste the email as text.
  Domain watch   lists every typo / lookalike of our domains that someone has
                 registered, and whether it can send email. Run it monthly.

What an email check looks at:
  - who really sent it: fake sender names, replies redirected elsewhere,
    lookalikes of our domain and our partners, brand-new domains
  - whether the sender was verified (SPF / DKIM / DMARC), in plain words
  - scam wording: changed bank details, urgent payments, password expiry, secrecy
  - links whose text shows one site but go to another, QR codes in the email
  - every attachment, including files inside ZIPs and documents:
    macros, remote templates, DDE, hidden programs, double extensions,
    fake login pages, HTML smuggling, SVG pictures with code, disk images


Phishing emails often hide a dangerous link inside a QR code in a PDF, so that
the email itself looks clean and you scan it with your phone.

This tool reads every QR code and link in a PDF or picture and tells you where it
really goes, and whether that place looks fake. It never opens the link on your PC.

Use it whenever someone reports a suspicious email with a PDF or a QR code in it.
Do NOT scan the QR code with your phone to "see what it is".


INSTALL (once per PC, about 5 minutes, no admin rights needed)
--------------------------------------------------------------
Easiest: run Email-Analyzer-Setup.exe from ICT. It needs NO internet:
Python and all libraries are inside it. Or, with the zip version:

1. Right-click the zip > Properties > tick Unblock > OK.
2. Right-click the zip > Extract All. Do not run it from inside the zip.
3. Double-click Install.bat in the extracted folder and click Install.
   It checks for Python and installs it for you if it is missing, then sets
   everything up. It needs internet the first time.
4. When it finishes, Email Analyzer opens on its own.

You now have:
  - a Email Analyzer icon on the Desktop and in the Start Menu
  - right-click any PDF > Send to > Email Analyzer
  - an entry in Settings > Apps > Installed apps (use it to uninstall)

API keys: click Settings in the app. Ask ICT which keys to use.
Without keys the offline check still works fully.


EVERYDAY USE
------------
1. In Outlook, click the suspicious email once. Do not open it.
2. Drag it into the Email Analyzer window, or click "Check selected Outlook
   email". (An attachment you saved: drag the file in, or right-click it >
   Send to > Email Analyzer, or click Browse files.)
3. Read the banner at the top. The bold line under the verdict says WHAT TO DO.
   The card under each file repeats it and shows how the score was reached.

Straight from Outlook works with CLASSIC Outlook for Windows. The email is saved
as a copy in Documents\Email Analyzer reports\Outlook and checked; it is never
opened. The "new Outlook" and Outlook on the web cannot do this: drag the email
to the desktop first, or use "Paste email text". If you drag from the new Outlook
by mistake, the window tells you what to do instead.
If the email Outlook hands over is not the one you dragged, nothing is checked
and the window tells you: click the email once in Outlook and drag it again.

Details switch (bottom, next to Open report):
  ON   every reason and the full score breakdown (for ICT).
  OFF  the verdict, what to do, and the main reason only.

"Check domain age now" button: appears under a result when the age of the
domains was not checked. One click turns on Online lookups and checks again.
4. Click "Open report". A readable report opens in your browser with:
     - Quick copy buttons: Ticket summary, Domains to block, All links
     - each link with its verdict and the reasons
   Everything you copy is made unclickable (hxxps, [.]) so nobody opens it.
   "Copy ticket summary" in the app copies the same text directly.
   Scroll the results with the mouse wheel, the scroll bar, Page Up/Down,
   or Home/End.

NOTHING GOES TO THE INTERNET UNLESS YOU SWITCH IT ON (two switches, left side):

Online lookups switch:
  OFF  nothing leaves this PC. Start here.
  ON   asks rdap.org how old each unknown domain is (and VirusTotal, if a key is
       set). Only the DOMAIN NAME is sent, never the full link or the email.
       A domain registered days ago is one of the strongest signs of phishing,
       so turn this on when the result is yellow or low risk and you are unsure.

Live scan switch:
  OFF  nothing visits the link.
  ON   urlscan.io opens the link on ITS servers (never on your PC), follows
       redirects and shows a screenshot of the page in the card.
       Use it when the result is yellow or the link is a short link (bit.ly...).

Paste email text:
  Best: paste the message source WITH headers (Outlook: open the email > File >
  Properties > copy "Internet headers", then paste the body under them). Then
  the sender is checked too. Body text alone also works: wording, links and
  links whose text shows one site but go to another are still checked.

Locked PDF: type the password from the email into "PDF password" on the left,
then click "Check again".


READING THE RESULT
------------------
THE RISK SCORE (0 to 100)
Every warning adds points:  HIGH 70,  MEDIUM 25,  LOW 10.
  70 or more   DANGEROUS    (one HIGH warning is enough)
  25 to 69     SUSPICIOUS   (one MEDIUM, or three LOW together)
  1 to 24      LOW RISK     (one or two weak signals only)
For an email or file the score is: every warning about the email/file itself,
plus its WORST link (not all links, so a newsletter with 30 ordinary links does
not add up to an alarm). The box under each file lists exactly which warnings
added which points. The numbers are at the top of qr_check.py (WEIGHTS).

LOW warnings are things that are common in honest mail too: plain http, a
free mail account, no DMARC, a SharePoint/OneDrive link, a .shop/.online/.live
address, a tracking link with your address in it. One alone means little;
several together, or one next to a real warning, push the score up.

Each link gets a coloured label:

  DANGEROUS (red)      Do not open. Report it to ICT. Delete the email for everyone.
  SUSPICIOUS (amber)   Not proven bad, but needs a closer look. Turn on Live scan
                       and check again, or ask ICT.
  LOW RISK (pale)      Only weak signals. Read the reasons; judge it together with
                       the rest of the email. Turn on Online lookups if unsure.
  KNOWN SITE (green)   The address belongs to a real bank or Microsoft. Still be
                       careful if the email itself was unexpected.
  NO FLAGS (grey)      Nothing wrong was found. That is not a guarantee it is safe.
  NOT A LINK (blue)    The QR holds something else (Wi-Fi, contact card, text).

The banner shows the worst result for the file. Each link has its own card.
Warnings about the FILE itself (password, hidden attachments, hidden scripts,
damaged PDF) appear at the top, before the links.

Above each verdict, each line explains WHY, for example:
  "Hostname contains 'eurobank' but the real domain is secure-login.top"
  "Link carries the recipient's email address"
  "eur0bank.gr is a lookalike of eurobank.gr"


WHERE THE RESULTS ARE SAVED
---------------------------
Next to the PDF you checked:
  name.emailcheck.html        readable report (open it, copy from it, attach it to the ticket,
                           or print it to PDF)
  name.emailcheck.json        the same results for tools and scripts
  name_screenshots\        urlscan screenshots of each page (full check only)


COMMAND LINE (for ICT)
----------------------
The old drag-onto-.bat tools are still in the install folder
(%LOCALAPPDATA%\Programs\Email Analyzer):
  Check-Email.bat "C:\path\file.eml"  [--lookups] [--live] [--open] [--password X]
  Check-Email.bat --paste               paste an email, finish with Ctrl+Z then Enter
  Check-Email-Offline.bat               drag a file on it, offline only
Offline is the default. --lookups = domain age + VirusTotal (domain name only).
--live = urlscan.io visits the link. (Before v2.1 the live scan ran by default.)


LANGUAGE (English / Greek)
--------------------------
Settings > Language: Auto, English or Ελληνικά. Auto = Greek on a Greek Windows.
Close and reopen the app after changing it. The window, the report and the ticket
summary follow the setting. The saved .json is always English.

SETTINGS FILE (config.txt)
--------------------------
Next to the program. Set it BEFORE building the installer and every PC gets it:
  LANGUAGE=auto | en | el
  ORG_NAME=              name shown in the window title and on reports
  SHARED_BANK_LIST=      one brand list for everybody (see below)
  TRUSTED_AUTHSERV=      only if your mail is NOT Microsoft 365 (see below)

ONE SHARED BRAND LIST
---------------------
Put banks.txt on a network share and give its path in Settings (or config.txt):
    SHARED_BANK_LIST=\\server\ict\email-analyzer\banks.txt
Every PC then reads that file, so one edit reaches everyone. Away from the office
the last copy is used. The bottom left of the window shows which list is in use.
IMPORTANT: staff must only be able to READ that share. Whoever can change the
list can mark a fake site as trusted.

THE BANK LIST (banks.txt)
-------------------------
The tool compares every link against the real website addresses of the banks and
companies we deal with. If a link uses a bank's name on the wrong address, it is
flagged red.
Click "Bank list" in the app to view it. Only ICT should edit this file, so everyone uses the same checked list.
To add a bank or supplier, send ICT the company name and its real website.


GOOD TO KNOW
------------
- Links copied from Outlook are wrapped by Microsoft Safe Links (also Proofpoint,
  Barracuda). The tool unwraps them and checks the real destination.
- "Domains to block" only lists a domain when the domain itself is the problem
  (lookalike, throwaway ending, IP address, disguise, malicious live scan).
  Real banks, Microsoft, Google, short links and file-sharing sites never appear.
- SharePoint / OneDrive / Google Forms links are LOW RISK on their own: anyone can
  share files there. With an unverified sender or scam wording they turn yellow
  or red. Add your own company's SharePoint tenant to banks.txt to trust it.
- Add our own email domains on the Domain watch page (or in watch_domains.txt).
  Until you do, emails imitating OUR name are not recognised as such.
- Hidden characters (right-to-left tricks, invisible spaces, terminal codes) are
  shown as <U+202E> style markers so they cannot fake what you see.


WHAT IT CANNOT DO
-----------------
- 7-Zip and RAR archives cannot be opened (they are flagged instead).
- An email forwarded as text, or saved from Sent items, has no delivery headers,
  so the sender cannot be verified (the tool says so).
- With Online lookups off, a brand-new domain is not recognised as new.
- "Sender verified" comes from the result your own mail server wrote into the
  email. A result the sender typed in themselves (it sits below all delivery
  lines) is ignored and reported. A .eml file written by hand from top to bottom
  can still fake it: only check emails that really arrived in a mailbox.
  Not on Microsoft 365? Set TRUSTED_AUTHSERV in config.txt.
- If a REAL website has been hacked, its address still looks correct. Only the
  full check (urlscan) may catch this, not the offline check.
- A brand new fake site may not be known to urlscan or VirusTotal yet.
- Some fake sites show a harmless page to scanners and the real fake page only
  to phones, or only to visitors from Greece. A clean urlscan result is not proof.
- A link can be safe today and switched to a fake page tomorrow.
- Heavily stylised "artistic" QR codes may not be readable.
- Banks and companies not listed in banks.txt get no brand check.
- It only checks links. It does not scan attachments for viruses. If Microsoft
  Defender blocks or removes a file before it can be read, the result says so and
  is DANGEROUS: do not open any copy of that file, report it to ICT.
- If in doubt, treat it as phishing and ask ICT.

Questions or problems: contact ICT.
