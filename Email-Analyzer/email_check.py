"""
Full email check for saved .eml and Outlook .msg files.

Sender forensics (display-name tricks, Reply-To / Return-Path redirection, lookalike
domains of our own company and known partners), authentication results explained in
plain words (SPF, DKIM, DMARC, Microsoft compauth), wording used in payment and
password scams, link text that lies about its destination, QR codes in the body,
and every attachment through the file inspectors.
"""
import email
import email.policy
import io
import re
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

import qr_check as E

HIGH, MED, LOW, INFO, GOOD = E.HIGH, E.MED, E.LOW, E.INFO, E.GOOD

SCAM_PHRASES = [
    (r"(new|updated?|chang\w*|amend\w*)\s+(of\s+)?(our\s+)?(bank|banking|account|payment|remittance)\s+(details|information|instructions|account)",
     "asks you to use new bank details", HIGH),
    (r"\b(iban|swift|bic|sort code|routing number)\b.{0,60}\b(chang|new|updat)", "talks about changed bank account numbers", HIGH),
    (r"(urgent|immediate(ly)?|asap|today)\b.{0,40}\b(payment|transfer|wire|remit)", "pushes for an urgent payment", MED),
    (r"(password|mailbox|account)\s+(will\s+)?(expir|suspend|deactivat|lock|clos)", "threatens that your account will expire", MED),
    (r"(verify|confirm|re-?validate|update)\s+your\s+(account|identity|password|mailbox|details|credentials)",
     "asks you to verify your account", MED),
    (r"(scan|use)\s+(the\s+)?qr\s*code", "asks you to scan a QR code", MED),
    (r"(gift\s*cards?|itunes|steam\s*cards?)", "mentions gift cards", LOW),
    (r"(keep\s+this\s+(confidential|between us)|don'?t\s+(tell|discuss)|i'?m\s+in\s+a\s+meeting)", "asks for secrecy", MED),
    (r"(shared|sent)\s+(a\s+)?(document|file|fax|voice\s*mail|voicemail)\s+with\s+you", "says a file was shared with you", INFO),
]


# --------------------------------------------------------------- reading
def is_msg(blob):
    try:
        import olefile
        ole = olefile.OleFileIO(io.BytesIO(blob))
        return any(e[0].startswith("__substg1.0_") for e in ole.listdir(streams=True, storages=False)) \
            or ole.exists("__properties_version1.0")
    except Exception:
        return False


def _msg_prop(ole, base, tag):
    """Read a MAPI property from an .msg (unicode 001F, ansi 001E or binary 0102)."""
    for typ in ("001F", "001E", "0102"):
        path = f"{base}__substg1.0_{tag}{typ}"
        if ole.exists(path):
            data = ole.openstream(path).read()
            if typ == "001F":
                return data.decode("utf-16-le", "ignore").rstrip("\x00")
            if typ == "001E":
                return data.decode("latin-1", "ignore").rstrip("\x00")
            return data
    return None


def read_msg(blob):
    """Turn an Outlook .msg into (headers Message or None, subject, sender_name, sender_addr, text, html, attachments)."""
    import olefile
    ole = olefile.OleFileIO(io.BytesIO(blob))
    headers_text = _msg_prop(ole, "", "007D") or ""
    headers = email.message_from_string(headers_text, policy=email.policy.default) if headers_text.strip() else None
    subject = _msg_prop(ole, "", "0037") or ""
    s_name = _msg_prop(ole, "", "0C1A") or _msg_prop(ole, "", "0042") or ""
    s_addr = _msg_prop(ole, "", "5D01") or _msg_prop(ole, "", "0C1F") or _msg_prop(ole, "", "0065") or ""
    text = _msg_prop(ole, "", "1000") or ""
    html = _msg_prop(ole, "", "1013") or ""
    if isinstance(html, bytes):
        html = html.decode("utf-8", "ignore")
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    attachments = []
    storages = {e[0] for e in ole.listdir(streams=False, storages=True)}
    for st in sorted(s for s in storages if s.startswith("__attach_version1.0_")):
        base = st + "/"
        name = _msg_prop(ole, base, "3707") or _msg_prop(ole, base, "3704") or "attachment"
        data = _msg_prop(ole, base, "3701")
        if isinstance(data, bytes):
            attachments.append((name, data))
        elif ole.exists(base + "__substg1.0_3701000D"):
            attachments.append((name + " (attached email)", None))
    return headers, subject, s_name, s_addr, text, html, attachments


def read_eml(blob):
    msg = email.message_from_bytes(blob, policy=email.policy.default)
    subject = str(msg.get("Subject", "") or "")
    s_name, s_addr = parseaddr(str(msg.get("From", "") or ""))
    text, html, attachments = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        fname = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if not fname and part.get("Content-ID") and ctype.startswith("image/"):
            attachments.append((f"picture in the email body ({ctype.split('/')[-1]})", payload))
        elif fname or disp == "attachment" or (disp == "inline" and not ctype.startswith("text/")):
            attachments.append((fname or f"inline.{ctype.split('/')[-1]}", payload))
        elif ctype == "text/html":
            html += payload.decode(part.get_content_charset() or "utf-8", "ignore")
        elif ctype == "text/plain":
            text += payload.decode(part.get_content_charset() or "utf-8", "ignore")
        elif ctype == "message/rfc822":
            attachments.append(("attached email.eml", part.as_bytes()))
    return msg, subject, s_name, s_addr, text, html, attachments


# --------------------------------------------------------------- checks
def _reg(domain):
    _, reg = E.host_info(domain.lower().strip("."))
    return reg


def known_partner(domain, brands):
    reg = _reg(domain)
    for b in brands:
        for d in b["domains"]:
            if reg == d or domain == d or domain.endswith("." + d):
                return b["name"]
    return None


def parse_auth(headers):
    """Authentication results from the receiving server (Microsoft 365 adds these)."""
    if headers is None:
        return None
    text, problem = trusted_auth_header(headers)
    if text is None:
        return {"untrusted": problem} if problem else None
    res = {}
    for key in ("spf", "dkim", "dmarc", "compauth"):
        m = re.search(rf"\b{key}=(\w+)", text, re.I)
        if m:
            res[key] = m.group(1).lower()
    m = re.search(r"header\.from=([^\s;]+)", text, re.I)
    res["header_from"] = m.group(1).lower() if m else None
    m = re.search(r"smtp\.mailfrom=([^\s;]+)", text, re.I)
    res["mailfrom"] = m.group(1).lower() if m else None
    m = re.search(r"header\.d=([^\s;]+)", text, re.I)
    res["dkim_domain"] = m.group(1).lower() if m else None
    m = re.search(r"compauth=\w+\s+reason=(\d+)", text, re.I)
    res["reason"] = m.group(1) if m else None
    return res


def _authserv(value):
    """The server name at the start of an Authentication-Results header ('' when there is none, as in Microsoft 365)."""
    first = value.split(";", 1)[0].strip()
    return "" if "=" in first else first.split()[0].lower() if first else ""


def trusted_auth_header(headers):
    """Pick the Authentication-Results header written by the RECEIVING mail server, never one the sender added.

    Mail servers add their headers on top, so the receiving server's result is the topmost one and has the
    delivery (Received) lines of the journey underneath it. A result the sender typed into the email sits at
    the bottom, under every Received line. Returns (header_text, None) or (None, reason_it_was_ignored).
    This cannot protect against a .eml file that was written by hand from top to bottom; nothing offline can."""
    import appconfig
    items = headers.items()
    idx = [i for i, (k, _) in enumerate(items) if k.lower() == "authentication-results"]
    if not idx:
        arc = headers.get_all("ARC-Authentication-Results") or []
        return (str(arc[0]), None) if arc else (None, None)
    trusted = [t.strip().lower() for t in appconfig.get("TRUSTED_AUTHSERV").split(",") if t.strip()]
    if trusted:
        for i in idx:
            name = _authserv(str(items[i][1]))
            if any(name == t or name.endswith("." + t) for t in trusted):
                return str(items[i][1]), None
        return None, "none of them was written by your own mail server (TRUSTED_AUTHSERV in config.txt)"
    top = idx[0]
    received_below = any(k.lower() == "received" for k, _ in items[top + 1:])
    received_any = any(k.lower() == "received" for k, _ in items)
    if received_any and not received_below:
        return None, "it sits below every delivery line, where only the sender could have put it"
    return str(items[top][1]), None


def auth_findings(auth, from_domain, notes, where):
    if auth is not None and auth.get("untrusted"):
        notes.append((LOW, f"{where}the email carries a 'sender verified' result that was ignored: {auth['untrusted']}. "
                           "A sender can add a fake result to look trustworthy, so the sender counts as NOT verified."))
        return
    if auth is None:
        notes.append((INFO, f"{where}no delivery headers in this file, so the sender cannot be verified "
                            "(normal for emails saved from Sent items or forwarded as text)."))
        return
    dmarc, spf, dkim, comp = auth.get("dmarc"), auth.get("spf"), auth.get("dkim"), auth.get("compauth")
    if dmarc == "fail" or comp == "fail":
        notes.append((HIGH, f"{where}the sender could NOT be verified: {from_domain or 'the sending domain'} did not "
                            "confirm this email came from them (DMARC/compauth failed). Strong sign of a spoofed sender."))
    elif dmarc in ("pass", "bestguesspass") or comp == "pass":
        notes.append((GOOD, f"{where}sender verified: the email really came from {from_domain or 'the sending domain'} "
                            "(DMARC passed). That proves who sent it, not that they are trustworthy."))
    elif dmarc in (None, "none") and comp in (None, "none", "softpass"):
        notes.append((LOW, f"{where}{from_domain or 'the sending domain'} does not protect its name (no DMARC result), "
                           "so anyone could have sent this in its name."))
    if spf in ("fail", "softfail", "permerror") and dmarc != "pass":
        notes.append((MED, f"{where}the sending server is not one {from_domain or 'the domain'} allows (SPF {spf})."))
    if dkim in ("fail", "permerror") and dmarc != "pass":
        notes.append((MED, f"{where}the email's digital signature is invalid (DKIM {dkim}); it may have been altered."))
    extra = ", ".join(f"{k.upper()}={v}" for k, v in auth.items() if k in ("spf", "dkim", "dmarc", "compauth") and v)
    if extra:
        notes.append((INFO, f"{where}authentication results: {extra}"
                            + (f" (compauth reason {auth['reason']})" if auth.get("reason") else "")))


def sender_findings(s_name, s_addr, headers, brands, notes, where, own_names):
    addr = (s_addr or "").strip().lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    name = (s_name or "").strip()
    notes.append((INFO, f"{where}From: {E.visible(name) + ' ' if name else ''}<{E.visible(addr) or 'unknown'}>"))

    # display name carrying a different email address
    m = E.EMAIL_RE.search(name)
    if m and m.group(0).lower() != addr:
        notes.append((HIGH, f"{where}the sender's name shows '{E.visible(m.group(0))}' but the email really came "
                            f"from '{E.visible(addr)}'. A common way to fake a sender."))
    # display name pretending to be our company / a known partner
    if domain and name:
        lname = name.lower()
        for b in brands:
            hit = next((k for k in b["keywords"] + [b["name"].lower()] if len(k) >= 4 and k in lname), None)
            if hit and not known_partner(domain, [b]):
                free = _reg(domain) in FREE_MAIL
                notes.append((HIGH, f"{where}the sender calls themselves '{E.visible(name)}' but writes from "
                                    f"{'a free mail account ' if free else ''}'{E.visible(domain)}', not a {b['name']} address."))
                break
        for own in own_names:
            if own in lname and not known_partner(domain, brands):
                notes.append((HIGH, f"{where}the sender uses our company name ('{E.visible(name)}') but writes from "
                                    f"'{E.visible(domain)}'. Internal staff never email from outside addresses."))
                break
    # the sender's domain itself: lookalikes, risky endings, new domains
    if domain:
        partner = known_partner(domain, brands)
        if partner:
            notes.append((GOOD, f"{where}sender's domain {domain} is on the known list ({partner})."))
        else:
            findings, reg = E.domain_checks("https://" + domain + "/", brands)
            for lv, msg in findings:
                if lv in (HIGH, MED, LOW) and not msg.startswith(("Plain http", "Link path")):
                    notes.append((lv, f"{where}sender's domain: {msg}"))
            if reg and reg not in FREE_MAIL:
                days, info = E.rdap_age(reg)
                if days is not None and days < 60:
                    notes.append((HIGH, f"{where}the sender's domain {reg} was registered only {days} days ago ({info}). "
                                        "New domains are a hallmark of fraud."))
                elif days is not None and days < 365:
                    notes.append((MED if days < 180 else LOW,
                                  f"{where}the sender's domain {reg} is less than a year old ({info})."))
                elif days is None and info == E.AGE_OFF:
                    notes.append((INFO, f"{where}age of the sender's domain {reg}: {info}."))
            if _reg(domain) in FREE_MAIL:
                notes.append((LOW, f"{where}sent from a free mail account ({domain}). Fine for private mail, "
                                   "unusual for suppliers, banks or agents."))

    if headers is not None:
        # Reply-To pointing somewhere else
        for rname, raddr in getaddresses([str(v) for v in headers.get_all("Reply-To") or []]):
            raddr = raddr.lower()
            rdom = raddr.rsplit("@", 1)[-1] if "@" in raddr else ""
            if rdom and domain and _reg(rdom) != _reg(domain):
                lvl = HIGH if (_reg(rdom) in FREE_MAIL or not known_partner(rdom, brands)) else MED
                notes.append((lvl, f"{where}replies go to '{E.visible(raddr)}', not to the sender ({E.visible(addr)}). "
                                   "Attackers use this so your answer reaches them."))
        # Return-Path / envelope sender
        rp = parseaddr(str(headers.get("Return-Path", "") or ""))[1].lower()
        if rp and domain and "@" in rp and _reg(rp.rsplit("@", 1)[-1]) != _reg(domain):
            notes.append((INFO, f"{where}the technical sender (Return-Path) is {E.visible(rp)}. Normal for mailing "
                                "services; suspicious if the From address claims to be a person."))
    return domain


def header_facts(headers, notes, where):
    if headers is None:
        return
    received = headers.get_all("Received") or []
    if received:
        first = str(received[-1])
        ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", first) or re.search(r"\((?:[^()]*?)(\d{1,3}(?:\.\d{1,3}){3})", first)
        if ip:
            notes.append((INFO, f"{where}first server that handled this email: {ip.group(1)} "
                                f"({len(received)} servers in total)."))
    xip = str(headers.get("X-Originating-IP", "") or "").strip("[] ")
    if xip:
        notes.append((INFO, f"{where}sender's own IP address (X-Originating-IP): {xip}"))
    dt = headers.get("Date")
    if dt:
        try:
            when = parsedate_to_datetime(str(dt))
            notes.append((INFO, f"{where}sent {when:%d %b %Y %H:%M} ({when:%z})"))
        except Exception:
            pass


def wording_findings(subject, text, notes, where):
    body = f"{subject}\n{text}"[:200000]
    seen = set()
    for pattern, what, lvl in SCAM_PHRASES:
        if what in seen:
            continue
        m = re.search(pattern, body, re.I | re.S)
        if m:
            seen.add(what)
            extra = (" Always confirm bank changes by phone, using a number you already have, never one from the email."
                     if "bank" in what else "")
            notes.append((lvl, f"{where}the email {what} (\"{E.visible(m.group(0)[:70])}\").{extra}"))


# --------------------------------------------------------------- entry points
def _own_names(brands):
    names = []
    for b in brands:
        if b["name"].lower().startswith(("our company", "own company")):
            names += [k for k in b["keywords"] if len(k) >= 4]
    return names


def _inspect(name, where, depth, ctx, headers, subject, s_name, s_addr, text, html, attachments):
    import inspectors
    import web_check
    brands = E.load_brands()
    w = where
    ctx.notes.append((INFO, f"{w}Subject: {E.visible(subject or '(no subject)')}"))
    domain = sender_findings(s_name, s_addr, headers, brands, ctx.notes, w, _own_names(brands))
    auth_findings(parse_auth(headers), domain, ctx.notes, w)
    header_facts(headers, ctx.notes, w)
    plain = text or re.sub(r"<[^>]+>", " ", html)
    wording_findings(subject, plain, ctx.notes, w)

    body_where = f"{w}email body: " if w else "email body: "
    if html:
        web_check.inspect(name, html.encode("utf-8", "ignore"), body_where, depth, ctx, attachment=False)
    if text:
        if not html:
            link_text_findings(text, ctx.notes, w)
        for u in inspectors.urls_in_text(text):
            ctx.items.append((u, f"{body_where}address in the text"))

    if attachments:
        ctx.notes.append((INFO, f"{w}{len(attachments)} attachment(s): "
                                + ", ".join(E.visible(n) for n, _ in attachments[:10])
                                + (" ..." if len(attachments) > 10 else "")))
    for aname, data in attachments:
        if data is None:
            ctx.notes.append((MED, f"{w}contains an attached email '{E.visible(aname)}' that could not be opened here; "
                                   "save it separately and check it."))
            continue
        inspectors.analyze(aname, data, f"{w}attachment '{E.visible(aname)}' > ", depth + 1, ctx)


def inspect_eml(name, blob, where, depth, ctx):
    msg, subject, s_name, s_addr, text, html, atts = read_eml(blob)
    _inspect(name, where, depth, ctx, msg, subject, s_name, s_addr, text, html, atts)


def inspect_msg(name, blob, where, depth, ctx):
    headers, subject, s_name, s_addr, text, html, atts = read_msg(blob)
    if headers is not None and not s_addr:
        s_name, s_addr = parseaddr(str(headers.get("From", "") or ""))
    elif headers is not None:
        h_name, h_addr = parseaddr(str(headers.get("From", "") or ""))
        if "@" not in (s_addr or "") and h_addr:     # Exchange-internal addresses (/O=EXCHANGELABS/...)
            s_name, s_addr = h_name or s_name, h_addr
    _inspect(name, where, depth, ctx, headers, subject, s_name, s_addr, text, html, atts)


OUTLOOK_LINK_RE = re.compile(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}[^\s<>]*)\s?<(https?://[^>\s]+)>", re.I)


def link_text_findings(text, notes, where):
    """Plain text shows a link as:  text shown <https://real.destination>  (Outlook and most mail programs)."""
    import web_check
    for m in OUTLOOK_LINK_RE.finditer(text[:200000]):
        shown, real = web_check._domain_in(m.group(1)), web_check._host(web_check.real_destination(m.group(2)))
        if shown and real and not web_check._same_site(shown, real):
            notes.append((HIGH, f"{where}a link shows '{E.visible(shown)}' but really goes to "
                                f"'{E.visible(real)}'. Classic phishing trick."))


def inspect_pasted(text, where, depth, ctx):
    """Email text pasted WITHOUT headers (copied from the reading pane, or the HTML source of the body).
    Wording, links and link-text tricks are checked; the sender cannot be."""
    import inspectors
    import web_check
    ctx.notes.append((INFO, f"{where}pasted text has no email headers, so the sender could not be checked. For a full "
                            "check paste the message source (Outlook: File > Properties > Internet headers, then "
                            "the body under it) or drop the saved .msg / .eml file."))
    is_html = bool(re.search(r"<(html|body|a|div|table|p|img|span|td)\b[^>]*>", text[:20000], re.I))
    plain = re.sub(r"<[^>]+>", " ", text) if is_html else text
    wording_findings("", plain, ctx.notes, where)
    body_where = f"{where}email body: "
    if is_html:
        web_check.inspect("pasted email", text.encode("utf-8", "ignore"), body_where, depth, ctx, attachment=False)
        return
    link_text_findings(text, ctx.notes, where)
    for u in inspectors.urls_in_text(text):
        ctx.items.append((u, f"{body_where}address in the text"))


FREE_MAIL = set()


def _load_free_mail():
    import inspectors
    FREE_MAIL.update(inspectors.FREE_MAIL)


_load_free_mail()
