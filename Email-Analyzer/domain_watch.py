"""
Lookalike domain watch.

Generates the domains an attacker would register to impersonate us or a partner
(typos, swapped letters, look-alike characters, extra words, other endings,
foreign-alphabet letters) and checks which ones actually exist, whether they can
send/receive email, whether they have a website, and how old they are.
Needs internet (DNS). Refuses to report "all clear" when DNS is not working.
"""
import concurrent.futures as cf
import re
from datetime import datetime

import qr_check as E

HIGH, MED, INFO = E.HIGH, E.MED, E.INFO

KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
    "p": "ol", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn",
    "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
LOOKALIKE = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "m": ["rn", "nn"], "w": ["vv"], "d": ["cl"], "e": ["3"],
             "a": ["4"], "s": ["5"], "g": ["q", "9"], "u": ["v"], "n": ["m"], "b": ["6"], "t": ["7"]}
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у",
            "i": "і", "s": "ѕ", "j": "ј"}
WORDS = ["group", "maritime", "shipping", "ships", "shipmanagement", "marine", "invoice", "invoices", "payment",
         "payments", "finance", "accounts", "billing", "mail", "secure", "login", "portal", "hr", "it", "support",
         "gr", "greece", "ltd", "inc", "online", "office", "management", "crew", "tankers", "bulk"]
TLDS = ["com", "net", "org", "gr", "com.gr", "co", "io", "info", "biz", "eu", "me", "us", "co.uk", "uk", "de",
        "shop", "online", "site", "top", "xyz", "cc", "ltd", "group", "email", "support", "services", "live",
        "app", "cloud", "global", "world", "marine", "co.com", "net.gr", "org.gr", "cy", "com.cy", "ae", "sg"]


def split(domain):
    ext = E.EXTRACT(domain.lower().strip().strip("."))
    return ext.domain, ext.suffix


def variants(domain, max_total=2500):
    """Every lookalike an attacker might register. Returns {domain: technique}."""
    label, suffix = split(domain)
    if not label or not suffix:
        return {}
    out = {}

    def add(lbl, sfx, how):
        lbl = lbl.strip("-")
        if not lbl or ("--" in lbl and not lbl.startswith("xn--")) or len(lbl) > 63:
            return
        d = f"{lbl}.{sfx}"
        if d != f"{label}.{suffix}" and d not in out:
            out[d] = how

    typos = {}
    for i in range(len(label)):
        typos.setdefault(label[:i] + label[i + 1:], "missing letter")
        typos.setdefault(label[:i] + label[i] + label[i:], "doubled letter")
        if i < len(label) - 1:
            typos.setdefault(label[:i] + label[i + 1] + label[i] + label[i + 2:], "swapped letters")
        for k in KEYBOARD.get(label[i], ""):
            typos.setdefault(label[:i] + k + label[i + 1:], "keyboard typo")
        for k in LOOKALIKE.get(label[i], []):
            typos.setdefault(label[:i] + k + label[i + 1:], "look-alike characters")
        if 0 < i < len(label):
            typos.setdefault(label[:i] + "-" + label[i:], "added hyphen")
    for a, b in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        if a in label:
            typos.setdefault(label.replace(a, b, 1), "look-alike characters")
    typos.setdefault(label + "s", "added letter")
    typos.pop(label, None)

    for t, how in typos.items():
        add(t, suffix, how)
        if suffix != "com":
            add(t, "com", how + ", .com")
    for w in WORDS:
        for lbl in (f"{label}-{w}", f"{label}{w}", f"{w}-{label}"):
            for sfx in {suffix, "com"}:
                add(lbl, sfx, "added word")
    for t in TLDS:
        add(label, t, "different ending")
    # foreign-alphabet look-alikes (shown in browsers as the real name)
    for i, ch in enumerate(label):
        if ch in CYRILLIC:
            fake = label[:i] + CYRILLIC[ch] + label[i + 1:]
            try:
                add(fake.encode("idna").decode(), suffix, f"foreign letter ({fake})")
            except Exception:
                pass
    return dict(list(out.items())[:max_total])


class DNS:
    """Small wrapper so tests can replace DNS."""
    def __init__(self):
        import dns.resolver
        self.r = dns.resolver.Resolver()
        self.r.lifetime = 4
        self.r.timeout = 2

    def query(self, name, rtype):
        """Returns list of answers, [] when the name exists without that record, None when it does not exist.
        Raises on network trouble."""
        import dns.exception
        import dns.resolver
        try:
            return [str(a).rstrip(".") for a in self.r.resolve(name, rtype)]
        except dns.resolver.NXDOMAIN:
            return None
        except (dns.resolver.NoAnswer,):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise ConnectionError(str(e))


def dns_works(dns, own_domains):
    """Refuse to say 'all clear' if DNS is broken or filtered (everything 'does not exist')."""
    try:
        controls = [dns.query(d, "NS") for d in ["microsoft.com", "google.com"] + list(own_domains)[:1]]
    except ConnectionError:
        return False
    return all(c for c in controls)


def check_one(dns, domain):
    res = {"domain": domain, "exists": None, "mx": [], "a": [], "ns": []}
    try:
        ns = dns.query(domain, "NS")
        if ns is None:
            res["exists"] = False
            return res
        res["exists"] = True
        res["ns"] = ns or []
        res["mx"] = dns.query(domain, "MX") or []
        res["a"] = dns.query(domain, "A") or []
    except ConnectionError:
        res["exists"] = None
    return res


def watch(domains, dns=None, progress=None, rdap=True, workers=24):
    """Check every lookalike of every watched domain. Returns (results, problems)."""
    dns = dns or DNS()
    own = [d.lower().strip() for d in domains if d.strip()]
    if not own:
        return [], ["Add at least one domain to watch."]
    if not dns_works(dns, own):
        return [], ["DNS is not working or is filtered on this network, so lookalike domains cannot be checked "
                    "reliably. Try again from a normal office connection."]
    own_ns = {}
    for d in own:
        try:
            own_ns[d] = set(dns.query(d, "NS") or [])
        except ConnectionError:
            own_ns[d] = set()

    todo = {}
    for d in own:
        for v, how in variants(d).items():
            if v not in own and v not in todo:
                todo[v] = (d, how)
    results, problems = [], []
    done = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_one, dns, v): v for v in todo}
        for f in cf.as_completed(futs):
            done += 1
            if progress and done % 25 == 0:
                progress(done, len(todo))
            r = f.result()
            if r["exists"] is None:
                problems.append(r["domain"])
            if not r["exists"]:
                continue
            base, how = todo[r["domain"]]
            r["imitates"], r["technique"] = base, how
            results.append(r)
    if progress:
        progress(len(todo), len(todo))

    for r in results:
        r["ours"] = bool(own_ns.get(r["imitates"]) and set(r["ns"]) & own_ns[r["imitates"]])
        r["created"], r["age_days"] = None, None
        if rdap and not r["ours"]:
            reg = E.host_info(r["domain"])[1]
            with E.network(lookups=True):   # Domain watch is an online tool; the user started it on purpose
                days, info = E.rdap_age(reg)
            if days is not None:
                r["created"], r["age_days"] = info, days
        r["level"], r["why"] = score(r)
    order = {HIGH: 0, MED: 1, INFO: 2}
    results.sort(key=lambda r: (order[r["level"]], r["age_days"] if r["age_days"] is not None else 99999))
    msgs = []
    if problems:
        msgs.append(f"{len(problems)} of {len(todo)} lookalikes could not be checked (DNS timeouts).")
    return results, msgs


def score(r):
    if r["ours"]:
        return INFO, "Uses the same name servers as your real domain: probably registered by your company."
    why, lvl = [], INFO
    if r["mx"]:
        why.append("can send and receive email (has mail servers)")
        lvl = HIGH
    if r["age_days"] is not None and r["age_days"] < 90:
        why.append(f"registered only {r['age_days']} days ago")
        lvl = HIGH
    if r["a"]:
        why.append("has a website")
        lvl = HIGH if lvl == HIGH else MED
    if not why:
        why.append("is registered but shows no website or email (parked)")
    return lvl, ("This domain " + ", ".join(why) + ".")


def block_list(results):
    return [r["domain"] for r in results if r["level"] in (HIGH, MED) and not r["ours"]]


def summary_text(results, own, when=None):
    when = when or datetime.now()
    lines = [f"Lookalike domain watch  |  {when:%d/%m/%Y %H:%M}  |  watched: {', '.join(own)}",
             "(domains are defanged with [.] so they cannot be clicked)", ""]
    if not results:
        lines.append("No registered lookalike domains found.")
    names = {HIGH: "DANGEROUS", MED: "SUSPICIOUS", INFO: "INFO"}
    for r in results:
        d = r["domain"].replace(".", "[.]")
        lines.append(f"[{names[r['level']]}] {d}  (imitates {r['imitates']}: {r['technique']})")
        lines.append(f"    {r['why']}" + (f" Created {r['created']}." if r.get("created") else ""))
    return "\n".join(lines) + "\n"


def load_watch_list(path):
    try:
        return [ln.strip().lower() for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.strip().startswith("#") and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", ln.strip().lower())]
    except Exception:
        return []
