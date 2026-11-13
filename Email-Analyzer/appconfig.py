"""
Settings for Email Analyzer, read from config.txt next to the program.

config.txt is plain  NAME=value  lines. Everything is optional:
  LANGUAGE=auto            auto | en | el   (auto = Greek on a Greek Windows, otherwise English)
  THEME=auto               auto | light | dark   (auto = follow Windows' own Light/Dark setting,
                           otherwise dark -- this app's original look)
  ORG_NAME=                shown in the window title and on reports, e.g. "Example Shipping Security"
  SHARED_BANK_LIST=        path to ONE brand list everybody uses, e.g. \\\\server\\security\\banks.txt
  TRUSTED_AUTHSERV=        only for mail systems other than Microsoft 365: the name your own mail
                           server writes at the start of its Authentication-Results header
API keys are NOT kept here (see keys.txt).
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILE = HERE / "config.txt"
DEFAULTS = {"LANGUAGE": "auto", "THEME": "auto", "ORG_NAME": "", "SHARED_BANK_LIST": "", "TRUSTED_AUTHSERV": ""}
MAX_LIST_BYTES = 1024 * 1024      # a brand list is a few KB; refuse anything silly


def load():
    cfg = dict(DEFAULTS)
    try:
        for line in FILE.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if k.strip().upper() in DEFAULTS:
                    cfg[k.strip().upper()] = v.strip().strip('"')
    except Exception:
        pass
    return cfg


def get(name):
    return load().get(name, "")


def save(values):
    """Update the given settings, keeping comments and the other lines of config.txt."""
    values = {k.upper(): str(v).strip() for k, v in values.items() if k.upper() in DEFAULTS}
    try:
        lines = FILE.read_text(encoding="utf-8-sig").splitlines()
    except Exception:
        lines = ["# Email Analyzer settings. See appconfig.py for what each line means."]
    done = set()
    for i, line in enumerate(lines):
        s = line.strip()
        if s and not s.startswith("#") and "=" in s and s.split("=", 1)[0].strip().upper() in values:
            k = s.split("=", 1)[0].strip().upper()
            lines[i] = f"{k}={values[k]}"
            done.add(k)
    lines += [f"{k}={v}" for k, v in values.items() if k not in done]
    FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def org_name():
    return get("ORG_NAME")


# ----------------------------------------------------------- shared brand list
CACHE = HERE / "banks.shared-cache.txt"
_STATE = {"source": "local", "detail": ""}


def brand_list_text(local_file):
    """Text of the brand list to use, and remember where it came from.
    Order: the shared list (and refresh the local copy of it) -> the last copy of the shared list
    (laptop away from the office) -> this PC's own banks.txt."""
    shared = get("SHARED_BANK_LIST")
    if shared:
        try:
            p = Path(shared)
            if p.stat().st_size > MAX_LIST_BYTES:
                raise ValueError("file too large")
            text = p.read_text(encoding="utf-8-sig")
            if "|" not in text:
                raise ValueError("not a brand list")
            try:
                if not CACHE.exists() or CACHE.read_text(encoding="utf-8") != text:
                    CACHE.write_text(text, encoding="utf-8")
            except Exception:
                pass
            _STATE.update(source="shared", detail=shared)
            return text
        except Exception as e:
            try:
                text = CACHE.read_text(encoding="utf-8")
                _STATE.update(source="cached", detail=f"{shared} ({e.__class__.__name__})")
                return text
            except Exception:
                _STATE.update(source="local-fallback", detail=f"{shared} ({e.__class__.__name__})")
    else:
        _STATE.update(source="local", detail="")
    try:
        return Path(local_file).read_text(encoding="utf-8-sig")
    except Exception:
        return ""


def brand_list_state():
    """('shared' | 'cached' | 'local' | 'local-fallback', detail) for the last list that was loaded."""
    return _STATE["source"], _STATE["detail"]
