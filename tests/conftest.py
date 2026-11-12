"""The tests check the English wording, whatever language the PC is set to.

Where the program is: Developer\\Email-Analyzer, next to this tests folder. APP_DIR is the one place that
says where the program lives; set the EMAIL_ANALYZER_APP environment variable to test a copy elsewhere."""
import os
import sys
from pathlib import Path

os.environ["EMAIL_ANALYZER_LANG"] = "en"
APP_DIR = Path(os.environ.get("EMAIL_ANALYZER_APP") or
               Path(__file__).resolve().parents[1] / "Email-Analyzer")
if not (APP_DIR / "qr_check.py").exists():
    raise SystemExit(f"Program not found in {APP_DIR}. Set EMAIL_ANALYZER_APP to the Email-Analyzer folder.")
sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))
