"""
Email Analyzer: desktop front-end.
Drop an email or attachment (also straight from Outlook), get a verdict with a plain "what to do",
open a readable report. English and Greek (see i18n.py).
"""
import contextlib
import getpass
import io
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from PIL import Image

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import appconfig  # noqa: E402
import i18n  # noqa: E402
from i18n import T  # noqa: E402

engine = None   # qr_check, loaded in the background so the window opens instantly
report = None   # report.py

try:
    from tkinterdnd2 import DND_ALL, TkinterDnD
    DND_OK = True
except Exception:  # drag and drop is a bonus, never a blocker
    DND_OK = False

APP_NAME = "Email Analyzer"
APP_VERSION = "2.3"

# ------------------------------------------------------------------- look
ctk.set_appearance_mode("dark")
ORG = appconfig.org_name()   # ORG_NAME in config.txt; shown in the title bar and reports
# Brand colours: navy #004680, blue #008AD8, mid blue #0069B1, grey #888B8D
BRAND_NAVY, BRAND_BLUE, BRAND_MID, BRAND_GREY = "#004680", "#008ad8", "#0069b1", "#888b8d"
NAVY_0 = "#051526"   # window
NAVY_1 = "#0a2238"   # panels
NAVY_2 = "#0f2d4a"   # cards
NAVY_3 = "#173d63"   # buttons / borders
HOVER = "#1d4f7f"
TEXT, MUTED, BODY = "#eaf2fa", "#93a9bf", "#c9d5e6"
ACCENT, ACCENT_HOVER = BRAND_BLUE, BRAND_MID

LEVELS = {
    "danger": {"label": "DANGEROUS", "color": "#e5484d", "soft": "#3a1d24"},
    "warn":   {"label": "SUSPICIOUS", "color": "#f5a524", "soft": "#3a2f17"},
    "minor":  {"label": "LOW RISK", "color": "#d6c15a", "soft": "#2f2c1a"},
    "known":  {"label": "KNOWN SITE", "color": "#30a46c", "soft": "#173528"},
    "clean":  {"label": "NO FLAGS", "color": "#7b8ca6", "soft": "#1d2738"},
    "info":   {"label": "NOT A LINK", "color": "#6e8efb", "soft": "#1c2547"},
}
FIND_COL = {"HIGH": "#e5484d", "MEDIUM": "#f5a524", "LOW": "#d6c15a", "GOOD": "#30a46c", "INFO": "#7b8ca6"}
RANK = {"danger": 0, "warn": 1, "minor": 2, "known": 3, "clean": 4, "info": 5}
SKIP_PREFIX = ("urlscan report:", "Screenshot saved:", "Screenshot not ready yet")
UI_FAMILY = "Segoe UI" if os.name == "nt" else "DejaVu Sans"
MONO_FAMILY = "Cascadia Mono" if os.name == "nt" else "DejaVu Sans Mono"


def ui_font(size=13, weight="normal"):
    return ctk.CTkFont(family=UI_FAMILY, size=size, weight=weight)


def level_of(rec):
    return report.level_of(rec)


def own_icon(win):
    """Our icon on a dialog. CustomTkinter puts its own icon on new windows after ~200 ms; put ours back after."""
    if os.name == "nt" and (HERE / "qr_inspector.ico").exists():
        win.after(260, lambda: win.winfo_exists() and win.iconbitmap(str(HERE / "qr_inspector.ico")))


def short_folder(folder, limit=55, keep=2):
    """'C:\\Users\\me\\AppData\\...\\tests\\samples' -> 'C:\\…\\tests\\samples': the drive and the last folders,
    which are the part people recognise. The full path stays in the report."""
    text = str(folder)
    parts = Path(folder).parts
    if len(text) <= limit or len(parts) <= keep + 1:
        return text
    anchor = parts[0].rstrip("\\/")
    sep = "\\" if "\\" in text else "/"
    return sep.join([anchor, "…", *parts[-keep:]])


def accent_button(btn):
    """A bright-blue button that looks switched off while it cannot be used (2.3). CustomTkinter only dims the
    text of a disabled button, so 'Open report' used to look ready before anything had been checked."""
    plain = btn.configure

    def configure(*a, **kw):
        if "state" in kw:
            on = kw["state"] == "normal"
            kw.setdefault("fg_color", ACCENT if on else NAVY_3)
            kw.setdefault("text_color_disabled", MUTED)
        plain(*a, **kw)
    btn.configure = configure
    btn.configure(state=btn.cget("state"))
    return btn


class QueueWriter(io.TextIOBase):
    """Catches the engine's console output; only a couple of lines are useful as status."""
    def __init__(self, q):
        self.q = q

    def write(self, s):
        if "VirusTotal free limit" in s:
            self.q.put(("status", "VirusTotal limit reached, waiting 20 seconds..."))
        return len(s)


# ------------------------------------------------------------- window
BaseTk = (type("DnDCTk", (ctk.CTk, TkinterDnD.DnDWrapper), {}) if DND_OK else ctk.CTk)


class App(BaseTk):
    def __init__(self, initial_files=None):
        super().__init__()
        if DND_OK:
            try:
                self.TkdndVersion = TkinterDnD._require(self)
            except Exception:
                pass
        self.title(f"{APP_NAME}  |  {ORG}" if ORG else APP_NAME)
        self.geometry("1180x820")
        self.minsize(980, 740)
        self.configure(fg_color=NAVY_0)
        try:
            if os.name == "nt" and (HERE / "qr_inspector.ico").exists():
                self.iconbitmap(str(HERE / "qr_inspector.ico"))
            elif (HERE / "qr_inspector.png").exists():
                from PIL import ImageTk
                self._icon = ImageTk.PhotoImage(Image.open(HERE / "qr_inspector.png"))
                self.iconphoto(True, self._icon)
        except Exception:
            pass

        self.scale = ctk.ScalingTracker.get_widget_scaling(self)
        self.q = queue.Queue()
        self.busy = False
        self.ready = False
        self.pending = list(initial_files or [])
        self.results = []          # [(path, notes, [recs])]
        self.last_report = None
        self.last_mode = "offline check"
        self.pasted = set()        # paths that hold pasted email text
        self.outlook_busy = False
        self._notice = None        # the one message window (NoticeDialog) that may be open
        self.wrap_labels = []      # (tk.Label, reserve_px)
        self._resize_job = None
        self.row = 0
        self.keys = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_header()
        self._build_sidebar()
        self._build_main()
        self._build_footer()
        self.page = "files"
        self._build_watch_page()
        self._show_empty_state()
        self._set_busy_ui(True, "Starting...")
        self.after(80, self._poll)
        threading.Thread(target=self._load_engine, daemon=True).start()

        if DND_OK:
            for w in (self, self.drop_zone, self.results_frame):
                try:
                    w.drop_target_register(DND_ALL)   # files, and emails dragged straight out of Outlook
                    w.dnd_bind("<<Drop>>", self._on_drop)
                    w.dnd_bind("<<DropEnter>>", self._on_drag_enter)
                    w.dnd_bind("<<DropLeave>>", lambda e: self._drop_hover(False))
                except Exception:
                    pass

    # ------------------------------------------------------------ fonts
    def tk_font(self, size, weight="normal", mono=False):
        """Plain tk fonts in pixels, scaled like the CustomTkinter widgets."""
        return (MONO_FAMILY if mono else UI_FAMILY, -int(round(size * self.scale)), weight)

    def _load_engine(self):
        global engine, report
        try:
            import qr_check as e
            import report as r
            engine, report = e, r
            self.q.put(("engine", None))
        except Exception as ex:
            self.q.put(("engine", ex))

    # ----------------------------------------------------------- header
    def _build_header(self):
        bar = ctk.CTkFrame(self, fg_color=BRAND_NAVY, corner_radius=0, height=72)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(2, weight=1)
        logo_path = HERE / "logo.png"
        self.hdr_bar = bar
        self.hdr_logo = None
        if logo_path.exists():
            img = Image.open(logo_path)
            h = 38
            self.hdr_logo = ctk.CTkLabel(bar, text="", image=ctk.CTkImage(img, img, size=(int(img.width * h / img.height), h)))
            self.hdr_logo.grid(row=0, column=0, padx=(24, 18), pady=17)
        self.hdr_sep = ctk.CTkFrame(bar, width=1, height=36, fg_color="#3c6f9e")
        self.hdr_sep.grid(row=0, column=1, padx=(0, 18))
        title = ctk.CTkFrame(bar, fg_color="transparent")
        title.grid(row=0, column=2, sticky="w")
        self.hdr_title = title
        self.hdr_name = ctk.CTkLabel(title, text=APP_NAME, font=ui_font(19, "bold"), text_color="#ffffff")
        self.hdr_name.pack(anchor="w")
        # full subtitle when it fits, its first part when space is short, nothing when there is no room (2.3)
        self.hdr_sub_full = T("ICT security tool  ·  Email, attachment and link phishing check")
        self.hdr_sub_short = self.hdr_sub_full.split("·")[0].strip()
        self.hdr_sub = ctk.CTkLabel(title, text=self.hdr_sub_full, font=ui_font(12), text_color="#a9c6e3")
        self.hdr_sub.pack(anchor="w")
        bar.bind("<Configure>", lambda e: self.after_idle(self._fit_header))
        self.nav = ctk.CTkSegmentedButton(bar, values=[T("Check files"), T("Domain watch")], command=self._switch_page,
                                          font=ui_font(13, "bold"), height=34, selected_color=BRAND_BLUE,
                                          selected_hover_color=BRAND_MID, unselected_color="#0b5592",
                                          unselected_hover_color=BRAND_MID, fg_color="#0b5592")
        self.nav.set(T("Check files"))
        self.nav.grid(row=0, column=3, padx=(10, 6))
        right = ctk.CTkFrame(bar, fg_color="transparent")
        right.grid(row=0, column=4, padx=(6, 20))
        self.hdr_right = right
        for text, cmd, w in (("Bank list", self._open_banks, 96), ("Settings", self._open_settings, 96),
                             ("Help", self._open_help, 70)):
            ctk.CTkButton(right, text=T(text), width=w, height=34, corner_radius=8, fg_color="#0b5592",
                          hover_color=BRAND_MID, border_width=1, border_color="#2b6aa3",
                          font=ui_font(13), command=cmd).pack(side="left", padx=4)

    @staticmethod
    def _text_px(label, text):
        """Width in screen pixels of `text` in a CTkLabel's real (already scaled) font."""
        import tkinter.font as tkfont
        try:
            return tkfont.Font(root=label, font=label._label.cget("font")).measure(text)
        except Exception:
            return 0

    def _fit_header(self):
        """Keep the header readable at any width and in Greek: never let the title area be squeezed."""
        try:
            bar_w = self.hdr_bar.winfo_width()
            if bar_w < 100:
                return
            pad = int(18 * self.scale)
            used = (self.hdr_logo.winfo_reqwidth() + int(42 * self.scale) if self.hdr_logo else 0) \
                + int(19 * self.scale) + self.nav.winfo_reqwidth() + int(16 * self.scale) \
                + self.hdr_right.winfo_reqwidth() + int(26 * self.scale) + pad
            avail = bar_w - used
            name_w = self._text_px(self.hdr_name, APP_NAME)
            for text in (self.hdr_sub_full, self.hdr_sub_short, ""):
                if max(name_w, self._text_px(self.hdr_sub, text)) <= avail:
                    break
            if name_w > avail:                     # no room even for the name: the logo and window title say it
                self.hdr_title.grid_remove()
                self.hdr_sep.grid_remove()
                return
            self.hdr_title.grid()
            self.hdr_sep.grid()
            if text:
                if self.hdr_sub.cget("text") != text:
                    self.hdr_sub.configure(text=text)
                if not self.hdr_sub.winfo_ismapped():
                    self.hdr_sub.pack(anchor="w")
            else:
                self.hdr_sub.pack_forget()
        except tk.TclError:
            pass

    # ---------------------------------------------------------- sidebar
    def _build_sidebar(self):
        side = ctk.CTkFrame(self, fg_color=NAVY_1, corner_radius=0, width=310)
        side.grid(row=1, column=0, sticky="nsw")
        self.side_frame = side
        side.grid_propagate(False)
        side.grid_columnconfigure(0, weight=1)

        self.drop_zone = ctk.CTkFrame(side, fg_color=NAVY_2, corner_radius=16, border_width=2,
                                      border_color=NAVY_3, height=222)
        self.drop_zone.grid(row=0, column=0, sticky="ew", padx=20, pady=(22, 14))
        self.drop_zone.grid_propagate(False)
        self.drop_zone.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.drop_zone, text=T("Drop an email or attachment"), font=ui_font(15, "bold"),
                     text_color=TEXT).grid(row=1, column=0, pady=(16, 0))
        ctk.CTkLabel(self.drop_zone, text=T("From Outlook (classic), or a saved file.\nDon't open it first."),
                     font=ui_font(11), text_color=MUTED, justify="center").grid(row=2, column=0, pady=(4, 10))
        self.browse_btn = ctk.CTkButton(self.drop_zone, text=T("Browse files"), width=236, height=34, corner_radius=17,
                                        fg_color=ACCENT, hover_color=ACCENT_HOVER, font=ui_font(13, "bold"),
                                        command=self._browse)
        self.browse_btn.grid(row=3, column=0)
        self.outlook_btn = ctk.CTkButton(self.drop_zone, text=T("Check selected Outlook email"), width=236, height=30,
                                         corner_radius=15, fg_color=NAVY_3, hover_color=HOVER, font=ui_font(12),
                                         command=self._from_outlook)
        self.outlook_btn.grid(row=4, column=0, pady=(8, 0))
        self.paste_btn = ctk.CTkButton(self.drop_zone, text=T("Paste email text"), width=236, height=30, corner_radius=15,
                                       fg_color=NAVY_3, hover_color=HOVER, font=ui_font(12),
                                       command=self._open_paste)
        self.paste_btn.grid(row=5, column=0, pady=(8, 0))

        opts = ctk.CTkFrame(side, fg_color="transparent")
        opts.grid(row=1, column=0, sticky="ew", padx=22)
        ctk.CTkLabel(opts, text=T("CHECK OPTIONS"), font=ui_font(11, "bold"), text_color=MUTED).pack(anchor="w", pady=(4, 8))
        self.lookup_var = ctk.BooleanVar(value=False)
        self.lookup_switch = ctk.CTkSwitch(opts, text=T("Online lookups (domain age)"), variable=self.lookup_var,
                                           font=ui_font(13), text_color=TEXT, progress_color=ACCENT)
        self.lookup_switch.pack(anchor="w")
        self.lookup_hint = ctk.CTkLabel(opts, text=T("Off: nothing leaves this PC.\nOn: only the domain name is sent."),
                                        font=ui_font(11), text_color=MUTED, justify="left", wraplength=250, anchor="w")
        self.lookup_hint.pack(anchor="w", fill="x", pady=(2, 8))
        self.live_var = ctk.BooleanVar(value=False)
        self.live_switch = ctk.CTkSwitch(opts, text=T("Live scan (urlscan.io)"), variable=self.live_var,
                                         font=ui_font(13), text_color=TEXT, progress_color=ACCENT)
        self.live_switch.pack(anchor="w")
        self.live_hint = ctk.CTkLabel(opts, text="", font=ui_font(11), text_color=MUTED, justify="left",
                                      wraplength=250, anchor="w")
        self.live_hint.pack(anchor="w", fill="x", pady=(2, 10))
        ctk.CTkLabel(opts, text=T("PDF password (only if locked)"), font=ui_font(12), text_color=MUTED).pack(anchor="w")
        self.pw_entry = ctk.CTkEntry(opts, placeholder_text=T("usually given in the email"), show="•",
                                     height=34, fg_color=NAVY_2, border_color=NAVY_3, font=ui_font(13))
        self.pw_entry.pack(fill="x", pady=(4, 10))
        self.pw_entry.bind("<Return>", lambda e: self._recheck())
        self.recheck_btn = ctk.CTkButton(opts, text=T("Check again"), height=38, corner_radius=10,
                                         fg_color=NAVY_3, hover_color=HOVER, font=ui_font(13, "bold"),
                                         state="disabled", command=self._recheck)
        self.recheck_btn.pack(fill="x")

        status = ctk.CTkFrame(side, fg_color="transparent")
        status.grid(row=3, column=0, sticky="sew", padx=22, pady=(6, 12))
        side.grid_rowconfigure(2, weight=1)
        # one compact line each, so the panel also fits on small laptop screens
        keys_row = ctk.CTkFrame(status, fg_color="transparent")
        keys_row.pack(anchor="w")
        self.us_status = ctk.CTkLabel(keys_row, text="○ urlscan.io", font=ui_font(11), text_color=MUTED, anchor="w")
        self.us_status.pack(side="left")
        self.vt_status = ctk.CTkLabel(keys_row, text="○ VirusTotal", font=ui_font(11), text_color=MUTED, anchor="w")
        self.vt_status.pack(side="left", padx=(14, 0))
        self.list_status = ctk.CTkLabel(status, text="", font=ui_font(11), text_color=MUTED, anchor="w")
        self.list_status.pack(anchor="w")
        self.side_version = ctk.CTkLabel(status, text=(f"{ORG}  ·  " if ORG else "") + f"v{APP_VERSION}\n" +
                                         T("Links are never opened on this PC"),
                                         justify="left", font=ui_font(10), text_color=BRAND_GREY)
        self.side_version.pack(anchor="w", pady=(6, 0))
        # On a short window the least important lines step aside instead of being cut off (2.3):
        # first the version line, then the key and brand-list status. Options and their hints always stay.
        self.side_status = status
        self.side_status_lines = (keys_row, self.list_status)
        self.side_top = (self.drop_zone, opts)
        self._fitting_side = False
        side.bind("<Configure>", lambda e: self.after_idle(self._fit_sidebar))

    def _fit_sidebar(self):
        # measured line by line, without forcing a redraw: a redraw here ran this again half-way through
        # and the stale outer run then hid the block on a normal-size window
        if self._fitting_side:
            return
        self._fitting_side = True
        try:
            room = self.side_frame.winfo_height()
            if room < 100:
                return
            top = sum(w.winfo_reqheight() for w in self.side_top) + int((22 + 14 + 12) * self.scale)
            status_h = sum(w.winfo_reqheight() for w in self.side_status_lines) + int(18 * self.scale)
            version_h = self.side_version.winfo_reqheight() + int(6 * self.scale)
            show_status = top + status_h <= room
            show_version = show_status and top + status_h + version_h <= room
            if show_status:
                self.side_status.grid()
            else:
                self.side_status.grid_remove()
            if show_version and not self.side_version.winfo_manager():
                self.side_version.pack(anchor="w", pady=(6, 0))
            elif not show_version and self.side_version.winfo_manager():
                self.side_version.pack_forget()
        except tk.TclError:
            pass
        finally:
            self._fitting_side = False

    # ------------------------------------------------------------- main
    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color=NAVY_0, corner_radius=0)
        main.grid(row=1, column=1, sticky="nsew")
        self.main_frame = main
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # The verdict box grows with its text (2.3). It used to have a fixed height with the count chips in a
        # column on the right: long or Greek text was cut off, and an empty chip area pushed the text out of view.
        self.banner = ctk.CTkFrame(main, fg_color=NAVY_1, corner_radius=14)
        self.banner.grid(row=0, column=0, sticky="ew", padx=22, pady=(22, 10))
        self.banner.grid_columnconfigure(1, weight=1)
        self.banner.grid_rowconfigure(4, minsize=14)          # bottom padding
        self.banner_dot = ctk.CTkFrame(self.banner, width=12, height=40, corner_radius=6, fg_color=NAVY_3)
        self.banner_dot.grid(row=0, column=0, rowspan=4, sticky="ns", padx=(18, 14), pady=(16, 2))
        self.banner_title = ctk.CTkLabel(self.banner, text=T("Ready"), font=ui_font(19, "bold"), text_color=TEXT,
                                         anchor="w", justify="left", wraplength=560)
        self.banner_title.grid(row=0, column=1, sticky="w", padx=(0, 22), pady=(14, 2))
        # the one line a non-specialist needs: what to do with this email
        self.banner_action = ctk.CTkLabel(self.banner, text="", font=ui_font(13, "bold"), text_color=TEXT, anchor="w",
                                          justify="left", wraplength=560)
        self.banner_action.grid(row=1, column=1, sticky="w", padx=(0, 22), pady=(0, 2))
        self.banner_sub = ctk.CTkLabel(self.banner, text=T("Drop a suspicious email or attachment to begin."),
                                       font=ui_font(12), text_color=MUTED, anchor="w", justify="left", wraplength=560)
        self.banner_sub.grid(row=2, column=1, sticky="w", padx=(0, 22))
        self.chips = ctk.CTkFrame(self.banner, fg_color="transparent")
        self.chips.grid(row=3, column=1, sticky="w", pady=(8, 0))
        self.chips.grid_remove()
        self.banner_action.grid_remove()
        self.banner.bind("<Configure>", self._banner_rewrap)
        self._build_main_results(main)

    def _watch_rewrap(self):
        """Domain watch box: wrap the title and line to the room left of the two buttons."""
        try:
            width = self.w_banner.winfo_width()
            if width < 50:
                return
            avail = max(200, int((width - self.w_btns.winfo_reqwidth()) / self.scale) - 44 - 32 - 8)
            for lab in (self.w_title, self.w_status):
                if lab.cget("wraplength") != avail:
                    lab.configure(wraplength=avail)
        except tk.TclError:
            pass

    def _banner_rewrap(self, event=None):
        """Wrap the verdict text to the box's real width (CTk scales wraplength itself, so pass unscaled)."""
        width = self.banner.winfo_width()
        if width < 50:
            return
        avail = max(240, int(width / self.scale) - 44 - 22 - 8)
        for lab in (self.banner_title, self.banner_action, self.banner_sub):
            if lab.cget("wraplength") != avail:
                lab.configure(wraplength=avail)

    def _build_main_results(self, main):

        self.results_frame = ctk.CTkScrollableFrame(main, fg_color=NAVY_0, corner_radius=0,
                                                    scrollbar_button_color=NAVY_3,
                                                    scrollbar_button_hover_color=HOVER)
        self.results_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 6))
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.canvas = self.results_frame._parent_canvas
        # keep CustomTkinter's own scroll-region binding: add ours with add="+"
        self.results_frame.bind("<Configure>", self._update_scrollregion, add="+")
        self.canvas.bind("<Configure>", self._on_resize, add="+")
        # Own wheel handling: CustomTkinter's default moves only ~20 px per notch on Windows.
        # Replace it with ~90 px per notch (about three lines), the same on every platform.
        self.canvas.configure(yscrollincrement=1)
        self.unbind_all("<MouseWheel>")
        self.bind_all("<MouseWheel>", self._on_wheel)
        self.bind_all("<Button-4>", lambda e: self._wheel_notches(e, -1))
        self.bind_all("<Button-5>", lambda e: self._wheel_notches(e, 1))
        for key, amount in (("<Prior>", -1), ("<Next>", 1)):
            self.bind(key, lambda e, a=amount: self.canvas.yview_scroll(a, "pages"))
        self.bind("<Home>", lambda e: self.canvas.yview_moveto(0))
        self.bind("<End>", lambda e: self.canvas.yview_moveto(1))

    def _build_footer(self):
        # The footer grows by one line when a message does not fit next to the buttons (2.3): it used to be
        # cut off mid-word, and that is where error messages and their advice were shown.
        foot = ctk.CTkFrame(self, fg_color=NAVY_1, corner_radius=0)
        foot.grid(row=2, column=0, columnspan=2, sticky="ew")
        foot.grid_columnconfigure(1, weight=1)
        self.foot = foot
        self.progress = ctk.CTkProgressBar(foot, width=160, height=6, progress_color=ACCENT, fg_color=NAVY_3,
                                           mode="determinate")
        self.progress.grid(row=0, column=0, padx=(22, 12), pady=24)
        self.progress.set(0)
        self.status = ctk.CTkLabel(foot, text=T("Ready."), font=ui_font(12), text_color=MUTED, anchor="w",
                                   justify="left")
        self.status.grid(row=0, column=1, sticky="w")
        self.status_below = False
        plain_configure = self.status.configure

        def status_configure(*a, **kw):               # every status change re-checks whether it fits
            plain_configure(*a, **kw)
            if "text" in kw:
                self.after_idle(self._fit_status)
        self.status.configure = status_configure
        foot.bind("<Configure>", lambda e: self.after_idle(self._fit_status))
        btns = ctk.CTkFrame(foot, fg_color="transparent")
        btns.grid(row=0, column=2, padx=18)
        self.footer_btns = btns
        # Details on: every reason (for ICT). Off: verdict, what to do and the main reason only.
        self.detail_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(btns, text=T("Details"), variable=self.detail_var, font=ui_font(12), text_color=MUTED,
                      progress_color=ACCENT, command=self._rerender).pack(side="left", padx=(4, 10))
        self.report_btn = ctk.CTkButton(btns, text=T("Open report"), width=130, height=34, corner_radius=10,
                                        fg_color=ACCENT, hover_color=ACCENT_HOVER, font=ui_font(13, "bold"),
                                        state="disabled", command=self._open_report)
        accent_button(self.report_btn)
        self.report_btn.pack(side="left", padx=4)
        self.copy_btn = ctk.CTkButton(btns, text=T("Copy ticket summary"), width=170, height=34, corner_radius=10,
                                      fg_color=NAVY_3, hover_color=HOVER, font=ui_font(13),
                                      state="disabled", command=self._copy_summary)
        self.copy_btn.pack(side="left", padx=4)
        self.folder_btn = ctk.CTkButton(btns, text=T("Show in folder"), width=124, height=34, corner_radius=10,
                                        fg_color=NAVY_3, hover_color=HOVER, font=ui_font(13),
                                        state="disabled", command=self._open_folder)
        self.folder_btn.pack(side="left", padx=4)
        ctk.CTkButton(btns, text=T("Clear"), width=70, height=34, corner_radius=10, fg_color=NAVY_3,
                      hover_color=HOVER, font=ui_font(13), command=self._clear).pack(side="left", padx=4)

    def _fit_status(self):
        """Status next to the buttons when it fits, otherwise on its own full-width line under them."""
        try:
            foot_w = self.foot.winfo_width()
            if foot_w < 100:
                return
            text = self.status.cget("text")
            avail = foot_w - self.progress.winfo_reqwidth() - self.footer_btns.winfo_reqwidth() - int(70 * self.scale)
            below = self._text_px(self.status, text) > avail
            if below != self.status_below:
                self.status_below = below
                if below:
                    self.status.grid_configure(row=1, column=0, columnspan=3, padx=22, pady=(0, 12))
                else:
                    self.status.grid_configure(row=0, column=1, columnspan=1, padx=0, pady=0)
            wrap = int(foot_w / self.scale - 50) if below else 0     # CTk scales wraplength itself
            if self.status.cget("wraplength") != wrap:
                self.status.configure(wraplength=wrap)
        except tk.TclError:
            pass

    # -------------------------------------------------------- scrolling
    def _update_scrollregion(self, _=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _over_results(self, widget):
        """The scrollable canvas under the pointer (results or domain watch), or None."""
        targets = [c for c in (self.canvas, getattr(self, "w_canvas", None)) if c is not None]
        w = widget
        while w is not None:
            for c in targets:
                if w is c:
                    return c
            w = getattr(w, "master", None)
        return None

    def _on_wheel(self, event):
        notches = -event.delta / 120.0          # Windows: 120 per notch, touchpads send smaller steps
        if sys.platform == "darwin":
            notches = -event.delta / 3.0
        self._wheel_notches(event, notches)

    def _wheel_notches(self, event, notches):
        canvas = self._over_results(event.widget)
        if canvas is None or canvas.yview() == (0.0, 1.0):
            return
        px = int(round(notches * 90 * self.scale))
        if px == 0:
            px = 1 if notches > 0 else -1
        canvas.yview_scroll(px, "units")

    def _on_resize(self, event):
        # debounce: re-wrap text once the user stops dragging the window edge
        if self._resize_job:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(120, lambda w=event.width: self._rewrap(w))

    def _rewrap(self, width):
        self._resize_job = None
        keep = []
        for lab, reserve in self.wrap_labels:
            try:
                lab.configure(wraplength=max(240, width - int(reserve * self.scale)))
                keep.append((lab, reserve))
            except tk.TclError:
                pass
        self.wrap_labels = keep
        self._update_scrollregion()

    def _wrap_now(self):
        return max(240, self.canvas.winfo_width())

    # ------------------------------------------------------ empty state
    def _show_empty_state(self):
        box = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        box.grid(row=0, column=0, pady=48)
        mark = HERE / "ll_mark.png"
        if mark.exists():
            im = Image.open(mark)
            ctk.CTkLabel(box, text="", image=ctk.CTkImage(im, im, size=(int(im.width * 74 / im.height), 74))).pack(pady=(0, 18))
        ctk.CTkLabel(box, text=T("No file checked yet"), font=ui_font(18, "bold"), text_color=TEXT).pack()
        tips = T("1.  Drag the suspicious email straight from Outlook (classic) into this window, or click “Check selected Outlook email”.\n"
                 "2.  Saved files work too: drag them in, or right-click > Send to > Email Analyzer.\n"
                 "3.  Red means dangerous: report it to ICT and do not open the link.\n"
                 "4.  Click “Open report” for a readable copy you can copy from and attach to the ticket.")
        ctk.CTkLabel(box, text=tips, font=ui_font(13), text_color=MUTED, justify="left").pack(pady=(14, 0))
        self.row = 1

    # ----------------------------------------------------------- inputs
    def _on_drag_enter(self, event):
        self._drop_hover(True)
        import outlook_grab
        if outlook_grab.classify_drag(getattr(event, "types", "")) == "chromium":
            # The new Outlook (a Chromium app) announces the drag but never completes the drop, so this is
            # the only moment we can tell the user anything. Shown once; a real file drop closes it again.
            if not (self._notice and self._notice.winfo_exists()):
                self.after(350, self._new_outlook_notice)
        return getattr(event, "action", None)

    def _new_outlook_notice(self):
        if self._notice and self._notice.winfo_exists():
            return
        self._show_notice(
            T("This email can't be read from the new Outlook"),
            T("The new Outlook doesn't hand emails to other programs, so nothing was checked.\n\n"
              "Do one of these instead:\n"
              "1.  Open Outlook (classic) from the Start menu and drag the email from there.\n"
              "2.  In the new Outlook, drag the email onto your desktop first, then drag that file in here.\n"
              "3.  Click “Paste email text”.\n\n"
              "The same goes for Outlook on the web in a browser."))

    def _show_notice(self, title, body):
        if self._notice and self._notice.winfo_exists():
            self._notice.destroy()
        self._notice = NoticeDialog(self, title, body)
        self.status.configure(text=title)

    def _close_notice(self):
        if self._notice and self._notice.winfo_exists():
            self._notice.destroy()
        self._notice = None

    def _on_drop(self, event):
        import outlook_grab
        self._drop_hover(False)
        try:
            items = list(self.tk.splitlist(event.data))
        except Exception:
            items = []
        files = [f for f in items if Path(f).is_file()]
        kind = outlook_grab.classify_drag(getattr(event, "types", ""), has_files=bool(files))
        if kind == "files":
            self._close_notice()
            self.run_check(files)
        elif kind == "classic":
            # An email dragged out of classic Outlook. Outlook is asked for the selected email, and the
            # subject it hands over is compared with the subject being dragged, so a different email is
            # never checked by mistake.
            self._from_outlook(dragged=outlook_grab.dragged_subjects(event.data))
        elif kind == "chromium":
            self._new_outlook_notice()
        else:
            # Text, a link from a web page, anything else: never fall back to "whatever Outlook has selected".
            self._show_notice(T("That wasn't a file or an email from Outlook (classic)"),
                              T("Nothing was checked.\n\nDrag in a saved file or an email from Outlook (classic), "
                                "or click “Paste email text”."))
        return getattr(event, "action", None)

    def _from_outlook(self, dragged=None):
        if not self.ready or self.busy or getattr(self, "outlook_busy", False):
            return
        self.outlook_busy = True
        self._set_busy_ui(True, T("Asking Outlook for the selected email..."))

        def work():
            import outlook_grab
            try:
                files = outlook_grab.grab_selected(report.fallback_dir() / "Outlook")
            except outlook_grab.OutlookError as e:
                self.q.put(("outlook", [], e.reason(i18n.language())))
                return
            except Exception as e:
                self.q.put(("outlook", [], str(e)))
                return
            if dragged:
                got = []
                try:
                    import email_check
                    got = [email_check.read_msg(Path(f).read_bytes())[1] for f in files]
                except Exception:
                    got = []          # cannot read the subject: the check itself will show the email
                if got and not outlook_grab.same_email(dragged, got):
                    self.q.put(("outlook_mismatch", dragged, got))
                    return
            self.q.put(("outlook", files, None))
        threading.Thread(target=work, daemon=True).start()

    def _outlook_done(self, files, why):
        self.outlook_busy = False
        self._set_busy_ui(False)
        if files:
            self._close_notice()
            self.run_check(files)
        else:
            self._show_notice(T("Could not get the email from Outlook"), why)

    def _outlook_mismatch(self, dragged, got):
        self.outlook_busy = False
        self._set_busy_ui(False)
        show = lambda s: engine.visible(str(s))[:120]
        self._show_notice(
            T("Outlook handed over a different email"),
            T("You dragged “{want}”, but the email selected in Outlook is “{got}”. "
              "Nothing was checked, so the two cannot be mixed up.\n\n"
              "Click the email once in Outlook (classic), then drag it in again or click “Check selected Outlook email”.",
              want=show(dragged[0]), got=show(got[0])))

    def _drop_hover(self, on):
        self.drop_zone.configure(border_color=ACCENT if on else NAVY_3, fg_color="#0d3a63" if on else NAVY_2)

    def _browse(self):
        files = ctk.filedialog.askopenfilenames(
            title="Choose the saved attachment",
            filetypes=[("Emails and attachments", "*.msg *.eml *.pdf *.doc *.docx *.docm *.xls *.xlsx *.xlsm *.ppt "
                        "*.pptx *.pptm *.htm *.html *.svg *.zip *.iso *.img *.png *.jpg *.jpeg *.gif *.bmp *.webp *.rtf *.txt"),
                       ("All files", "*.*")])
        if files:
            self.run_check(list(files))

    def _recheck(self):
        if self.results and not self.busy:
            self.run_check([r[0] for r in self.results])

    # -------------------------------------------------------- run check
    def _set_busy_ui(self, busy, text=None):
        if busy:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.set(0)
        state = "disabled" if busy else "normal"
        self.browse_btn.configure(state=state)
        self.paste_btn.configure(state=state)
        self.outlook_btn.configure(state=state)
        if text:
            self.status.configure(text=text)

    def run_check(self, files):
        if not self.ready:
            self.pending.extend(files)
            return
        if self.busy:
            return
        files = [f for f in files if Path(f).is_file()]
        if not files:
            return
        if self.page != "files":
            self._switch_page(T("Check files"))
        self._clear(keep_banner=True)
        self.busy = True
        self.results = []
        self.keys = engine.load_keys()
        live = self.live_var.get() and bool(self.keys.get("URLSCAN_API_KEY"))
        lookups = bool(self.lookup_var.get())
        engine.set_network(lookups=lookups, live=live)   # nothing goes online unless a switch is on
        self.last_mode = ("live scan (urlscan.io)" if live else "offline check") + (" + online lookups" if lookups else "")
        pw = self.pw_entry.get().strip() or None
        for b in (self.copy_btn, self.recheck_btn, self.report_btn, self.folder_btn):
            b.configure(state="disabled")
        self._set_busy_ui(True)
        self._set_banner("clean", T("Checking..."), f"{len(files)} {T('file(s)')}  ·  " +
                         T("live scan on, about 30 seconds per link" if live else
                           "online lookups on, links are not visited" if lookups else
                           "offline check, nothing is sent to the internet"))
        threading.Thread(target=self._worker, args=(files, live, pw), daemon=True).start()

    def _worker(self, files, live, pw):
        try:
            self._worker_inner(files, live, pw)
        except Exception as e:  # never leave the window stuck on "Checking..."
            self.q.put(("status", f"Something went wrong: {e}. Try again or contact ICT."))
        self.q.put(("done", live))

    def _worker_inner(self, files, live, pw):
        brands = engine.load_brands()
        with contextlib.redirect_stdout(QueueWriter(self.q)):
            for path in files:
                name = Path(path).name
                self.q.put(("status", f"Reading {name}..."))
                try:
                    links, notes = engine.collect(path, pw, pasted=str(path) in self.pasted)
                except Exception as e:
                    msg = str(e)
                    lvl = "HIGH" if "password" in msg.lower() else "MEDIUM"
                    self.q.put(("file", path, [(lvl, msg)], 0))
                    self.q.put(("filedone", path, [(lvl, msg)], []))
                    continue
                self.q.put(("file", path, notes, len(links)))
                shots = Path(path).parent / (Path(path).stem + "_screenshots")

                def png_for(n, text):
                    url = engine.normalise_url(text)
                    if not live or not url:
                        return None
                    host = re.sub(r"[^A-Za-z0-9.-]", "_", engine.safe_split(url)[0].hostname or "link")[:60]
                    for folder in (shots, None):
                        try:
                            if folder is None:
                                folder = report.fallback_dir() / (Path(path).stem + "_screenshots")
                            folder.mkdir(parents=True, exist_ok=True)
                            return folder / f"link{n}_{host}.png"
                        except Exception:
                            continue
                    return None

                total = len(links)
                self.q.put(("status", f"{name}: checking {total} link(s)"
                            + (", urlscan.io is visiting them..." if live else "...")))
                recs = []
                for n, rec in enumerate(engine.check_links(links, brands, self.keys, live, True, png_for), 1):
                    rec.pop("_console", None)
                    recs.append(rec)
                    self.q.put(("rec", rec))
                    self.q.put(("status", f"{name}: {n} of {total} link(s) checked..."))
                data = {"file": str(path), "checked": datetime.now().isoformat(timespec="seconds"),
                        "mode": self.last_mode,
                        "risk_score": 0,
                        "file_findings": [{"level": lv, "detail": m} for lv, m in notes], "links": recs}
                data["risk_score"] = report.file_score(notes, recs)[0]
                data["overall"] = report.LEVELS[report.file_level(notes, recs)][0]
                report.write_text_safely(Path(path).with_suffix(".emailcheck.json"),
                                         json.dumps(data, indent=2, ensure_ascii=False))
                self.q.put(("filedone", path, notes, recs))

    def _poll(self):
        handled = 0
        try:
            while handled < 25:   # keep the window responsive while cards stream in
                item = self.q.get_nowait()
                handled += 1
                kind = item[0]
                if kind == "status":
                    self.status.configure(text=item[1])
                elif kind == "file":
                    self._add_file_header(item[1], item[2], item[3])
                elif kind == "rec":
                    self._add_card(item[1])
                elif kind == "filedone":
                    self.results.append((item[1], item[2], item[3]))
                    self._add_score_box(item[2], item[3])
                elif kind == "done":
                    self._finish(item[1])
                elif kind == "outlook":
                    self._outlook_done(item[1], item[2])
                elif kind == "outlook_mismatch":
                    self._outlook_mismatch(item[1], item[2])
                elif kind == "wprogress":
                    self.w_status.configure(text=f"Checked {item[1]} of {item[2]} lookalike domains...")
                elif kind == "wdone":
                    self._watch_done(item[1], item[2], item[3])
                elif kind == "engine":
                    self._engine_ready(item[1])
        except queue.Empty:
            pass
        self.after(40 if handled else 90, self._poll)

    def _engine_ready(self, err):
        if err:
            self._set_busy_ui(False, f"Could not start: {err}. Reinstall or contact ICT.")
            self._set_banner("danger", "The checker could not start", str(err))
            return
        self.ready = True
        self._set_busy_ui(False, T("Ready."))
        self._refresh_key_status()
        if self.pending:
            files, self.pending = self.pending, []
            self.run_check(files)

    def _finish(self, live):
        self.busy = False
        self._set_busy_ui(False)
        recs = [r for _, _, rs in self.results for r in report.flatten(rs)]
        notes = [n for _, ns, _ in self.results for n in ns]
        levels = [level_of(r) for r in recs]
        counts = {k: levels.count(k) for k in LEVELS}
        worst = min([report.file_level(ns, rs) for _, ns, rs in self.results] or ["clean"], key=lambda x: RANK[x])
        titles = {"danger": "Dangerous: do not open, report to ICT",
                  "warn": "Suspicious: needs a closer look",
                  "minor": "Low risk: only minor flags",
                  "known": "Links go to known legitimate sites",
                  "clean": "No red flags found", "info": "No web links found"}
        top_score = max([report.file_score(ns, rs)[0] for _, ns, rs in self.results] or [0])
        mode = " + ".join(T(m) for m in self.last_mode.split(" + "))
        sub = (f"{T('Risk score')} {top_score}/100  ·  {len(self.results)} {T('file(s)')}, {len(recs)} {T('link(s)')}  ·  {mode}"
               f"  ·  {i18n.date(datetime.now())}")
        if not recs and not notes:
            self._set_banner("clean", T("No QR codes or links found"), sub, action=i18n.action("info"))
        else:
            self._set_banner(worst, T(titles[worst]), sub, counts, action=i18n.action(worst))
        self.last_report = None
        if self.results:
            self.last_report = report.write_report(self.results, self.last_mode, getpass.getuser(),
                                                   engine.load_brands())
        self.status.configure(text=T("Done. “Open report” gives a copy for the ticket."
                                     if self.last_report else "Done."))
        for b in (self.copy_btn, self.recheck_btn, self.folder_btn):
            b.configure(state="normal" if self.results else "disabled")
        self.report_btn.configure(state="normal" if self.last_report else "disabled")
        self._update_scrollregion()

    # ---------------------------------------------------------- drawing
    def _set_banner(self, level, title, sub, counts=None, action=""):
        lv = LEVELS[level]
        self.banner_dot.configure(fg_color=lv["color"])
        self.banner.configure(fg_color=lv["soft"] if level in ("danger", "warn") else NAVY_1)
        self.banner_title.configure(text=title)
        self.banner_action.configure(text=action or "")
        self.banner_sub.configure(text=sub)
        # empty lines take no room
        for lab, text in ((self.banner_action, action), (self.banner_sub, sub)):
            lab.grid() if text else lab.grid_remove()
        for w in self.chips.winfo_children():
            w.destroy()
        shown = 0
        if counts:
            for key in ("danger", "warn", "minor", "known", "clean"):
                if counts.get(key):
                    c = ctk.CTkFrame(self.chips, fg_color=NAVY_0, corner_radius=12, border_width=1,
                                     border_color=LEVELS[key]["soft"])
                    c.pack(side="left", padx=(0, 8))
                    ctk.CTkLabel(c, text=f"{counts[key]}  {T(LEVELS[key]['label'].lower())}",
                                 font=ui_font(12, "bold"), text_color=LEVELS[key]["color"]).pack(padx=12, pady=5)
                    shown += 1
        self.chips.grid() if shown else self.chips.grid_remove()
        self._banner_rewrap()

    def _next_row(self):
        r = self.row
        self.row += 1
        return r

    def _label(self, parent, text, size=12, color=BODY, bg=NAVY_2, mono=False, weight="normal", reserve=None):
        lab = tk.Label(parent, text=text, font=self.tk_font(size, weight, mono), fg=color, bg=bg,
                       justify="left", anchor="w", bd=0, highlightthickness=0)
        if reserve is not None:
            lab.configure(wraplength=max(240, self._wrap_now() - int(reserve * self.scale)))
            self.wrap_labels.append((lab, reserve))
        return lab

    def _add_file_header(self, path, notes, n_links):
        box = tk.Frame(self.results_frame, bg=NAVY_0)
        box.grid(row=self._next_row(), column=0, sticky="ew", padx=10, pady=(14, 4))
        self._label(box, engine.visible(Path(path).name), 15, TEXT, NAVY_0, weight="bold").pack(anchor="w")
        self._label(box, f"{n_links} {T('QR code(s) or link(s) found')}  ·  {engine.visible(short_folder(Path(path).parent))}",
                    11, MUTED, NAVY_0, reserve=60).pack(anchor="w", fill="x")
        details = self.detail_var.get()
        for lv, msg in report.order_notes(notes):
            headline = msg.startswith(("Subject:", "From:"))
            text = engine.visible(i18n.msg(report.sentence(msg)))
            if not details and lv not in ("HIGH", "MEDIUM", "GOOD") and not headline:
                continue          # simple view: sender, subject and the warnings that matter
            if lv in ("HIGH", "MEDIUM", "LOW", "GOOD"):
                bg = {"HIGH": LEVELS["danger"]["soft"], "MEDIUM": LEVELS["warn"]["soft"], "LOW": LEVELS["minor"]["soft"],
                      "GOOD": LEVELS["known"]["soft"]}[lv]
                w = tk.Frame(box, bg=bg)
                w.pack(fill="x", pady=(6, 0))
                self._label(w, f"●  {text}", 12, FIND_COL.get(lv, MUTED), bg, reserve=90).pack(anchor="w", padx=12, pady=8)
            else:   # background details: quiet, no box
                self._label(box, text, 11, TEXT if headline else MUTED, NAVY_0,
                            weight="bold" if msg.startswith("Subject:") else "normal",
                            reserve=90).pack(anchor="w", padx=14, pady=(3, 0))
        self._update_scrollregion()

    def _add_card(self, rec, indent=0):
        lv = LEVELS[level_of(rec)]
        card = ctk.CTkFrame(self.results_frame, fg_color=NAVY_2, corner_radius=14)
        card.grid(row=self._next_row(), column=0, sticky="ew", padx=(10 + indent, 10), pady=6)
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkFrame(card, width=5, height=10, corner_radius=3, fg_color=lv["color"]).grid(
            row=0, column=0, sticky="ns", padx=(10, 0), pady=12)
        body = tk.Frame(card, bg=NAVY_2)
        body.grid(row=0, column=1, sticky="ew", padx=14, pady=12)
        body.grid_columnconfigure(1, weight=1)

        pill = f" {T(lv['label'])} " + (f"· {rec['score']} " if rec.get("score") else "")
        ctk.CTkLabel(body, text=pill, font=ui_font(11, "bold"), text_color=lv["color"],
                     fg_color=lv["soft"], corner_radius=8, height=24).grid(row=0, column=0, sticky="nw", padx=(0, 12))
        raw = rec.get("raw", "")
        shown = engine.visible(raw if len(raw) < 300 else raw[:300] + "...")
        self._label(body, shown, 13, TEXT, mono=True, reserve=280 + indent).grid(row=0, column=1, sticky="w")
        ctk.CTkButton(body, text=T("Copy"), width=58, height=26, corner_radius=8, fg_color=NAVY_3,
                      hover_color=HOVER, font=ui_font(11),
                      command=lambda r=raw: self._to_clipboard(report.defang(r),
                                                               T("Link copied in safe form (hxxps, [.]), it cannot be clicked."))
                      ).grid(row=0, column=2, sticky="ne", padx=(10, 0))
        self._label(body, f"{T('Found in:')} {i18n.where(engine.visible('; '.join(rec.get('found_in', []))))}", 11, MUTED,
                    reserve=200 + indent).grid(row=1, column=1, columnspan=2, sticky="w", pady=(4, 6))

        r = 2
        findings = [f for f in rec.get("findings", []) if not f["detail"].startswith(SKIP_PREFIX)]
        shown = findings
        if not self.detail_var.get():     # simple view: the main reason only
            shown = [f for f in findings if f["level"] in ("HIGH", "MEDIUM", "LOW", "GOOD")][:1]
        for f in shown:
            line = tk.Frame(body, bg=NAVY_2)
            line.grid(row=r, column=1, columnspan=2, sticky="ew", pady=1)
            self._label(line, "●", 9, FIND_COL.get(f["level"], MUTED)).pack(side="left", anchor="n", pady=(3, 0))
            self._label(line, i18n.msg(f["detail"]), 12, BODY, reserve=240 + indent).pack(side="left", anchor="w", padx=(6, 0))
            r += 1
        if len(shown) < len(findings):
            self._label(body, T("{n} more reason(s). Turn on Details or open the report.", n=len(findings) - len(shown)),
                        11, MUTED).grid(row=r, column=1, columnspan=2, sticky="w", pady=(2, 0))
            r += 1

        us = rec.get("urlscan")
        if us:
            scan = tk.Frame(body, bg=NAVY_1)
            scan.grid(row=r, column=1, columnspan=2, sticky="ew", pady=(10, 0))
            info = tk.Frame(scan, bg=NAVY_1)
            info.pack(side="left", fill="both", expand=True, padx=12, pady=10)
            self._label(info, T("LIVE SCAN  ·  urlscan.io"), 10, MUTED, NAVY_1, weight="bold").pack(anchor="w")
            if us.get("final_url"):
                self._label(info, f"{T('Lands on:')} {engine.visible(us['final_url'][:200])}", 11, TEXT, NAVY_1, mono=True,
                            reserve=560 + indent).pack(anchor="w", pady=(4, 0))
            if us.get("title"):
                self._label(info, f"{T('Page title:')} {engine.visible(us['title'][:120])}", 11, MUTED, NAVY_1).pack(anchor="w")
            if us.get("error"):
                self._label(info, us["error"], 11, "#f5a524", NAVY_1, reserve=560).pack(anchor="w")
            if us.get("report"):
                link = self._label(info, T("Open full urlscan report  ↗"), 12, ACCENT, NAVY_1, weight="bold")
                link.configure(cursor="hand2")
                link.pack(anchor="w", pady=(6, 0))
                link.bind("<Button-1>", lambda e, u=us["report"]: webbrowser.open(u))
            shot = us.get("screenshot_file")
            if shot and Path(shot).exists():
                try:
                    im = Image.open(shot)
                    w = 240
                    h = min(int(im.height * w / im.width) if im.width else 150, 180)
                    thumb = ctk.CTkLabel(scan, text="", image=ctk.CTkImage(im, im, size=(w, h)), cursor="hand2")
                    thumb.pack(side="right", padx=10, pady=10)
                    thumb.bind("<Button-1>", lambda e, p=shot: self._open_path(p))
                except Exception:
                    pass

        for inner in rec.get("links_inside", []):
            self._add_card(inner, indent=indent + 34)
        self._update_scrollregion()

    def _add_score_box(self, notes, recs):
        """Shown under each file once its links are checked: the score and what it is made of."""
        score, why = report.score_lines(notes, recs)
        lv = LEVELS[report.file_level(notes, recs)]
        card = ctk.CTkFrame(self.results_frame, fg_color=NAVY_1, corner_radius=14, border_width=1, border_color=lv["color"])
        card.grid(row=self._next_row(), column=0, sticky="ew", padx=10, pady=(8, 14))
        body = tk.Frame(card, bg=NAVY_1)
        body.pack(fill="x", padx=16, pady=12)
        level = report.file_level(notes, recs)
        self._label(body, f"{T(lv['label'])}  ·  {T('risk score')} {score}/100", 14, lv["color"], NAVY_1, weight="bold").pack(anchor="w")
        self._label(body, f"{T('What to do:')} {i18n.action(level)}", 13, TEXT, NAVY_1, weight="bold",
                    reserve=120).pack(anchor="w", pady=(4, 2))
        if self.detail_var.get():
            self._label(body, T("Each warning adds points (HIGH {h}, MEDIUM {m}, LOW {l}). From {s} suspicious, from {d} dangerous. "
                                "Only the worst link counts, plus everything about the email or file itself.",
                                h=engine.WEIGHTS["HIGH"], m=engine.WEIGHTS["MEDIUM"], l=engine.WEIGHTS["LOW"],
                                s=engine.SUSPICIOUS_AT, d=engine.DANGER_AT),
                        11, MUTED, NAVY_1, reserve=120).pack(anchor="w", pady=(2, 6))
            _, parts = report.file_score(notes, recs)
            lines = [f"+{pt:<3} {i18n.msg(m)}" for pt, _, m in sorted(parts, key=lambda x: -x[0])]
            for line in lines[:12] or [T("Nothing added points.")]:
                self._label(body, engine.visible(line), 12, BODY, NAVY_1, mono=True, reserve=120).pack(anchor="w")
        # the age of a domain is the strongest signal we skip offline: offer it right here
        age_skipped = any(engine.AGE_OFF in m for _, m in notes) or any(
            engine.AGE_OFF in f["detail"] for r in report.flatten(recs) for f in r.get("findings", []))
        if age_skipped and level != "danger" and not self.lookup_var.get():
            self._label(body, T("The age of the domains was not checked. A domain registered days ago is one of the "
                                "strongest signs of phishing. This sends only the domain names to rdap.org."),
                        11, MUTED, NAVY_1, reserve=120).pack(anchor="w", pady=(8, 4))
            ctk.CTkButton(body, text=T("Check domain age now"), width=220, height=32, corner_radius=10, fg_color=ACCENT,
                          hover_color=ACCENT_HOVER, font=ui_font(13, "bold"), command=self._check_age_now).pack(anchor="w")
        self._update_scrollregion()

    def _check_age_now(self):
        self.lookup_var.set(True)
        self._recheck()

    def _rerender(self):
        """Draw the stored results again (Details switch changed). Nothing is checked again."""
        if self.busy or not self.results:
            return
        self._clear(keep_banner=True)
        for path, notes, recs in self.results:
            self._add_file_header(path, notes, len(recs))
            for rec in recs:
                self._add_card(rec)
            self._add_score_box(notes, recs)

    def _open_paste(self):
        if self.ready and not self.busy:
            PasteDialog(self)

    def check_pasted(self, text):
        """Save pasted email text to a file (so the report has a home) and check it."""
        if not text.strip():
            return
        try:
            f = report.fallback_dir() / f"Pasted-email-{datetime.now():%Y%m%d-%H%M%S}.txt"
            f.write_text(text, encoding="utf-8")
        except Exception as e:
            self.status.configure(text=f"Could not save the pasted text: {e}")
            return
        self.pasted.add(str(f))
        self.run_check([str(f)])

    # ----------------------------------------------------- domain watch
    def _build_watch_page(self):
        page = ctk.CTkFrame(self, fg_color=NAVY_0, corner_radius=0)
        page.grid_columnconfigure(1, weight=1)
        page.grid_rowconfigure(0, weight=1)
        self.watch_page = page

        left = ctk.CTkFrame(page, fg_color=NAVY_1, corner_radius=0, width=310)
        left.grid(row=0, column=0, sticky="nsw")
        left.grid_propagate(False)
        ctk.CTkLabel(left, text=T("WATCHED DOMAINS"), font=ui_font(11, "bold"), text_color=MUTED).pack(anchor="w", padx=22, pady=(24, 6))
        self.w_text = ctk.CTkTextbox(left, height=170, fg_color=NAVY_2, border_color=NAVY_3, border_width=1,
                                     font=ctk.CTkFont(family=MONO_FAMILY, size=13))
        self.w_text.pack(fill="x", padx=20)
        ctk.CTkLabel(left, text=T("One per line: our own domains and key partners\n(e.g. our bank, port agents, charterers)."),
                     font=ui_font(11), text_color=MUTED, justify="left").pack(anchor="w", padx=22, pady=(6, 14))
        self.w_run = ctk.CTkButton(left, text=T("Check for lookalikes"), height=40, corner_radius=10, fg_color=ACCENT,
                                   hover_color=ACCENT_HOVER, font=ui_font(14, "bold"), command=self._watch_run)
        self.w_run.pack(fill="x", padx=20)
        ctk.CTkLabel(left, text=T("Builds every typo and lookalike an attacker\ncould register and checks which exist.\n"
                                  "Needs internet. Takes 1 to 3 minutes.\nRun it monthly."),
                     font=ui_font(11), text_color=MUTED, justify="left").pack(anchor="w", padx=22, pady=(10, 0))
        try:
            import domain_watch as dw
            saved = dw.load_watch_list(HERE / "watch_domains.txt")
        except Exception:
            saved = []
        self.w_text.insert("1.0", "\n".join(saved))

        right = ctk.CTkFrame(page, fg_color=NAVY_0, corner_radius=0)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)
        # grows with its text and wraps it beside the buttons (2.3: the Greek title and line were cut off)
        self.w_banner = ctk.CTkFrame(right, fg_color=NAVY_1, corner_radius=14)
        self.w_banner.grid(row=0, column=0, sticky="ew", padx=22, pady=(22, 10))
        self.w_banner.grid_columnconfigure(1, weight=1)
        self.w_dot = ctk.CTkFrame(self.w_banner, width=12, height=40, corner_radius=6, fg_color=NAVY_3)
        self.w_dot.grid(row=0, column=0, rowspan=2, sticky="ns", padx=(18, 14), pady=16)
        self.w_title = ctk.CTkLabel(self.w_banner, text=T("Lookalike domain watch"), font=ui_font(19, "bold"),
                                    text_color=TEXT, anchor="w", justify="left", wraplength=400)
        self.w_title.grid(row=0, column=1, sticky="sw", pady=(14, 2))
        self.w_status = ctk.CTkLabel(self.w_banner, text=T("Add our domains on the left, then click “Check for lookalikes”."),
                                     font=ui_font(12), text_color=MUTED, anchor="w", justify="left", wraplength=400)
        self.w_status.grid(row=1, column=1, sticky="nw", pady=(0, 14))
        wb = ctk.CTkFrame(self.w_banner, fg_color="transparent")
        wb.grid(row=0, column=2, rowspan=2, padx=16)
        self.w_btns = wb
        self.w_banner.bind("<Configure>", lambda e: self.after_idle(self._watch_rewrap))
        self.w_report_btn = ctk.CTkButton(wb, text=T("Open report"), width=120, height=34, corner_radius=10,
                                          fg_color=ACCENT, hover_color=ACCENT_HOVER, font=ui_font(13, "bold"),
                                          state="disabled", command=self._watch_open_report)
        accent_button(self.w_report_btn)
        self.w_report_btn.pack(side="left", padx=4)
        self.w_block_btn = ctk.CTkButton(wb, text=T("Copy block list"), width=130, height=34, corner_radius=10,
                                         fg_color=NAVY_3, hover_color=HOVER, font=ui_font(13), state="disabled",
                                         command=self._watch_copy_block)
        self.w_block_btn.pack(side="left", padx=4)

        self.w_results = ctk.CTkScrollableFrame(right, fg_color=NAVY_0, corner_radius=0,
                                                scrollbar_button_color=NAVY_3, scrollbar_button_hover_color=HOVER)
        self.w_results.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 6))
        self.w_results.grid_columnconfigure(0, weight=1)
        self.w_canvas = self.w_results._parent_canvas
        self.w_canvas.configure(yscrollincrement=1)
        self.w_results.bind("<Configure>", lambda e: self.w_canvas.configure(scrollregion=self.w_canvas.bbox("all")), add="+")
        self.w_row = 0
        self.w_last = None          # (results, own, problems)
        self.w_report = None

    def _switch_page(self, value):
        self.page = "watch" if value == T("Domain watch") else "files"
        self.nav.set(value)
        if self.page == "watch":
            self.side_frame.grid_remove()
            self.main_frame.grid_remove()
            self.footer_btns.grid_remove()
            self.watch_page.grid(row=1, column=0, columnspan=2, sticky="nsew")
        else:
            self.watch_page.grid_remove()
            self.side_frame.grid()
            self.main_frame.grid()
            self.footer_btns.grid()

    def _watch_run(self):
        if not self.ready or getattr(self, "w_busy", False):
            return
        import domain_watch as dw
        raw = self.w_text.get("1.0", "end")
        domains = []
        for ln in raw.splitlines():
            d = ln.strip().lower().removeprefix("https://").removeprefix("http://").removeprefix("www.").split("/")[0]
            if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d) and d not in domains:
                domains.append(d)
        if not domains:
            self.w_status.configure(text="Add at least one domain, for example our own email domain.")
            return
        try:
            (HERE / "watch_domains.txt").write_text(
                "# Domains watched for lookalikes. Also treated as 'our company' in email and link checks.\n"
                + "\n".join(domains) + "\n", encoding="utf-8")
        except Exception:
            pass
        self.w_busy = True
        self.w_run.configure(state="disabled", text="Checking...")
        for w in self.w_results.winfo_children():
            w.destroy()
        self.w_row = 0
        self.w_report_btn.configure(state="disabled")
        self.w_block_btn.configure(state="disabled")
        self.w_dot.configure(fg_color=NAVY_3)
        self.w_banner.configure(fg_color=NAVY_1)
        n = sum(len(dw.variants(d)) for d in domains)
        self.w_title.configure(text=f"Checking {n} possible lookalikes...")
        self.w_status.configure(text="Asking DNS which of them exist. Takes 1 to 3 minutes.")
        self._set_busy_ui(True, "Domain watch running...")

        def work():
            try:
                res, problems = dw.watch(domains, progress=lambda d, t: self.q.put(("wprogress", d, t)))
            except Exception as e:
                res, problems = [], [f"Domain watch failed: {e}"]
            self.q.put(("wdone", res, domains, problems))
        threading.Thread(target=work, daemon=True).start()

    def _watch_done(self, results, own, problems):
        import domain_watch as dw
        self.w_busy = False
        self.w_run.configure(state="normal", text=T("Check for lookalikes"))
        self._set_busy_ui(False, "Domain watch finished.")
        self.w_last = (results, own, problems)
        high = sum(r["level"] == engine.HIGH for r in results)
        med = sum(r["level"] == engine.MED for r in results)
        if problems and not results:
            lvl, title = "warn", "Could not check lookalikes"
        elif high:
            lvl, title = "danger", f"{high} dangerous lookalike domain(s)"
        elif med:
            lvl, title = "warn", f"{med} suspicious lookalike domain(s)"
        else:
            lvl, title = "known", "No dangerous lookalikes found"
        lv = LEVELS[lvl]
        self.w_dot.configure(fg_color=lv["color"])
        self.w_banner.configure(fg_color=lv["soft"] if lvl in ("danger", "warn") else NAVY_1)
        self.w_title.configure(text=title)
        self.w_status.configure(text=(problems[0] if problems else
                                      f"{len(results)} registered lookalike(s) of {', '.join(own)}  ·  {datetime.now():%d %b %Y %H:%M}"))
        for r in results:
            self._watch_card(r)
        if not results and not problems:
            self._label(self.w_results, "None of the lookalikes are registered. Run this again next month.", 13, MUTED,
                        NAVY_0).grid(row=0, column=0, pady=40)
        try:
            page = report.build_watch_html(results, own, problems, getpass.getuser())
            name = f"Domain-watch-{datetime.now():%Y%m%d-%H%M}.html"
            self.w_report = report.write_text_safely(report.fallback_dir() / name, page)
        except Exception:
            self.w_report = None
        self.w_report_btn.configure(state="normal" if self.w_report else "disabled")
        self.w_block_btn.configure(state="normal" if dw.block_list(results) else "disabled")
        self.w_canvas.configure(scrollregion=self.w_canvas.bbox("all"))

    def _watch_card(self, r):
        lvl = {engine.HIGH: "danger", engine.MED: "warn"}.get(r["level"], "clean")
        lv = LEVELS[lvl]
        label = T("PROBABLY OURS" if r.get("ours") else ("PARKED" if r["level"] == engine.INFO else lv["label"]))
        card = ctk.CTkFrame(self.w_results, fg_color=NAVY_2, corner_radius=14)
        card.grid(row=self.w_row, column=0, sticky="ew", padx=10, pady=6)
        self.w_row += 1
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkFrame(card, width=5, height=10, corner_radius=3, fg_color=lv["color"]).grid(row=0, column=0, sticky="ns",
                                                                                          padx=(10, 0), pady=12)
        body = tk.Frame(card, bg=NAVY_2)
        body.grid(row=0, column=1, sticky="ew", padx=14, pady=12)
        body.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(body, text=f" {label} ", font=ui_font(11, "bold"), text_color=lv["color"], fg_color=lv["soft"],
                     corner_radius=8, height=24).grid(row=0, column=0, sticky="nw", padx=(0, 12))
        self._label(body, r["domain"], 14, TEXT, mono=True, weight="bold").grid(row=0, column=1, sticky="w")
        ctk.CTkButton(body, text="Copy", width=58, height=26, corner_radius=8, fg_color=NAVY_3, hover_color=HOVER,
                      font=ui_font(11), command=lambda d=r["domain"]: self._to_clipboard(d, f"{d} copied.")
                      ).grid(row=0, column=2, sticky="ne", padx=(10, 0))
        self._label(body, f"Imitates {r['imitates']}  ·  {r['technique']}", 11, MUTED).grid(
            row=1, column=1, columnspan=2, sticky="w", pady=(4, 6))
        lines = [(FIND_COL.get(r["level"], MUTED), i18n.msg(r["why"]))]
        if r.get("created"):
            lines.append((MUTED, f"Registered {r['created']}" + (f" ({r['age_days']} days ago)" if r.get("age_days") is not None else "")))
        if r["mx"]:
            lines.append((MUTED, "Mail servers: " + ", ".join(r["mx"][:3])))
        if r["a"]:
            lines.append((MUTED, "Website address: " + ", ".join(r["a"][:3])))
        for i, (c, t) in enumerate(lines):
            line = tk.Frame(body, bg=NAVY_2)
            line.grid(row=2 + i, column=1, columnspan=2, sticky="ew", pady=1)
            self._label(line, "●", 9, c).pack(side="left", anchor="n", pady=(3, 0))
            self._label(line, t, 12, BODY, reserve=320).pack(side="left", anchor="w", padx=(6, 0))

    def _watch_open_report(self):
        if self.w_report and Path(self.w_report).exists():
            webbrowser.open(Path(self.w_report).as_uri())

    def _watch_copy_block(self):
        import domain_watch as dw
        if self.w_last:
            blk = dw.block_list(self.w_last[0])
            self._to_clipboard("\n".join(blk), f"{len(blk)} domain(s) copied for the block list.")

    # ---------------------------------------------------------- actions
    def _copy_summary(self):
        text = report.summary_text(self.results, self.last_mode, getpass.getuser())
        self._to_clipboard(text, T("Ticket summary copied. Paste it into the ticket."))

    def _to_clipboard(self, text, msg):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()   # keeps the clipboard after the app closes on Windows
        self.status.configure(text=msg)

    def _open_path(self, p):
        try:
            if os.name == "nt":
                os.startfile(p)
            else:
                webbrowser.open(Path(p).as_uri())
        except Exception:
            pass

    def _open_report(self):
        if self.last_report and Path(self.last_report).exists():
            webbrowser.open(Path(self.last_report).as_uri())

    def _open_folder(self):
        target = self.last_report or (self.results[-1][0] if self.results else None)
        if not target:
            return
        if os.name == "nt":
            import subprocess
            subprocess.Popen(["explorer", "/select,", str(target)])
        else:
            self._open_path(str(Path(target).parent))

    def _open_banks(self):
        self._open_path(str(HERE / "banks.txt"))

    def _open_help(self):
        greek = HERE / "README-EL.txt"
        self._open_path(str(greek if i18n.language() == "el" and greek.exists() else HERE / "README.txt"))

    def _clear(self, keep_banner=False):
        for w in self.results_frame.winfo_children():
            w.destroy()
        self.wrap_labels = []
        self.row = 0
        self.canvas.yview_moveto(0)
        if not keep_banner:
            self.results = []
            self.last_report = None
            self._set_banner("clean", T("Ready"), T("Drop a suspicious email or attachment to begin."))
            self.banner_dot.configure(fg_color=NAVY_3)
            for b in (self.copy_btn, self.recheck_btn, self.folder_btn, self.report_btn):
                b.configure(state="disabled")
            self.status.configure(text=T("Ready."))
            self._show_empty_state()
        self._update_scrollregion()

    def _refresh_key_status(self):
        self.keys = engine.load_keys()
        has_us = bool(self.keys.get("URLSCAN_API_KEY"))
        has_vt = bool(self.keys.get("VT_API_KEY"))
        self.us_status.configure(text=("● urlscan.io" if has_us else "○ urlscan.io"),
                                 text_color="#30a46c" if has_us else MUTED)
        self.vt_status.configure(text=("● VirusTotal" if has_vt else "○ VirusTotal"),
                                 text_color="#30a46c" if has_vt else MUTED)
        if has_us:
            self.live_switch.configure(state="normal")
            self.live_hint.configure(text=T("On: urlscan.io opens the link on its own servers."))
        else:
            self.live_var.set(False)
            self.live_switch.configure(state="disabled")
            self.live_hint.configure(text=T("Add a urlscan.io key in Settings to turn this on."))
        self._refresh_list_status()

    def _refresh_list_status(self):
        """Which brand list is in use: the shared one, its last copy, or this PC's own."""
        try:
            engine.load_brands()
            source, _ = appconfig.brand_list_state()
        except Exception:
            source = "local"
        text, colour = {"shared": ("● " + T("Brand list: shared"), "#30a46c"),
                        "cached": ("● " + T("Brand list: last shared copy"), "#f5a524"),
                        "local-fallback": ("● " + T("Brand list: shared list not reachable"), "#e5484d"),
                        }.get(source, ("○ " + T("Brand list: this PC"), MUTED))
        self.list_status.configure(text=text, text_color=colour)

    def _open_settings(self):
        if self.ready:
            SettingsDialog(self)


class NoticeDialog(ctk.CTkToplevel):
    """A message the user must be able to read in full (the status bar cuts long text off).
    Not modal: it may appear while a drag is still in progress."""
    def __init__(self, app, title, body):
        super().__init__(app)
        self.title(APP_NAME)
        self.configure(fg_color=NAVY_1)
        self.resizable(False, False)
        self.transient(app)
        self.attributes("-topmost", True)
        ctk.CTkLabel(self, text=title, font=ui_font(16, "bold"), text_color=LEVELS["warn"]["color"],
                     wraplength=540, justify="left").pack(anchor="w", padx=26, pady=(22, 10))
        ctk.CTkLabel(self, text=body, font=ui_font(13), text_color=TEXT,
                     wraplength=540, justify="left").pack(anchor="w", padx=26)
        ok = ctk.CTkButton(self, text="OK", width=120, height=34, corner_radius=17, fg_color=ACCENT,
                           hover_color=ACCENT_HOVER, font=ui_font(13, "bold"), command=self.destroy)
        ok.pack(anchor="e", padx=26, pady=(18, 20))
        for key in ("<Escape>", "<Return>"):
            self.bind(key, lambda e: self.destroy())
        self.update_idletasks()
        x = app.winfo_rootx() + max(0, (app.winfo_width() - self.winfo_width()) // 2)
        y = app.winfo_rooty() + max(0, (app.winfo_height() - self.winfo_height()) // 3)
        self.geometry(f"+{x}+{y}")
        self.after(50, ok.focus_set)
        own_icon(self)


class PasteDialog(ctk.CTkToplevel):
    """Paste an email as text. Best: the message source with headers, so the sender can be checked too."""
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title(T("Paste email text"))
        self.geometry(f"760x560+{app.winfo_rootx() + 210}+{app.winfo_rooty() + 70}")
        self.minsize(560, 400)
        self.configure(fg_color=NAVY_1)
        self.transient(app)
        self.after(150, self.grab_set)
        own_icon(self)
        ctk.CTkLabel(self, text=T("Paste email text"), font=ui_font(18, "bold"), text_color=TEXT).pack(anchor="w", padx=24, pady=(20, 2))
        ctk.CTkLabel(self, text=T("Best: the full message source, headers included (Outlook: open the email > File > Properties >\n"
                                  "copy \"Internet headers\", then paste the body under them). Body text alone also works,\n"
                                  "but then the sender cannot be checked. The text is only read, never opened or run."),
                     font=ui_font(12), text_color=MUTED, justify="left").pack(anchor="w", padx=24)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=18, side="bottom")
        ctk.CTkButton(row, text=T("Check"), width=120, height=36, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=ui_font(13, "bold"), command=self._go).pack(side="right")
        ctk.CTkButton(row, text=T("Cancel"), width=90, height=36, fg_color=NAVY_3, hover_color=HOVER,
                      font=ui_font(13), command=self.destroy).pack(side="right", padx=8)
        ctk.CTkButton(row, text=T("Paste from clipboard"), width=190, height=36, fg_color=NAVY_3, hover_color=HOVER,
                      font=ui_font(13), command=self._from_clipboard).pack(side="left")
        self.box = ctk.CTkTextbox(self, fg_color=NAVY_2, border_color=NAVY_3, border_width=1, wrap="word",
                                  font=ctk.CTkFont(family=MONO_FAMILY, size=12))
        self.box.pack(fill="both", expand=True, padx=24, pady=(12, 0))
        self.box.focus_set()

    def _from_clipboard(self):
        try:
            self.box.insert("end", self.clipboard_get())
        except Exception:
            pass

    def _go(self):
        text = self.box.get("1.0", "end")
        self.destroy()
        self.app.check_pasted(text)


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title(T("Settings"))
        self.geometry(f"560x640+{app.winfo_rootx() + 310}+{app.winfo_rooty() + 60}")
        self.resizable(False, False)
        self.configure(fg_color=NAVY_1)
        self.transient(app)
        self.after(150, self.grab_set)
        own_icon(self)
        ctk.CTkLabel(self, text=T("Settings"), font=ui_font(18, "bold"), text_color=TEXT).pack(anchor="w", padx=26, pady=(22, 2))
        ctk.CTkLabel(self, text=T("Keys are stored on this PC only, in keys.txt."), font=ui_font(12),
                     text_color=MUTED).pack(anchor="w", padx=26)
        keys = engine.load_keys()
        self.entries = {}
        for k, title, hint in (("URLSCAN_API_KEY", "urlscan.io API key",
                                "Needed for live scans and screenshots. urlscan.io > Profile > API keys."),
                               ("VT_API_KEY", "VirusTotal API key (optional)",
                                "Adds domain reputation. virustotal.com > profile > API key.")):
            ctk.CTkLabel(self, text=T(title), font=ui_font(13, "bold"), text_color=TEXT).pack(anchor="w", padx=26, pady=(18, 0))
            e = ctk.CTkEntry(self, show="•", height=36, fg_color=NAVY_2, border_color=NAVY_3,
                             font=ctk.CTkFont(family=MONO_FAMILY, size=12))
            e.insert(0, keys.get(k, ""))
            e.pack(fill="x", padx=26, pady=(4, 0))
            ctk.CTkLabel(self, text=T(hint), font=ui_font(11), text_color=MUTED).pack(anchor="w", padx=26)
            self.entries[k] = e
        self.show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(self, text=T("Show keys"), variable=self.show_var, font=ui_font(12), text_color=MUTED,
                        command=self._toggle).pack(anchor="w", padx=26, pady=(12, 0))
        cfg = appconfig.load()
        ctk.CTkLabel(self, text=T("Shared brand list (path to one banks.txt for everybody)"), font=ui_font(13, "bold"),
                     text_color=TEXT).pack(anchor="w", padx=26, pady=(18, 0))
        self.shared_entry = ctk.CTkEntry(self, height=36, fg_color=NAVY_2, border_color=NAVY_3,
                                         font=ctk.CTkFont(family=MONO_FAMILY, size=12))
        self.shared_entry.insert(0, cfg.get("SHARED_BANK_LIST", ""))
        self.shared_entry.pack(fill="x", padx=26, pady=(4, 0))
        ctk.CTkLabel(self, text=T("Leave empty to use this PC's own list. Example: \\\\server\\ict\\banks.txt"),
                     font=ui_font(11), text_color=MUTED).pack(anchor="w", padx=26)
        # always both languages, so someone stuck in the wrong one can still find it (2.3: showed "Γλώσσα / Γλώσσα")
        ctk.CTkLabel(self, text="Language / Γλώσσα", font=ui_font(13, "bold"), text_color=TEXT).pack(
            anchor="w", padx=26, pady=(18, 0))
        self.lang_codes = {"Auto": "auto", "English": "en", "Ελληνικά": "el"}
        current = next((k for k, v in self.lang_codes.items() if v == cfg.get("LANGUAGE", "auto").lower()), "Auto")
        self.lang_var = ctk.StringVar(value=current)
        ctk.CTkOptionMenu(self, values=list(self.lang_codes), variable=self.lang_var, width=180, height=32,
                          fg_color=NAVY_3, button_color=NAVY_3, button_hover_color=HOVER,
                          font=ui_font(13)).pack(anchor="w", padx=26, pady=(4, 0))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=26, pady=22, side="bottom")
        ctk.CTkButton(row, text=T("Save"), width=110, height=36, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=ui_font(13, "bold"), command=self._save).pack(side="right")
        ctk.CTkButton(row, text=T("Cancel"), width=90, height=36, fg_color=NAVY_3, hover_color=HOVER,
                      font=ui_font(13), command=self.destroy).pack(side="right", padx=8)

    def _toggle(self):
        for e in self.entries.values():
            e.configure(show="" if self.show_var.get() else "•")

    def _save(self):
        vals = {k: e.get().strip() for k, e in self.entries.items()}
        text = ("# Saved by Email Analyzer. Keys stay on this PC.\n"
                "# urlscan.io: https://urlscan.io/user/profile/\n"
                f"URLSCAN_API_KEY={vals['URLSCAN_API_KEY']}\n\n"
                "# VirusTotal: https://www.virustotal.com/gui/my-apikey\n"
                f"VT_API_KEY={vals['VT_API_KEY']}\n")
        (HERE / "keys.txt").write_text(text, encoding="utf-8")
        old_lang = appconfig.get("LANGUAGE").lower() or "auto"
        new_lang = self.lang_codes.get(self.lang_var.get(), "auto")
        try:
            appconfig.save({"SHARED_BANK_LIST": self.shared_entry.get().strip(), "LANGUAGE": new_lang})
        except Exception:
            pass
        self.app._refresh_key_status()
        self.app.status.configure(text=T("Settings saved. Close and reopen the app to change the language."
                                         if new_lang != old_lang else "Settings saved."))
        self.destroy()


def main():
    if os.name == "nt":
        try:  # own taskbar icon instead of the Python one
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("EmailAnalyzer.Desktop")
        except Exception:
            pass
    files = [a for a in sys.argv[1:] if Path(a).is_file()]
    App(initial_files=files).mainloop()


if __name__ == "__main__":
    main()
