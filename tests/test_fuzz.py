"""Fuzzing: hostile QR text and hostile files must never crash or hang the checker."""
import contextlib
import io
import os
import random
import sys
import time
from pathlib import Path

import pymupdf
from hypothesis import HealthCheck, given, settings, strategies as st

import qr_check as q  # noqa: E402
import report  # noqa: E402

BRANDS = q.load_brands()
TESTS = Path(__file__).resolve().parent / "samples"


def check(text):
    with contextlib.redirect_stdout(io.StringIO()):
        rec = q.check_link(text, ["fuzz"], BRANDS, {}, False, True)
    assert "verdict" in rec
    report.level_of(rec)
    report.summary_text([("f.pdf", [], [rec])], "offline", "u")
    report.build_html([("f.pdf", [], [rec])], "offline", "u", BRANDS)
    return rec


url_chars = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300)
pieces = st.sampled_from(["https://", "http://", "HTTPS://", "//", "\\", "@", "%", "%25", "%2F", "#", "?", "&", "=",
                          "xn--", "..", ".", "[", "]", ":", "::1", "0x", "1", "255", "\u202e", "\u200b", "\u0435",
                          "eurobank", ".gr", ".top", "www.", "data:", "javascript:", "WIFI:", "BEGIN:VCARD\n",
                          "aHR0cHM6Ly9", "a1", "/amp/s/", "url=", "safelinks.protection.outlook.com/?url=",
                          "urldefense.com/v3/__", "__;", " ", "\n", "\t", "\x00", "\x1b[2J"])


@settings(max_examples=1500, deadline=None, suppress_health_check=list(HealthCheck))
@given(url_chars)
def test_random_text_never_crashes(s):
    check(s)


@settings(max_examples=2500, deadline=None, suppress_health_check=list(HealthCheck))
@given(st.lists(st.one_of(pieces, st.text(max_size=12)), min_size=1, max_size=25))
def test_structured_url_garbage_never_crashes(parts):
    check("".join(parts))


def test_huge_and_nested_payloads_are_fast():
    t = time.perf_counter()
    check("https://a.top/?" + "&".join(f"u{i}=https%3A%2F%2Fx{i}.top" for i in range(400)))
    check("https://a.top/" + "%25" * 5000)
    check("https://" + "a." * 120 + "top/")
    check("data:text/html;base64," + "A" * 200000)
    check("BEGIN:VCARD\n" + "URL:https://x.top\n" * 50 + "END:VCARD")
    assert time.perf_counter() - t < 20


def _mutate(data, n, rnd):
    b = bytearray(data)
    for _ in range(n):
        i = rnd.randrange(len(b))
        b[i] = rnd.randrange(256)
    return bytes(b)


def test_corrupted_pdfs_never_crash(tmp_path):
    rnd = random.Random(1234)
    sources = [p for p in (TESTS / "QR_Test_HardMode.pdf", TESTS / "QR_Test_Breaker.pdf",
                           TESTS / "fake_phish.pdf") if p.exists()]
    assert sources
    for i in range(60):
        src = sources[i % len(sources)].read_bytes()
        bad = _mutate(src, rnd.choice([1, 5, 50, 500]), rnd)
        if i % 7 == 0:
            bad = bad[: rnd.randrange(len(bad))]          # truncated
        f = tmp_path / f"fuzz_{i}.pdf"
        f.write_bytes(bad)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                links, notes = q.collect(str(f))
        except RuntimeError as e:                           # only our own plain-language messages may escape
            assert "password" in str(e).lower() or "could not be opened" in str(e).lower(), repr(e)


def test_attachment_bomb_and_self_nesting(tmp_path):
    # a PDF attached inside a PDF inside a PDF ... 8 levels deep
    data = None
    for level in range(8):
        d = pymupdf.open()
        d.new_page().insert_text((50, 60), f"level {level} https://lvl{level}.top/x")
        if data:
            d.embfile_add(f"inner{level}.pdf", data)
        data = d.tobytes()
    f = tmp_path / "nested.pdf"
    f.write_bytes(data)
    t = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        links, notes = q.collect(str(f))
    assert time.perf_counter() - t < 30
    found = " ".join(links)
    assert "lvl7.top" in found and "lvl4.top" in found      # outer levels checked
    assert "lvl0.top" not in found                           # depth limit stops the bomb


def test_many_pages_and_links_capped(tmp_path):
    d = pymupdf.open()
    for i in range(150):
        d.new_page().insert_text((50, 60), " ".join(f"https://p{i}-{j}.top/" for j in range(3)))
    f = tmp_path / "big.pdf"
    d.save(str(f))
    t = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        links, notes = q.collect(str(f))
    assert any("only the first" in n[1] for n in notes)
    assert time.perf_counter() - t < 90


def test_non_pdf_and_empty_files(tmp_path):
    for name, data in (("empty.pdf", b""), ("random.pdf", os.urandom(4000)), ("fake.png", b"not an image"),
                       ("empty.png", b"")):
        f = tmp_path / name
        f.write_bytes(data)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                q.collect(str(f))
        except Exception as e:
            assert not isinstance(e, (RecursionError, MemoryError)), repr(e)
