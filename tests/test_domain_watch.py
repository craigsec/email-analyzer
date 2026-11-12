"""Lookalike domain watch, with a simulated DNS (no internet needed)."""
import sys
from pathlib import Path

import domain_watch as W  # noqa: E402


class FakeDNS:
    def __init__(self, zones, broken=False, everything_missing=False):
        self.zones, self.broken, self.missing = zones, broken, everything_missing

    def query(self, name, rtype):
        if self.broken:
            raise ConnectionError("timeout")
        if self.missing:
            return None
        z = self.zones.get(name)
        if z is None:
            return None
        return z.get(rtype, [])


ZONES = {
    "microsoft.com": {"NS": ["ns1.msft.net"]}, "google.com": {"NS": ["ns1.google.com"]},
    "acmeshipping.com": {"NS": ["ns1.ourdns.net"], "MX": ["mail.acmeshipping.com"], "A": ["1.2.3.4"]},
    "acmesh1pping.com": {"NS": ["ns1.evil.net"], "MX": ["mx.evil.net"], "A": ["5.6.7.8"]},        # digit-for-letter typo, with email
    "acmeshipping-invoice.com": {"NS": ["ns1.evil.net"], "A": ["5.6.7.9"]},                       # word added, website
    "acmeshipping.top": {"NS": ["ns1.parking.net"]},                                               # parked
    "acmeshipping.net": {"NS": ["ns1.ourdns.net"], "A": ["1.2.3.4"]},                              # defensive, ours
}


def test_variants_cover_the_usual_tricks():
    v = W.variants("acmeshipping.com")
    for d, how in (("acmesh1pping.com", "look-alike"), ("acmesipping.com", "missing"), ("acmesihpping.com", "swapped"),
                   ("acmeshipping-invoice.com", "added word"), ("acmeshipping.gr", "ending"), ("acmeshipping.top", "ending")):
        assert d in v and how in v[d], (d, v.get(d))
    assert any(d.startswith("xn--") for d in v), "foreign-alphabet look-alikes"
    assert "acmeshipping.com" not in v and len(v) > 150


def test_watch_finds_and_ranks_registered_lookalikes():
    res, msgs = W.watch(["acmeshipping.com"], dns=FakeDNS(ZONES), rdap=False)
    by = {r["domain"]: r for r in res}
    assert set(by) == {"acmesh1pping.com", "acmeshipping-invoice.com", "acmeshipping.top", "acmeshipping.net"}
    assert by["acmesh1pping.com"]["level"] == "HIGH" and "email" in by["acmesh1pping.com"]["why"]
    assert by["acmeshipping-invoice.com"]["level"] == "MEDIUM"
    assert by["acmeshipping.top"]["level"] == "INFO" and "parked" in by["acmeshipping.top"]["why"]
    assert by["acmeshipping.net"]["ours"] and by["acmeshipping.net"]["level"] == "INFO"
    assert res[0]["domain"] == "acmesh1pping.com"
    assert W.block_list(res) == ["acmesh1pping.com", "acmeshipping-invoice.com"]
    txt = W.summary_text(res, ["acmeshipping.com"])
    assert "acmesh1pping[.]com" in txt and "acmesh1pping.com" not in txt


def test_refuses_all_clear_when_dns_is_broken_or_filtered():
    for dns in (FakeDNS(ZONES, broken=True), FakeDNS(ZONES, everything_missing=True)):
        res, msgs = W.watch(["acmeshipping.com"], dns=dns, rdap=False)
        assert res == [] and msgs and "DNS is not working" in msgs[0]


def test_watch_list_file(tmp_path):
    f = tmp_path / "watch_domains.txt"
    f.write_text("# ours\nacmeshipping.com\n\nnot a domain\nAcmeshipping.GR\n", encoding="utf-8")
    assert W.load_watch_list(f) == ["acmeshipping.com", "acmeshipping.gr"]
