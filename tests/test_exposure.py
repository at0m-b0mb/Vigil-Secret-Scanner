"""
The exposure map's data.

The widget is painted, but the thing it paints is a pure function, which is
where the honesty of the picture actually lives. If these hold, the map cannot
drift from the document it claims to summarise.
"""

import os

import pytest

from vigil.core.grade import analyze
from vigil.core.model import Severity
from vigil.core.scan import exposure_bands, scan

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

AKIA = "AKIAEXAMPLEKEY123456"
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "bm90LWEtcmVhbC1rZXk=\n"
       "bm90LWEtcmVhbC1rZXk=\n"
       "bm90LWEtcmVhbC1rZXk=\n"
       "-----END RSA PRIVATE KEY-----")


def _sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _doc(lines: int, hits: dict[int, str] | None = None) -> str:
    """A synthetic document of *lines* lines, with a secret on chosen lines."""
    hits = hits or {}
    out = []
    for n in range(1, lines + 1):
        out.append(hits.get(n, f"# line {n}"))
    return "\n".join(out)


# --- coverage ---------------------------------------------------------------

@pytest.mark.parametrize("lines,buckets", [
    (1, 1), (1, 40), (10, 4), (10, 10), (10, 40), (97, 16), (500, 64),
])
def test_bands_cover_every_line_exactly_once(lines, buckets):
    result = scan(_doc(lines))
    bands = exposure_bands(result, buckets)
    assert bands[0].first_line == 1
    assert bands[-1].last_line == result.line_count
    for a, b in zip(bands, bands[1:]):
        assert b.first_line == a.last_line + 1
    assert sum(b.last_line - b.first_line + 1 for b in bands) == result.line_count


@pytest.mark.parametrize("buckets", [1, 3, 7, 16, 64])
def test_band_indices_run_in_order_from_zero(buckets):
    bands = exposure_bands(scan(_doc(80)), buckets)
    assert [b.index for b in bands] == list(range(len(bands)))


def test_more_buckets_than_lines_gives_one_band_per_line():
    bands = exposure_bands(scan(_doc(6)), 200)
    assert len(bands) == 6
    assert all(b.first_line == b.last_line for b in bands)


def test_zero_or_negative_buckets_still_gives_one_band():
    for buckets in (0, -5):
        assert len(exposure_bands(scan(_doc(10)), buckets)) == 1


def test_an_unexamined_document_still_produces_a_band():
    bands = exposure_bands(scan(""), 20)
    assert len(bands) == 1
    assert bands[0].is_quiet


# --- quiet and loud ---------------------------------------------------------

def test_a_clean_document_has_no_tinted_band():
    bands = exposure_bands(scan(_doc(40)), 20)
    assert all(b.is_quiet for b in bands)
    assert all(b.hits == 0 for b in bands)


def test_a_hit_tints_the_band_that_holds_its_line():
    result = analyze(_doc(40, {12: f"KEY={AKIA}"}))
    bands = exposure_bands(result, 40)
    loud = [b for b in bands if not b.is_quiet]
    assert len(loud) == 1
    assert loud[0].first_line == 12
    assert loud[0].severity is Severity.ALERT


def test_a_band_takes_the_worst_severity_in_its_range():
    text = _doc(8, {
        3: "STRIPE=sk_test_EXAMPLEnotarealkey00",   # notice
        4: f"KEY={AKIA}",                           # alert
    })
    bands = exposure_bands(analyze(text), 4)      # two lines per band
    holder = next(b for b in bands if b.first_line <= 3 <= b.last_line)
    assert holder.severity is Severity.ALERT
    assert holder.hits == 2


def test_a_block_paints_every_line_it_spans():
    text = _doc(3) + "\n" + PEM + "\n" + _doc(3)
    result = analyze(text)
    bands = exposure_bands(result, result.line_count)
    loud = [b.first_line for b in bands if not b.is_quiet]
    assert loud == [4, 5, 6, 7, 8]


def test_every_occurrence_of_a_collapsed_value_is_painted():
    text = _doc(20, {4: f"A={AKIA}", 11: f"B={AKIA}", 18: f"C={AKIA}"})
    result = analyze(text)
    bands = exposure_bands(result, result.line_count)
    assert [b.first_line for b in bands if not b.is_quiet] == [4, 11, 18]
    assert len(result.findings) == 1        # one value, three places


def test_hits_count_occurrences_not_findings():
    text = _doc(4, {2: f"A={AKIA} B=ghp_EXAMPLEnotarealtokenEXAMPLE000000000"})
    bands = exposure_bands(analyze(text), 4)
    assert bands[1].hits == 2


def test_the_loud_bands_match_the_exposed_line_set():
    result = analyze(_sample("webhook_service.py"))
    bands = exposure_bands(result, result.line_count)
    loud = {b.first_line for b in bands if not b.is_quiet}
    assert loud == result.exposed_lines


@pytest.mark.parametrize("buckets", [1, 2, 7, 13, 32, 41])
def test_a_tinted_band_always_covers_the_line_that_caused_it(buckets):
    """The invariant: the layout and the line lookup must never disagree.

    Both are derived from one edge list, and this walks every line of a
    document to prove it — the kind of off-by-one that makes a minimap lie
    about where a secret is.
    """
    for line in range(1, 41):
        result = analyze(_doc(40, {line: f"KEY={AKIA}"}))
        loud = [b for b in exposure_bands(result, buckets) if not b.is_quiet]
        assert len(loud) == 1, (buckets, line)
        assert loud[0].first_line <= line <= loud[0].last_line, (buckets, line)


# --- the samples ------------------------------------------------------------

@pytest.mark.parametrize("name", ["leaky.env", "tidy-config.yml",
                                  "webhook_service.py", "docker-compose.yml",
                                  "release-notes.md"])
@pytest.mark.parametrize("buckets", [8, 32, 120])
def test_a_sample_maps_without_drifting(name, buckets):
    result = analyze(_sample(name))
    bands = exposure_bands(result, buckets)
    assert bands[0].first_line == 1
    assert bands[-1].last_line == result.line_count
    assert sum(b.hits for b in bands) >= result.total_occurrences
    for band in bands:
        if not band.is_quiet:
            covered = set(range(band.first_line, band.last_line + 1))
            assert covered & result.exposed_lines


def test_the_tidy_sample_maps_entirely_quiet():
    result = analyze(_sample("tidy-config.yml"))
    assert all(b.is_quiet for b in exposure_bands(result, 32))


def test_the_leaky_sample_clusters_its_exposure():
    result = analyze(_sample("leaky.env"))
    bands = exposure_bands(result, 8)
    loud = [b for b in bands if not b.is_quiet]
    # Every key sits in the lower two-thirds of the file, which is the whole
    # point of drawing the distribution rather than listing it.
    assert loud
    assert min(b.index for b in loud) >= 2
