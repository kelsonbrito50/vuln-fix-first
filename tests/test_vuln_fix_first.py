import io
import json
import socket
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
import vuln_fix_first as t  # noqa: E402
from vuln_fix_first import sources  # noqa: E402


def no_network(request, *args, **kwargs):
    raise AssertionError(f"test tried to reach the network: {getattr(request, 'full_url', request)}")


def setUpModule():
    """No test may reach the network or the user's real cache."""
    global _tmp, _patches
    import tempfile
    _tmp = tempfile.TemporaryDirectory()
    _patches = [mock.patch("urllib.request.urlopen", no_network),
                mock.patch.dict("os.environ", {"XDG_CACHE_HOME": _tmp.name}),
                mock.patch("time.sleep")]
    for p in _patches:
        p.start()


def tearDownModule():
    for p in _patches:
        p.stop()
    _tmp.cleanup()


def fake_net(routes):
    """urlopen stand-in: the first route whose URL prefix matches answers with its JSON, or raises it."""
    calls = []

    def urlopen(request, *args, **kwargs):
        calls.append(request.full_url)
        for prefix, answer in routes.items():
            if request.full_url.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return io.BytesIO(json.dumps(answer).encode())
        raise http_error(404)
    return mock.patch("urllib.request.urlopen", urlopen), calls


class DecisionTable(unittest.TestCase):
    def test_table_has_all_36_rows(self):
        self.assertEqual(len(t.SSVC), 36)

    def test_known_rows(self):
        # Spot checks against cisa_coordinator_2_0_3.csv rows 0, 5, 8, 16, 29, 30, 34.
        self.assertEqual(t.decide("none", "no", "partial", "low"), "track")
        self.assertEqual(t.decide("none", "no", "total", "high"), "track*")
        self.assertEqual(t.decide("none", "yes", "partial", "high"), "attend")
        self.assertEqual(t.decide("public poc", "no", "total", "medium"), "track*")
        self.assertEqual(t.decide("active", "no", "total", "high"), "act")
        self.assertEqual(t.decide("active", "yes", "partial", "low"), "attend")
        self.assertEqual(t.decide("active", "yes", "total", "medium"), "act")


class Parsing(unittest.TestCase):
    def test_extract_ids_dedupes_and_normalizes(self):
        text = '{"id": "cve-2021-44228"} CVE-2021-44228 GHSA-JFH8-C2JP-5V3Q CVE-2024-3400'
        cves, ghsas = t.extract_ids(text)
        self.assertEqual(cves, ["CVE-2021-44228", "CVE-2024-3400"])
        self.assertEqual(ghsas, ["GHSA-jfh8-c2jp-5v3q"])

    def test_decode_utf16_and_utf8(self):
        text = '{"id": "CVE-2021-44228", "title": "Log4Shell é"}'
        self.assertEqual(t.decode(text.encode("utf-16")), text)  # Windows PowerShell 5.1 redirect
        self.assertEqual(t.decode(b"\xef\xbb\xbf" + text.encode()), text)
        self.assertIn("CVE-2021-44228", t.decode(b"CVE-2021-44228 \xff bad byte"))

    def test_parse_record(self):
        record = json.loads((HERE / "fixtures" / "sample-record.json").read_text())
        info = t.parse_record(record)
        self.assertEqual(info["product"], "ExampleOS")
        self.assertEqual(info["cvss"], ("3.1", 9.1))
        self.assertEqual(info["ssvc"], {"exploitation": "active", "automatable": "yes", "technical impact": "total"})

    def test_parse_record_poc_and_na_product(self):
        ssvc = {"type": "ssvc", "content": {"options": [{"Exploitation": "poc"}, {"Automatable": "no"}]}}
        record = {"containers": {"cna": {"affected": [{"vendor": "n/a", "product": "n/a", "packageName": "qs"}]},
                                 "adp": [{"metrics": [{"other": ssvc}]}]}}
        info = t.parse_record(record)
        self.assertEqual(info["product"], "qs")
        self.assertEqual(info["ssvc"]["exploitation"], "public poc")

    def test_parse_record_strips_terminal_escapes(self):
        record = {"containers": {"cna": {"affected": [{"product": "evil\x1b[2J\x1b]0;pwned\x07lib"}]}}}
        self.assertEqual(t.parse_record(record)["product"], "evil[2J]0;pwnedlib")


class Triage(unittest.TestCase):
    EMPTY = {"product": "", "cvss": None, "ssvc": {}}

    def test_kev_forces_active(self):
        r = t.triage("CVE-1", {**self.EMPTY, "ssvc": {"exploitation": "none"}}, 0.01, True, "medium")
        self.assertEqual(r["exploitation"], "active")

    def test_missing_data_marked_assumed(self):
        r = t.triage("CVE-1", self.EMPTY, None, False, "high")
        self.assertEqual(r["assumed"], ["exploitation", "automatable", "technical impact"])
        self.assertEqual(r["decision"], "attend")  # none, yes, total, high

    def test_sort_order(self):
        rows = [
            {"decision": "track", "in_kev": False, "epss": 0.9},
            {"decision": "act", "in_kev": False, "epss": 0.1},
            {"decision": "act", "in_kev": True, "epss": 0.05},
            {"decision": "act", "in_kev": False, "epss": 0.5},
        ]
        got = [(r["decision"], r["in_kev"], r["epss"]) for r in sorted(rows, key=t.sort_key)]
        self.assertEqual(got, [("act", True, 0.05), ("act", False, 0.5), ("act", False, 0.1), ("track", False, 0.9)])

    def test_ransomware_ranks_first_within_kev(self):
        rows = [{"decision": "act", "in_kev": True, "ransomware": False, "epss": 0.9},
                {"decision": "act", "in_kev": True, "ransomware": True, "epss": 0.1}]
        self.assertTrue(sorted(rows, key=t.sort_key)[0]["ransomware"])

    def test_by_package_groups_and_orders(self):
        rows = sorted([
            t.triage("CVE-1", {**self.EMPTY, "product": "lodash"}, 0.1, False, "medium"),
            t.triage("CVE-2", {**self.EMPTY, "product": "Lodash"}, 0.2, False, "medium"),
            t.triage("CVE-3", {**self.EMPTY, "product": "log4j"}, 0.9, True, "medium"),
        ], key=t.sort_key)
        groups = t.by_package(rows)
        self.assertEqual([(name, len(r)) for name, r in groups], [("log4j", 1), ("Lodash", 2)])


class Planning(unittest.TestCase):
    TODAY = __import__("datetime").date(2026, 1, 1)

    def test_load_ignores(self):
        text = "# accepted risk\nCVE-2021-44228 2026-06-30 WAF blocks it\ncve-2024-3400 2025-12-31 old\n\n"
        active, expired = t.load_ignores(text, self.TODAY)
        self.assertEqual(active, {"CVE-2021-44228": ("2026-06-30", "WAF blocks it")})
        self.assertEqual(expired, ["CVE-2024-3400"])

    def test_load_ignores_rejects_bad_lines(self):
        for bad in ("CVE-2021-44228", "CVE-2021-44228 2026-13-01 x", "lodash 2026-06-30 x"):
            with self.assertRaises(ValueError):
                t.load_ignores(bad, self.TODAY)

    def test_expected_attacked(self):
        rows = [{"epss": 0.5}, {"epss": 0.25}, {"epss": None}]
        self.assertAlmostEqual(t.expected_attacked(rows), 0.75)

    def test_percentile_in_reason(self):
        r = t.triage("CVE-1", Triage.EMPTY, 0.189, False, "medium", percentile=0.953)
        self.assertIn("EPSS 18.9% (top 4.7%)", t.reason(r))

    def test_capacity_rejects_zero(self):
        with self.assertRaises(SystemExit):
            t.main(["CVE-2021-44228", "--capacity", "0"])


class Deadline(unittest.TestCase):
    TODAY = __import__("datetime").date(2026, 1, 1)

    def test_table_has_all_16_rows(self):
        self.assertEqual(len(t.DEADLINE), 16)

    def test_known_rows(self):
        # Spot checks against cisa_bod_26_04_1_0_0.csv rows 0, 2, 11, 12, 14.
        self.assertEqual(t.deadline(False, False, "no", "partial", self.TODAY), ("at next system upgrade", None))
        self.assertEqual(t.deadline(False, True, "no", "partial", self.TODAY), ("within 60 days", "2026-03-02"))
        self.assertEqual(t.deadline(True, True, "yes", "partial", self.TODAY), ("within 3 days", "2026-01-04"))
        self.assertEqual(t.deadline(True, True, "no", "total", self.TODAY),
                         ("within 3 days + check for compromise", "2026-01-04"))
        self.assertEqual(t.deadline(False, True, "yes", "total", self.TODAY), ("within 3 days", "2026-01-04"))

    def test_exposed_shortens_deadline(self):
        info = {"product": "", "cvss": None, "ssvc": {"automatable": "yes", "technical impact": "total"}}
        inside = t.triage("CVE-1", info, None, False, "medium", exposed=False)
        public = t.triage("CVE-1", info, None, False, "medium", exposed=True)
        self.assertEqual((inside["fix_within"], public["fix_within"]), ("within 60 days", "within 3 days"))


def http_error(code):
    return urllib.error.HTTPError("https://example.test", code, "error", {}, io.BytesIO(b""))


class Retry(unittest.TestCase):
    def test_retries_429_5xx_and_timeouts_then_succeeds(self):
        answers = [http_error(429), urllib.error.URLError(socket.timeout("timed out")), io.BytesIO(b'{"ok": 1}')]
        with mock.patch("urllib.request.urlopen", side_effect=answers) as urlopen,                 mock.patch("time.sleep") as sleep:
            self.assertEqual(t.get_json("https://example.test"), {"ok": 1})
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [1, 2])

    def test_gives_up_after_3_tries(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(503)] * 3) as urlopen,                 mock.patch("time.sleep"):
            with self.assertRaises(urllib.error.HTTPError):
                t.get_json("https://example.test")
        self.assertEqual(urlopen.call_count, 3)

    def test_404_is_not_retried(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(404)]) as urlopen,                 mock.patch("time.sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                t.get_json("https://example.test")
        self.assertEqual((urlopen.call_count, sleep.call_count), (1, 0))


class Cache(unittest.TestCase):
    KEV = {"catalogVersion": "2026.10.17", "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}

    def setUp(self):
        import shutil
        shutil.rmtree(sources.cache_dir(), ignore_errors=True)
        self.addCleanup(setattr, sources, "mode", "online")

    def test_second_call_uses_cache(self):
        patch, calls = fake_net({sources.KEV_URL: self.KEV})
        with patch:
            self.assertEqual(t.fetch_kev(), ({"CVE-2021-44228": False}, "2026.10.17"))
            t.fetch_kev()
        self.assertEqual(len(calls), 1)
        self.assertTrue((sources.cache_dir() / "kev.json").exists())

    def test_expired_entry_is_downloaded_again(self):
        patch, calls = fake_net({sources.KEV_URL: self.KEV})
        with patch:
            t.fetch_kev()
            with mock.patch("time.time", return_value=__import__("time").time() + sources.KEV_TTL + 1):
                t.fetch_kev()
        self.assertEqual(len(calls), 2)

    def test_no_cache_neither_reads_nor_writes(self):
        sources.mode = "no-cache"
        patch, calls = fake_net({sources.KEV_URL: self.KEV})
        with patch:
            t.fetch_kev()
            t.fetch_kev()
        self.assertEqual(len(calls), 2)
        self.assertFalse((sources.cache_dir() / "kev.json").exists())

    def test_offline_uses_stale_cache_and_never_the_network(self):
        patch, _ = fake_net({sources.KEV_URL: self.KEV})
        with patch:
            t.fetch_kev()
        sources.mode = "offline"
        with mock.patch("time.time", return_value=__import__("time").time() + 3 * sources.DAY):
            self.assertIn("CVE-2021-44228", t.fetch_kev()[0])
        self.assertGreater(sources.ages["kev"], 2 * sources.DAY)
        with self.assertRaises(LookupError):
            t.get_json(sources.EPSS_URL + "CVE-2021-44228")

    def test_offline_without_cache_fails(self):
        sources.mode = "offline"
        with self.assertRaises(LookupError):
            t.fetch_kev()

    def test_damaged_cache_file_is_ignored(self):
        path = sources.cache_dir() / "kev.json"
        path.parent.mkdir(parents=True)
        path.write_text("{not json")
        patch, calls = fake_net({sources.KEV_URL: self.KEV})
        with patch:
            self.assertIn("CVE-2021-44228", t.fetch_kev()[0])
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
