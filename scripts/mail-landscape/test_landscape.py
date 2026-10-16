import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import landscape


UTC = timezone.utc
NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


class ParserTests(unittest.TestCase):
    def test_parses_arxiv_atom_and_collapses_title_whitespace(self):
        payload = b"""<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry>
            <title>  Email
              security research </title>
            <id>https://arxiv.org/abs/2604.00001</id>
            <published>2026-04-20T10:30:00Z</published>
            <summary>Detects a message.</summary>
          </entry>
        </feed>"""
        items = landscape.parse_arxiv(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].source, "arxiv")
        self.assertEqual(items[0].title, "Email security research")
        self.assertEqual(items[0].url, "https://arxiv.org/abs/2604.00001")
        self.assertEqual(items[0].published, datetime(2026, 4, 20, 10, 30, tzinfo=UTC))
        self.assertEqual(items[0].summary, "Detects a message.")

    def test_parses_zenn_rss_with_rfc2822_date(self):
        payload = b"""<rss version="2.0"><channel><item>
          <title>Zenn article</title>
          <link>https://zenn.dev/example/articles/mail</link>
          <pubDate>Mon, 20 Apr 2026 10:30:00 +0000</pubDate>
          <description>Article summary</description>
        </item></channel></rss>"""
        items = landscape.parse_zenn(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].source, "zenn")
        self.assertEqual(items[0].published, datetime(2026, 4, 20, 10, 30, tzinfo=UTC))
        self.assertEqual(items[0].summary, "Article summary")

    def test_parses_qiita_json_without_storing_article_body(self):
        payload = json.dumps(
            [
                {
                    "title": "Qiita mail article",
                    "url": "https://qiita.com/example/items/1",
                    "created_at": "2026-04-20T19:30:00+09:00",
                    "body": "The article body must not be stored.",
                }
            ]
        ).encode("utf-8")
        items = landscape.parse_qiita(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].published, datetime(2026, 4, 20, 10, 30, tzinfo=UTC))
        self.assertEqual(items[0].summary, "")

    def test_parses_github_json(self):
        payload = json.dumps(
            {
                "items": [
                    {
                        "full_name": "example/mail-security",
                        "html_url": "https://github.com/example/mail-security",
                        "pushed_at": "2026-04-20T10:30:00Z",
                        "description": "Repository description",
                    }
                ]
            }
        ).encode("utf-8")
        items = landscape.parse_github(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].title, "example/mail-security")
        self.assertEqual(items[0].summary, "Repository description")

    def test_ietf_sorts_by_time_descending_and_truncates(self):
        payload = json.dumps(
            {
                "objects": [
                    {
                        "name": "draft-old",
                        "title": "Old draft",
                        "time": "2026-04-10T10:00:00Z",
                        "abstract": "Old",
                    },
                    {
                        "name": "draft-new",
                        "title": "New draft",
                        "time": "2026-04-25T10:00:00Z",
                        "abstract": "New",
                    },
                    {
                        "name": "draft-middle",
                        "title": "Middle draft",
                        "time": "2026-04-18T10:00:00Z",
                        "abstract": "Middle",
                    },
                ]
            }
        ).encode("utf-8")
        items = landscape.parse_ietf(payload, limit=2)
        self.assertEqual([item.title for item in items], ["New draft", "Middle draft"])
        self.assertEqual(
            [item.url for item in items],
            [
                "https://datatracker.ietf.org/doc/draft-new/",
                "https://datatracker.ietf.org/doc/draft-middle/",
            ],
        )

    def test_parses_hn_and_falls_back_for_null_url(self):
        payload = json.dumps(
            {
                "hits": [
                    {
                        "objectID": "456",
                        "title": "Hacker News mail story",
                        "url": None,
                        "created_at": "2026-04-20T10:30:00Z",
                    }
                ]
            }
        ).encode("utf-8")
        items = landscape.parse_hn(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].url, "https://news.ycombinator.com/item?id=456")

    def test_parses_iso_z_and_rfc2822_dates_as_utc(self):
        self.assertEqual(
            landscape.parse_iso_datetime("2026-04-20T10:30:00Z"),
            datetime(2026, 4, 20, 10, 30, tzinfo=UTC),
        )
        self.assertEqual(
            landscape.parse_rfc2822_datetime("Mon, 20 Apr 2026 12:30:00 +0200"),
            datetime(2026, 4, 20, 10, 30, tzinfo=UTC),
        )
        self.assertIsNone(landscape.parse_iso_datetime("not a date"))

    def test_rejects_xml_dtd_and_entity_declarations(self):
        payload = b"""<!DOCTYPE feed [<!ENTITY x "unsafe">]>
        <feed xmlns="http://www.w3.org/2005/Atom"><entry /></feed>"""
        with self.assertRaisesRegex(ValueError, "DTD/entity"):
            landscape.parse_arxiv(payload)


class FetchSafetyTests(unittest.TestCase):
    def test_fetch_rejects_http_and_unallowlisted_hosts_before_network(self):
        with patch.object(landscape.urllib.request, "build_opener") as build_opener:
            with self.assertRaises(ValueError):
                landscape.fetch("http://api.github.com/search")
            with self.assertRaises(ValueError):
                landscape.fetch("https://example.com/search")
            build_opener.assert_not_called()

    def test_fetch_sets_user_agent_timeout_and_rejects_oversized_response(self):
        class Response:
            def __init__(self):
                self.requested_size = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self, size):
                self.requested_size = size
                return b"x" * size

        class Opener:
            def __init__(self, response):
                self.response = response
                self.request = None
                self.timeout = None

            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return self.response

        response = Response()
        opener = Opener(response)
        with patch.object(
            landscape.urllib.request, "build_opener", return_value=opener
        ):
            with self.assertRaisesRegex(ValueError, "exceeds 2 MiB"):
                landscape.fetch("https://api.github.com/search")
        self.assertEqual(opener.request.get_header("User-agent"), landscape.USER_AGENT)
        self.assertEqual(opener.timeout, 20)
        self.assertEqual(response.requested_size, landscape.MAX_RESPONSE_BYTES + 1)


class MatchingAndCoverageTests(unittest.TestCase):
    def test_short_ascii_keywords_use_boundaries_and_japanese_uses_substrings(self):
        topics = [
            {"id": "idn", "keywords": ["idn"]},
            {"id": "calendar", "keywords": ["カレンダー招待"]},
        ]
        midnight = landscape.Item("hn", "midnight message", "https://e/1", NOW, "")
        homograph = landscape.Item(
            "hn", "IDN homograph attack", "https://e/2", NOW, ""
        )
        japanese = landscape.Item(
            "hn", "不審なカレンダー招待を検出", "https://e/3", NOW, ""
        )
        self.assertNotIn("idn", landscape.match_topics(midnight, topics))
        self.assertIn("idn", landscape.match_topics(homograph, topics))
        self.assertIn("calendar", landscape.match_topics(japanese, topics))

    def test_filters_by_window_and_deduplicates_urls(self):
        old = landscape.Item(
            "arxiv", "Old", "https://e/shared", NOW - timedelta(days=100), ""
        )
        recent_duplicate = landscape.Item(
            "github", "Recent", "https://e/shared", NOW - timedelta(days=1), ""
        )
        recent = landscape.Item(
            "hn", "Recent item", "https://e/recent", NOW - timedelta(days=2), ""
        )
        items = landscape.filter_items(
            [old, recent_duplicate, recent], NOW, window_days=90
        )
        self.assertEqual(len(items), 2)
        self.assertEqual(
            {item.url for item in items}, {"https://e/shared", "https://e/recent"}
        )
        self.assertEqual(
            next(item for item in items if item.url == "https://e/shared").source,
            "github",
        )

    def test_check_reports_fake_drift_and_accepts_existing_symbol(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src" / "lib.rs"
            source.parent.mkdir()
            source.write_text("fn present_symbol() {}\n", encoding="utf-8")
            catalog = {
                "topics": [
                    {
                        "id": "sample",
                        "coverage": [
                            {"path": "src/lib.rs", "symbol": "missing_symbol"}
                        ],
                    }
                ]
            }
            output = io.StringIO()
            self.assertEqual(landscape.run_check(catalog, root, output), 1)
            self.assertIn("coverage drift: sample:", output.getvalue())

            catalog["topics"][0]["coverage"][0]["symbol"] = "present_symbol"
            output = io.StringIO()
            self.assertEqual(landscape.run_check(catalog, root, output), 0)
            self.assertEqual(output.getvalue(), "coverage ok: 1 topics, 1 symbols\n")

    def test_real_catalog_coverage_is_current(self):
        catalog = landscape.load_catalog()
        output = io.StringIO()
        self.assertEqual(landscape.run_check(catalog, landscape.ROOT, output), 0)
        self.assertIn("coverage ok:", output.getvalue())


class CollectionReportTests(unittest.TestCase):
    def test_emerging_terms_use_document_frequency_and_exclude_known_generic_terms(self):
        catalog = {
            "sources": {"arxiv": ["phishing"]},
            "topics": [
                {
                    "id": "phishing",
                    "keywords": ["phishing", "dmarc"],
                    "coverage": [],
                }
            ],
        }
        items = [
            landscape.Item(
                "arxiv",
                "MTA-STS domain phishing analysis example header only protocol report results support",
                "https://example.com/{}".format(index),
                NOW,
                "DMARC security",
            )
            for index in range(3)
        ]
        terms = landscape.emerging_terms(catalog, items)
        self.assertIn(("mta-sts", 3), terms)
        for excluded in (
            "domain",
            "phishing",
            "analysis",
            "security",
            "dmarc",
            "example",
            "header",
            "only",
            "protocol",
            "report",
            "results",
            "support",
        ):
            self.assertNotIn(excluded, {term for term, _ in terms})

    def test_collect_and_render_are_deterministic_and_rank_largest_gap_first(self):
        atom = b"""<?xml version="1.0"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>DMARCbis DKIM2 secure rare topic</title>
            <id>https://arxiv.org/abs/2604.00001</id>
            <published>2026-04-28T10:00:00Z</published><summary>New work</summary>
          </entry>
          <entry><title>DMARCbis DKIM2 topic second</title>
            <id>https://arxiv.org/abs/2604.00002</id>
            <published>2026-04-27T10:00:00Z</published><summary>New work</summary>
          </entry>
          <entry><title>DMARCbis DKIM2 topic third</title>
            <id>https://arxiv.org/abs/2604.00003</id>
            <published>2026-04-26T10:00:00Z</published><summary>New work</summary>
          </entry>
        </feed>"""
        catalog = {
            "sources": {"arxiv": ["mail security", "dmarc"], "hn": ["failure"]},
            "topics": [
                {
                    "id": "dmarcbis-dkim2",
                    "title": "DMARCbis / DKIM2",
                    "keywords": ["dmarcbis", "dkim2"],
                    "coverage": [],
                    "note": "Coverage gap.",
                },
                {
                    "id": "other-gap",
                    "title": "Other gap",
                    "keywords": ["rare"],
                    "coverage": [],
                    "note": "Lower volume.",
                },
            ],
        }

        def fixture_fetcher(url):
            host = urlsplit(url).hostname
            if host == "hn.algolia.com":
                raise RuntimeError("fixture source unavailable")
            if host == "export.arxiv.org":
                return atom
            raise AssertionError("unexpected host: {}".format(host))

        first_items, first_failures = landscape.collect_items(
            catalog,
            NOW,
            per_query=20,
            fetcher=fixture_fetcher,
            sleep=lambda _: None,
        )
        second_items, second_failures = landscape.collect_items(
            catalog,
            NOW,
            per_query=20,
            fetcher=fixture_fetcher,
            sleep=lambda _: None,
        )
        first_report = landscape.render_report(
            catalog, first_items, [], first_failures, NOW, 90
        )
        second_report = landscape.render_report(
            catalog, second_items, [], second_failures, NOW, 90
        )
        self.assertEqual(first_report, second_report)
        self.assertEqual(first_failures, second_failures)
        self.assertIn("hn:failure: RuntimeError: fixture source unavailable", first_report)
        gap_section = first_report.split("## 1. ギャップ (未カバーの話題)", 1)[1]
        self.assertLess(
            gap_section.index("### dmarcbis-dkim2"),
            gap_section.index("### other-gap"),
        )
        self.assertEqual(len(first_items), 3)
        self.assertEqual(
            len(
                [
                    item
                    for item in first_items
                    if "dmarcbis-dkim2" in landscape.match_topics(
                        item, catalog["topics"]
                    )
                ]
            ),
            3,
        )


if __name__ == "__main__":
    unittest.main()
