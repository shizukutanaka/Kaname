#!/usr/bin/env python3
"""開発者向けに公開メールセキュリティ情報を集め、検出カバレッジと照合する。

RSS/ニュース集約をアプリへ持ち込まない (A-4) 開発者側の道具であり、
アプリ本体はオフラインのまま、P-LLM もネットワークへ接続しない (I4)。
`check` でカタログの実装シンボルを確認し、`collect` でレポートを生成する。
collect → §1/§2/§4 をレビュー → 次の PR の候補を一つ選び、ギャップを閉じたら
`topics.json` の coverage を更新する (check がカタログの整合性を保つ)。
"""

import argparse
import email.utils
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "scripts" / "mail-landscape" / "topics.json"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
USER_AGENT = "kaname-mail-landscape/1 (+https://github.com/shizukutanaka/Kaname)"
ALLOWED_HOSTS = frozenset(
    {
        "export.arxiv.org",
        "datatracker.ietf.org",
        "zenn.dev",
        "qiita.com",
        "api.github.com",
        "hn.algolia.com",
    }
)
SOURCE_ORDER = ("arxiv", "ietf", "zenn", "qiita", "github", "hn")
ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}
TERM_RE = re.compile(r"[a-z][a-z0-9-]{3,}|[ァ-ヶー]{3,}")
SHORT_ASCII_KEYWORD_RE = re.compile(r"[a-z0-9]+\Z")
XML_DECLARATION_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)

STOPWORDS = frozenset(
    {
        "about",
        "after",
        "also",
        "allows",
        "analysis",
        "based",
        "been",
        "before",
        "being",
        "between",
        "both",
        "can",
        "could",
        "data",
        "defines",
        "document",
        "domain",
        "each",
        "email",
        "emails",
        "example",
        "from",
        "have",
        "header",
        "here",
        "http",
        "https",
        "into",
        "mail",
        "message",
        "messages",
        "more",
        "most",
        "other",
        "over",
        "only",
        "protocol",
        "public",
        "report",
        "results",
        "security",
        "show",
        "some",
        "such",
        "support",
        "than",
        "that",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "through",
        "under",
        "using",
        "very",
        "was",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "will",
        "with",
        "www",
        "your",
        "github",
        "identified",
        "system",
        "systems",
        "メール",
        "セキュリティ",
    }
)


@dataclass(frozen=True)
class Item:
    source: str
    title: str
    url: str
    published: datetime
    summary: str


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_iso_datetime(value: str) -> Optional[datetime]:
    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        return _as_utc(datetime.fromisoformat(normalized))
    except (AttributeError, OverflowError, TypeError, ValueError):
        return None


def parse_rfc2822_datetime(value: str) -> Optional[datetime]:
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        return _as_utc(parsed)
    except (OverflowError, TypeError, ValueError):
        return None


def _normalized_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return " ".join(value.split())


def _make_item(
    source: str,
    title: Optional[str],
    url: Optional[str],
    date_value: Optional[str],
    summary: Optional[str] = "",
    date_parser: Callable[[str], Optional[datetime]] = parse_iso_datetime,
) -> Optional[Item]:
    clean_title = _normalized_text(title)
    clean_url = (url or "").strip()
    if not clean_title or not clean_url or not date_value:
        return None
    published = date_parser(date_value)
    if published is None:
        return None
    return Item(
        source=source,
        title=clean_title,
        url=clean_url,
        published=published,
        summary=_normalized_text(summary),
    )


def _parse_xml(payload: bytes) -> ET.Element:
    if XML_DECLARATION_RE.search(payload):
        raise ValueError("XML DTD/entity declarations are not allowed")
    return ET.fromstring(payload)


def _parse_json(payload: bytes):
    return json.loads(payload.decode("utf-8"))


def parse_arxiv(payload: bytes, limit: int = 20) -> List[Item]:
    root = _parse_xml(payload)
    items = []
    for entry in root.findall("atom:entry", ATOM_NS):
        item = _make_item(
            "arxiv",
            entry.findtext("atom:title", default="", namespaces=ATOM_NS),
            entry.findtext("atom:id", default="", namespaces=ATOM_NS),
            entry.findtext("atom:published", default="", namespaces=ATOM_NS),
            entry.findtext("atom:summary", default="", namespaces=ATOM_NS),
        )
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda item: (-item.published.timestamp(), item.url))[:limit]


def parse_ietf(payload: bytes, limit: int = 20) -> List[Item]:
    data = _parse_json(payload)
    items = []
    for obj in data.get("objects", []):
        name = str(obj.get("name") or "").strip()
        item = _make_item(
            "ietf",
            obj.get("title") or name,
            "https://datatracker.ietf.org/doc/{}/".format(name) if name else None,
            obj.get("time"),
            obj.get("abstract") or "",
        )
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda item: (-item.published.timestamp(), item.url))[:limit]


def parse_zenn(payload: bytes, limit: int = 20) -> List[Item]:
    root = _parse_xml(payload)
    items = []
    for entry in root.findall(".//item"):
        item = _make_item(
            "zenn",
            entry.findtext("title"),
            entry.findtext("link"),
            entry.findtext("pubDate"),
            entry.findtext("description") or "",
            parse_rfc2822_datetime,
        )
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda item: (-item.published.timestamp(), item.url))[:limit]


def parse_qiita(payload: bytes, limit: int = 20) -> List[Item]:
    data = _parse_json(payload)
    items = []
    for obj in data if isinstance(data, list) else []:
        item = _make_item(
            "qiita",
            obj.get("title"),
            obj.get("url"),
            obj.get("created_at"),
            "",
        )
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda item: (-item.published.timestamp(), item.url))[:limit]


def parse_github(payload: bytes, limit: int = 20) -> List[Item]:
    data = _parse_json(payload)
    items = []
    for obj in data.get("items", []):
        item = _make_item(
            "github",
            obj.get("full_name") or obj.get("name"),
            obj.get("html_url"),
            obj.get("pushed_at"),
            obj.get("description") or "",
        )
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda item: (-item.published.timestamp(), item.url))[:limit]


def parse_hn(payload: bytes, limit: int = 20) -> List[Item]:
    data = _parse_json(payload)
    items = []
    for obj in data.get("hits", []):
        object_id = obj.get("objectID")
        url = obj.get("url") or (
            "https://news.ycombinator.com/item?id={}".format(object_id)
            if object_id is not None
            else None
        )
        item = _make_item(
            "hn",
            obj.get("title"),
            url,
            obj.get("created_at"),
            "",
        )
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda item: (-item.published.timestamp(), item.url))[:limit]


PARSERS = {
    "arxiv": parse_arxiv,
    "ietf": parse_ietf,
    "zenn": parse_zenn,
    "qiita": parse_qiita,
    "github": parse_github,
    "hn": parse_hn,
}


def build_url(source: str, query: str, per_query: int) -> str:
    encoded = urllib.parse.quote(query, safe="")
    if source == "arxiv":
        search = urllib.parse.quote('all:"{}"'.format(query), safe="")
        return (
            "https://export.arxiv.org/api/query?search_query={}"
            "&sortBy=submittedDate&sortOrder=descending&max_results={}"
        ).format(search, per_query)
    if source == "ietf":
        return (
            "https://datatracker.ietf.org/api/v1/doc/document/"
            "?name__contains={}&type=draft&limit=100&format=json"
        ).format(encoded)
    if source == "zenn":
        return "https://zenn.dev/topics/{}/feed".format(encoded)
    if source == "qiita":
        tag_query = urllib.parse.quote("tag:{}".format(query), safe="")
        return "https://qiita.com/api/v2/items?query={}&per_page={}".format(
            tag_query, per_query
        )
    if source == "github":
        return (
            "https://api.github.com/search/repositories?q={}&sort=updated&per_page={}"
        ).format(encoded, per_query)
    if source == "hn":
        return (
            "https://hn.algolia.com/api/v1/search_by_date?query={}&tags=story"
            "&hitsPerPage={}&typoTolerance=false&restrictSearchableAttributes=title"
        ).format(encoded, per_query)
    raise ValueError("unsupported source: {}".format(source))


def _validate_url(url: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() != "https" or host not in ALLOWED_HOSTS:
        raise ValueError("URL must use https and an allowlisted host: {}".format(url))
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    if parsed.port not in (None, 443):
        raise ValueError("nonstandard HTTPS ports are not allowed")
    return parsed


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> bytes:
    _validate_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(_AllowlistedRedirectHandler)
    with opener.open(request, timeout=20) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("response exceeds 2 MiB")
    return payload


def filter_items(
    items: Iterable[Item], now: datetime, window_days: int
) -> List[Item]:
    cutoff = _as_utc(now) - timedelta(days=window_days)
    by_url: Dict[str, Item] = {}
    for item in items:
        if _as_utc(item.published) < cutoff:
            continue
        current = by_url.get(item.url)
        if current is None or _as_utc(item.published) > _as_utc(current.published):
            by_url[item.url] = item
    return sorted(
        by_url.values(),
        key=lambda item: (
            -_as_utc(item.published).timestamp(),
            item.source,
            item.url,
        ),
    )


def collect_items(
    catalog: dict,
    now: datetime,
    per_query: int,
    fetcher: Callable[[str], bytes] = fetch,
    sleep: Callable[[float], None] = time.sleep,
    window_days: int = 90,
) -> Tuple[List[Item], List[str]]:
    collected: List[Item] = []
    failures: List[str] = []
    host_last_request: Dict[str, float] = {}

    for source, queries in catalog.get("sources", {}).items():
        parser = PARSERS.get(source)
        for query in queries:
            host = ""
            request_started = False
            try:
                url = build_url(source, query, per_query)
                host = (urllib.parse.urlsplit(url).hostname or "").lower()
                previous = host_last_request.get(host)
                if previous is not None:
                    delay = max(0.0, 1.0 - (time.monotonic() - previous))
                    if delay:
                        sleep(delay)
                request_started = True
                payload = fetcher(url)
                if parser is None:
                    raise ValueError("unsupported source: {}".format(source))
                collected.extend(parser(payload, per_query))
            except Exception as exc:
                message = " ".join(str(exc).split())
                failures.append(
                    "{}:{}: {}: {}".format(source, query, type(exc).__name__, message)
                )
            finally:
                if request_started and host:
                    host_last_request[host] = time.monotonic()

    return filter_items(collected, now, window_days), failures


def match_topics(item: Item, topics: Sequence[dict]) -> List[str]:
    text = (item.title + " " + item.summary).lower()
    matched = []
    for topic in topics:
        for keyword in topic.get("keywords", []):
            normalized = keyword.lower()
            if (
                normalized.isascii()
                and len(normalized) <= 4
                and SHORT_ASCII_KEYWORD_RE.fullmatch(normalized)
            ):
                found = re.search(
                    r"(?<![a-z0-9]){}(?![a-z0-9])".format(re.escape(normalized)),
                    text,
                )
            else:
                found = normalized in text
            if found:
                matched.append(topic["id"])
                break
    return matched


def emerging_terms(
    catalog: dict, items: Sequence[Item], minimum_df: int = 3, limit: int = 15
) -> List[Tuple[str, int]]:
    known_texts = [
        str(keyword).lower()
        for topic in catalog.get("topics", [])
        for keyword in topic.get("keywords", [])
    ]
    known_texts.extend(
        str(query).lower()
        for queries in catalog.get("sources", {}).values()
        for query in queries
    )
    document_frequency: Counter = Counter()
    for item in items:
        text = (item.title + " " + item.summary).lower()
        terms = set(TERM_RE.findall(text))
        for term in terms:
            if term in STOPWORDS or any(term in known for known in known_texts):
                continue
            document_frequency[term] += 1
    ranked = sorted(
        (
            (term, count)
            for term, count in document_frequency.items()
            if count >= minimum_df
        ),
        key=lambda entry: (-entry[1], entry[0]),
    )
    return ranked[:limit]


def coverage_drift(catalog: dict, root: Path) -> Tuple[List[str], int]:
    drift = []
    symbol_count = 0
    for topic in catalog.get("topics", []):
        topic_id = topic.get("id", "(unknown)")
        for coverage in topic.get("coverage", []):
            symbol_count += 1
            relative_path = coverage.get("path", "")
            symbol = coverage.get("symbol", "")
            path = root / relative_path
            if not path.is_file():
                drift.append("{}: {}: file missing".format(topic_id, relative_path))
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                drift.append(
                    "{}: {}: {}: {}".format(
                        topic_id, relative_path, type(exc).__name__, exc
                    )
                )
                continue
            if not symbol or re.search(r"\b{}\b".format(re.escape(symbol)), text) is None:
                drift.append(
                    "{}: {}: symbol missing: {}".format(
                        topic_id, relative_path, symbol or "(empty)"
                    )
                )
    return drift, symbol_count


def run_check(catalog: dict, root: Path, stream=sys.stdout) -> int:
    drift, symbol_count = coverage_drift(catalog, root)
    if drift:
        for entry in drift:
            print("coverage drift: {}".format(entry), file=stream)
        return 1
    print(
        "coverage ok: {} topics, {} symbols".format(
            len(catalog.get("topics", [])), symbol_count
        ),
        file=stream,
    )
    return 0


def _ranked_topics(catalog: dict, items: Sequence[Item]):
    topics = catalog.get("topics", [])
    matches = {topic["id"]: [] for topic in topics}
    for item in items:
        for topic_id in match_topics(item, topics):
            matches.setdefault(topic_id, []).append(item)
    ranked = sorted(
        topics,
        key=lambda topic: (-len(matches.get(topic["id"], [])), topic["id"]),
    )
    return ranked, matches


def _recent_links(items: Sequence[Item], limit: int = 3) -> List[Item]:
    return sorted(
        items,
        key=lambda item: (
            -_as_utc(item.published).timestamp(),
            item.source,
            item.url,
        ),
    )[:limit]


def _link(item: Item) -> str:
    title = item.title.replace("\\", "\\\\").replace("[", r"\[").replace("]", r"\]")
    url = item.url.replace("(", "%28").replace(")", "%29").replace(" ", "%20")
    return "[{}]({}) ({}, {})".format(
        title, url, item.source, _as_utc(item.published).strftime("%Y-%m-%d")
    )


def _utc_iso(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def render_report(
    catalog: dict,
    items: Sequence[Item],
    drift: Sequence[str],
    failures: Sequence[str],
    now: datetime,
    window_days: int,
) -> str:
    ranked, matches = _ranked_topics(catalog, items)
    counts = Counter(item.source for item in items)
    sources = list(catalog.get("sources", {}).keys())
    sources.extend(sorted(set(counts) - set(sources)))
    lines = [
        "# メール事情ランドスケープ — 改善候補レポート",
        "",
        "`scripts/mail-landscape/landscape.py collect` が生成。手編集しないこと。",
        "",
        "生成日時 (UTC): {}".format(_utc_iso(now)),
        "対象期間: 過去 {} 日".format(window_days),
        "",
        "収集件数:",
    ]
    for source in sources:
        lines.append("- {}: {}".format(source, counts.get(source, 0)))
    lines.extend(["", "収集失敗:"])
    if failures:
        lines.extend("- {}".format(failure) for failure in failures)
    else:
        lines.append("- なし")

    lines.extend(["", "## 1. ギャップ (未カバーの話題)", ""])
    gaps = [topic for topic in ranked if not topic.get("coverage")]
    if gaps:
        for topic in gaps:
            topic_items = _recent_links(matches.get(topic["id"], []))
            lines.extend(
                [
                    "### {} — {}".format(topic["id"], topic.get("title", "")),
                    "- 件数: {}".format(len(matches.get(topic["id"], []))),
                    "- note: {}".format(topic.get("note") or "記載なし"),
                ]
            )
            if topic_items:
                lines.extend("- {}".format(_link(item)) for item in topic_items)
            else:
                lines.append("- 該当記事なし")
            lines.append("")
    else:
        lines.append("なし")
        lines.append("")

    lines.extend(["## 2. カバレッジのずれ", ""])
    if drift:
        lines.extend("- {}".format(entry) for entry in drift)
    else:
        lines.append("なし")

    lines.extend(
        [
            "",
            "## 3. 話題量ランキング",
            "",
            "| 話題 | 件数 | カバー |",
            "| --- | ---: | :---: |",
        ]
    )
    for topic in ranked:
        title = str(topic.get("title", "")).replace("|", r"\|")
        lines.append(
            "| {} | {} | {} |".format(
                title,
                len(matches.get(topic["id"], [])),
                "✓" if topic.get("coverage") else "—",
            )
        )

    lines.extend(
        [
            "",
            "## 4. 新出語の候補 (どの話題にも未登録)",
            "",
        ]
    )
    terms = emerging_terms(catalog, items)
    if terms:
        lines.extend("- {} ({})".format(term, count) for term, count in terms)
    else:
        lines.append("なし")

    lines.extend(["", "## 5. 話題別の最新記事", ""])
    topics_with_items = [
        topic for topic in ranked if matches.get(topic["id"])
    ]
    if topics_with_items:
        for topic in topics_with_items:
            lines.append("### {} — {}".format(topic["id"], topic.get("title", "")))
            lines.extend(
                "- {}".format(item_link)
                for item_link in (
                    _link(item)
                    for item in _recent_links(matches[topic["id"]])
                )
            )
            lines.append("")
    else:
        lines.append("なし")
    return "\n".join(lines).rstrip() + "\n"


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    with path.open("r", encoding="utf-8") as catalog_file:
        return json.load(catalog_file)


def _output_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else ROOT / path


def _write_json_items(items: Sequence[Item], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = []
    for item in items:
        entry = asdict(item)
        entry["published"] = _utc_iso(item.published)
        serialized.append(entry)
    with path.open("w", encoding="utf-8") as output:
        json.dump(serialized, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="メールセキュリティ事情の開発者向け収集")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="coverage symbols をオフラインで確認")
    collect_parser = subparsers.add_parser("collect", help="公開ソースを収集してレポート化")
    collect_parser.add_argument("--out", default="docs/mail-landscape-report.md")
    collect_parser.add_argument("--json", dest="json_path")
    collect_parser.add_argument("--window-days", type=_positive_int, default=90)
    collect_parser.add_argument("--per-query", type=_positive_int, default=20)
    args = parser.parse_args(argv)

    catalog = load_catalog()
    if args.command == "check":
        return run_check(catalog, ROOT)

    now = datetime.now(timezone.utc)
    items, failures = collect_items(
        catalog,
        now,
        args.per_query,
        window_days=args.window_days,
    )
    drift, _ = coverage_drift(catalog, ROOT)
    report = render_report(catalog, items, drift, failures, now, args.window_days)
    report_path = _output_path(args.out)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    if args.json_path:
        _write_json_items(items, _output_path(args.json_path))
    print("report: {}".format(report_path))
    print("items: {}".format(len(items)))
    print("failures: {}".format(len(failures)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
