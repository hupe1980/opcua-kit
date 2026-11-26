"""Check links, fragments and search metadata in a production Zola build."""

import sys
import tomllib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from xml.etree import ElementTree

SITE = Path(__file__).resolve().parent
PUBLIC = SITE / "public"
BASE = tomllib.loads((SITE / "config.toml").read_text())["base_url"].rstrip("/") + "/"


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.ids = set()
        self.links = []
        self.meta = {}
        self.canonical = None
        self.feed(path.read_text())
        self.close()

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if "id" in fields:
            self.ids.add(fields["id"])
        if tag == "meta":
            self.meta[fields.get("name") or fields.get("property")] = fields.get(
                "content"
            )
        if tag == "link" and fields.get("rel") == "canonical":
            self.canonical = fields["href"]
        for key in ("href", "src"):
            if key in fields:
                self.links.append(fields[key])


def check():
    documents = {path: Document(path) for path in PUBLIC.rglob("*.html")}
    indexed = {
        entry.text
        for entry in ElementTree.parse(PUBLIC / "sitemap.xml").iterfind(
            ".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"
        )
    }
    found = set()
    errors = []
    for path, doc in documents.items():
        relative = path.relative_to(PUBLIC).as_posix()
        url = BASE + relative.removesuffix("index.html")
        if relative == "404.html":
            if doc.meta.get("robots") != "noindex":
                errors.append("404.html needs noindex")
        else:
            found.add(url)
            if doc.canonical != url or doc.meta.get("og:url") != url:
                errors.append(f"{relative} has inconsistent canonical URLs")
            for key in ("description", "og:title", "og:description", "og:image"):
                if not doc.meta.get(key):
                    errors.append(f"{relative} is missing {key}")
        for link in [*doc.links, doc.meta.get("og:image") or ""]:
            target = urlsplit(urljoin(url, link))
            if target.netloc != urlsplit(BASE).netloc:
                continue
            prefix = urlsplit(BASE).path
            if not target.path.startswith(prefix):
                errors.append(f"{relative} links outside the project path: {link}")
                continue
            local = PUBLIC / unquote(target.path.removeprefix(prefix))
            if local.is_dir():
                local = local / "index.html"
            if not local.is_file():
                errors.append(f"{relative} links to missing file: {link}")
            elif (
                target.fragment
                and local in documents
                and unquote(target.fragment) not in documents[local].ids
            ):
                errors.append(f"{relative} links to missing heading: {link}")
    if indexed != found:
        errors.append(f"Sitemap mismatch: {indexed ^ found}")
    if errors:
        sys.exit("\n".join(errors))
    print(f"Verified production links and metadata for {len(documents)} pages.")


if __name__ == "__main__":
    check()
