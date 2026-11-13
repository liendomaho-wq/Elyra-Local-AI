"""Crawler acotado: endpoints, formularios, parametros y secretos visibles."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urldefrag

from ..util import endpoint_key, origin

JS_ENDPOINT_RE = re.compile(r"""["'](/[A-Za-z0-9_./?=&%:-]{2,120})["']""")


class _SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.comments: list[str] = []
        self.js_text: list[str] = []
        self.title = ""
        self._form: dict | None = None
        self._in_title = False
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script":
            if values.get("src"):
                self.scripts.append(values["src"])
            self._in_script = True
        elif tag == "form":
            self._form = {
                "action": values.get("action") or "",
                "method": (values.get("method") or "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            name = values.get("name")
            if name:
                self._form["inputs"].append(
                    {
                        "name": name,
                        "type": (values.get("type") or "text").lower(),
                        "value": values.get("value") or "",
                    }
                )
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_script:
            self.js_text.append(data)

    def handle_comment(self, data):
        text = " ".join(data.split())
        if text:
            self.comments.append(text[:300])


def _same_origin(candidate: str, base: str) -> bool:
    return origin(candidate) == origin(base)


def _params(url: str, source: str) -> list[dict]:
    parsed = urlparse(url)
    values = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        values.append(
            {
                "name": name,
                "sample": value,
                "endpoint": endpoint_key("GET", url),
                "url": url,
                "source": source,
            }
        )
    return values


def crawl(start_url: str, fetch, max_pages: int = 20, timeout: float = 6.0) -> dict:
    start_url = urldefrag(start_url)[0]
    queue: list[tuple[str, int]] = [(start_url, 0)]
    seen: set[str] = {start_url}
    pages: list[dict] = []
    endpoints: list[dict] = []
    parameters: list[dict] = []
    forms: list[dict] = []
    scripts: list[str] = []
    comments: list[dict] = []
    errors: list[str] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        result = fetch(url, timeout=timeout)
        if result.get("error") or result.get("status") is None:
            errors.append(f"{url}: {result.get('error') or 'sin respuesta'}")
            continue
        content_type = str((result.get("headers") or {}).get("content-type") or "")
        body = str(result.get("body_excerpt") or "")
        final_url = str(result.get("final_url") or url)
        pages.append(
            {
                "url": final_url,
                "depth": depth,
                "status": result.get("status"),
                "content_type": content_type,
                "title": result.get("title") or "",
                "bytes": result.get("body_bytes", 0),
            }
        )
        endpoints.append(
            {
                "url": url,
                "final_url": final_url,
                "method": "GET",
                "status": result.get("status"),
                "content_type": content_type,
                "title": result.get("title") or "",
                "has_params": bool(urlparse(url).query),
                "source": "crawl",
            }
        )
        if final_url != url:
            endpoints.append(
                {
                    "url": final_url,
                    "method": "GET",
                    "status": result.get("status"),
                    "content_type": content_type,
                    "title": result.get("title") or "",
                    "has_params": bool(urlparse(final_url).query),
                    "source": "redirect",
                }
            )
        parameters.extend(_params(url, "crawl"))
        if "html" not in content_type.lower() and "<html" not in body.lower():
            continue
        parser = _SurfaceParser()
        try:
            parser.feed(body)
        except Exception as exc:
            errors.append(f"{url}: HTML no procesable ({exc})")
            continue
        if parser.title:
            pages[-1]["title"] = " ".join(parser.title.split())[:200]
            endpoints[-1]["title"] = pages[-1]["title"]
        for form in parser.forms:
            action = urljoin(final_url, form.get("action") or final_url)
            if not _same_origin(action, final_url):
                continue
            forms.append(
                {
                    "page": final_url,
                    "action": action,
                    "method": str(form.get("method") or "GET").upper(),
                    "inputs": form.get("inputs") or [],
                }
            )
            for field in form.get("inputs") or []:
                parameters.append(
                    {
                        "name": field["name"],
                        "sample": field.get("value", ""),
                        "endpoint": endpoint_key(form.get("method") or "GET", action),
                        "url": action,
                        "source": f"form:{form.get('method') or 'GET'}",
                    }
                )
        for link in parser.links:
            candidate = urldefrag(urljoin(final_url, link))[0]
            if not candidate.startswith(("http://", "https://")):
                continue
            if not _same_origin(candidate, start_url):
                continue
            if candidate not in seen:
                seen.add(candidate)
                queue.append((candidate, depth + 1))
        for script in parser.scripts:
            absolute = urljoin(final_url, script)
            if absolute not in scripts:
                scripts.append(absolute)
        for comment in parser.comments:
            comments.append({"page": final_url, "text": comment})
        for block in parser.js_text:
            for match in JS_ENDPOINT_RE.finditer(block):
                endpoint = urljoin(final_url, match.group(1))
                if _same_origin(endpoint, start_url):
                    endpoints.append(
                        {
                            "url": endpoint,
                            "method": "GET",
                            "status": None,
                            "content_type": "",
                            "title": "",
                            "has_params": bool(urlparse(endpoint).query),
                            "source": "javascript",
                        }
                    )

    unique_params: dict[tuple[str, str], dict] = {}
    for item in parameters:
        unique_params.setdefault((item["endpoint"], item["name"]), item)
    unique_endpoints: dict[tuple[str, str], dict] = {}
    for item in endpoints:
        unique_endpoints.setdefault((item["method"], item["url"]), item)

    return {
        "start_url": start_url,
        "pages": pages,
        "endpoints": list(unique_endpoints.values()),
        "parameters": list(unique_params.values()),
        "forms": forms,
        "scripts": scripts,
        "comments": comments,
        "errors": errors,
    }
