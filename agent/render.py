"""Output rendering. client_render() SIMULATES a chat UI that auto-loads markdown/HTML images: that is the
exfiltration channel. sanitize_markdown() is the fix.  INTENTIONALLY VULNERABLE unless sanitised (S3)."""
import re
import urllib.request
from urllib.parse import urlsplit

from .config import Config
from .dlp import redact

IMG_INLINE = re.compile(r'!\[[^\]]*\]\(\s*<?([^\s)>]+)>?(?:\s+"[^"]*")?\s*\)')
IMG_REF = re.compile(r"!\[[^\]]*\]\[([^\]]*)\]")
REF_DEF = re.compile(r"^[ ]{0,3}\[([^\]]+)\]:\s*<?(\S+?)>?(?:\s+.*)?$", re.M)
HTML_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?([^\"' >]+)[^>]*>", re.I)
LINK_INLINE = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?([^\s)>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HTML_BLOCK = re.compile(r"<\s*(script|style|iframe|object)\b[^>]*>.*?<\s*/\s*\1\s*>", re.I | re.S)
DANGEROUS_HTML = re.compile(r"<\s*/?\s*(?:script|iframe|object|embed|img|link|style)\b[^>]*>", re.I)


def image_urls(text: str) -> list[str]:
    defs = {k.lower(): v for k, v in REF_DEF.findall(text)}
    urls = IMG_INLINE.findall(text) + HTML_IMG.findall(text)
    urls += [defs[r.lower()] for r in IMG_REF.findall(text) if r.lower() in defs]
    return urls


def client_render(text: str) -> list[str]:
    """What the user's chat client does on display: GET every image URL. Returns the URLs it fetched."""
    fetched = []
    for url in image_urls(text):
        if urlsplit(url).scheme in ("http", "https"):
            fetched.append(url)
            try:
                urllib.request.urlopen(url, timeout=3).read()  # noqa: S310
            except OSError:
                pass
    return fetched


def sanitize_markdown(text: str, allowed_netlocs=()) -> str:
    """Remove images and non-allow-listed links, drop raw dangerous HTML, redact secret-looking strings."""
    allowed = set(allowed_netlocs)

    def ok(url: str) -> bool:
        return urlsplit(url).netloc in allowed

    text = HTML_BLOCK.sub("", text)
    text = HTML_IMG.sub("[image removed]", text)
    text = DANGEROUS_HTML.sub("", text)
    text = IMG_INLINE.sub("[image removed]", text)
    text = IMG_REF.sub("[image removed]", text)
    text = REF_DEF.sub(lambda m: m.group(0) if ok(m.group(2)) else "[reference removed]", text)
    text = LINK_INLINE.sub(lambda m: m.group(0) if ok(m.group(2)) else f"{m.group(1)} (link removed)", text)
    return redact(text)


def render_output(text: str, cfg: Config) -> tuple[str, list[str]]:
    """(text shown to the user, URLs the client auto-fetched)."""
    if cfg.hardening.get("sanitize_output"):
        text = sanitize_markdown(text, cfg.hardening.get("link_allowlist", ()))
    return text, client_render(text)
