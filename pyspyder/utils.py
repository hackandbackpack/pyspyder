import logging
import re
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter, Retry


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

DEFAULT_FILE_TYPES = ["pdf", "docx", "xlsx", "doc", "xls", "pptx", "ppt"]


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )
    return logging.getLogger("pyspyder")


def get_session(user_agent=None):
    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def resolve_domain(domain, session):
    """Follow redirects to find the actual hostname for a domain."""
    try:
        resp = session.head(f"https://{domain}/", timeout=10, allow_redirects=True)
        actual_host = urlparse(resp.url).netloc.lower()
        if actual_host and actual_host != domain.lower():
            return actual_host
    except Exception:
        pass
    try:
        resp = session.head(f"http://{domain}/", timeout=10, allow_redirects=True)
        actual_host = urlparse(resp.url).netloc.lower()
        if actual_host and actual_host != domain.lower():
            return actual_host
    except Exception:
        pass
    return domain


def normalize_url(url):
    parsed = urlparse(url)
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment="",
    )
    path = normalized.path.rstrip("/")
    normalized = normalized._replace(path=path)
    return normalized.geturl()


def is_target_file(url, file_types):
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    return any(path_lower.endswith(f".{ft.lower()}") for ft in file_types)


def generate_output_dir(domain):
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    safe_domain = re.sub(r"[^\w.-]", "_", domain)
    return f"{safe_domain}-{timestamp}"
