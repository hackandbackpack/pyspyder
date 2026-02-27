import logging
import time
from collections import deque
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from pyspyder.utils import is_target_file, resolve_domain

logger = logging.getLogger("pyspyder")


MAX_PAGES = 500


def spider_domain(domain, file_types, session, max_depth=2, delay=1.0,
                  ignore_robots=False, max_pages=MAX_PAGES):
    file_urls = set()
    visited = set()

    # Resolve the actual hostname (e.g., tri-c.edu -> www.tri-c.edu)
    actual_domain = resolve_domain(domain, session)
    if actual_domain != domain.lower():
        logger.info(f"Spider: {domain} redirects to {actual_domain}")

    base_url = f"https://{actual_domain}"
    queue = deque([(base_url + "/", 0)])

    # Use both the input domain and resolved domain for link matching
    match_domains = {domain.lower(), actual_domain.lower()}

    robot_parser = None
    if not ignore_robots:
        robot_parser = _load_robots(base_url, session)

    while queue:
        if len(visited) >= max_pages:
            logger.info(f"Spider: Reached page limit ({max_pages}), stopping crawl")
            break

        current_url, depth = queue.popleft()
        normalized = current_url.split("#")[0].rstrip("/")

        if normalized in visited:
            continue
        visited.add(normalized)

        if robot_parser and not robot_parser.can_fetch("*", current_url):
            logger.debug(f"Spider: Blocked by robots.txt: {current_url}")
            continue

        logger.debug(f"Spider: Crawling {current_url} (depth {depth})")

        try:
            response = session.get(current_url, timeout=15)
            response.raise_for_status()
        except Exception as err:
            logger.debug(f"Spider: Failed to fetch {current_url}: {err}")
            continue

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            absolute_url = urljoin(current_url, href)
            parsed = urlparse(absolute_url)
            link_host = parsed.netloc.lower()

            # Match links on either the input domain or resolved domain
            if not any(d in link_host for d in match_domains):
                continue

            clean_url = parsed._replace(fragment="").geturl()

            if is_target_file(clean_url, file_types):
                file_urls.add(clean_url)
            elif depth < max_depth and clean_url.split("#")[0].rstrip("/") not in visited:
                queue.append((clean_url, depth + 1))

        time.sleep(delay)

    logger.info(f"Spider: Found {len(file_urls)} file(s) across {len(visited)} pages crawled")
    return file_urls


def _load_robots(base_url, session):
    robots_url = f"{base_url}/robots.txt"
    parser = RobotFileParser()
    try:
        response = session.get(robots_url, timeout=10)
        if response.status_code == 200:
            parser.parse(response.text.splitlines())
            logger.debug(f"Spider: Loaded robots.txt from {robots_url}")
            return parser
    except Exception:
        logger.debug("Spider: Could not fetch robots.txt, proceeding without restrictions")
    return None
