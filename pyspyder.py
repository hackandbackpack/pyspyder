#!/usr/bin/env python3
"""PySpyder - Spider a target domain for files, download them, and extract metadata."""

import argparse
import csv
import logging
import os
import re
import sys
import time
from collections import deque
from datetime import datetime
from urllib.parse import unquote, urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter, Retry

__version__ = "1.0.0"

logger = logging.getLogger("pyspyder")

BANNER = r"""
 ____        ____                  _
|  _ \ _   _/ ___| _ __  _   _  __| | ___ _ __
| |_) | | | \___ \| '_ \| | | |/ _` |/ _ \ '__|
|  __/| |_| |___) | |_) | |_| | (_| |  __/ |
|_|    \__, |____/| .__/ \__, |\__,_|\___|_|
       |___/      |_|    |___/
  Domain File Metadata Extractor
"""

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

DEFAULT_FILE_TYPES = ["pdf", "docx", "xlsx", "doc", "xls", "pptx", "ppt"]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
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


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------

def spider_domain(domain, file_types, session, max_depth=2, delay=1.0,
                  ignore_robots=False, max_pages=500):
    file_urls = set()
    visited = set()

    actual_domain = resolve_domain(domain, session)
    if actual_domain != domain.lower():
        logger.info(f"Spider: {domain} redirects to {actual_domain}")

    base_url = f"https://{actual_domain}"
    queue = deque([(base_url + "/", 0)])
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


# ---------------------------------------------------------------------------
# Downloader
# ---------------------------------------------------------------------------

def download_files(urls, output_dir, session, delay=0.5):
    os.makedirs(output_dir, exist_ok=True)

    downloaded = []
    seen_filenames = {}

    for url in urls:
        filename = _extract_filename(url)

        if filename in seen_filenames:
            seen_filenames[filename] += 1
            name, ext = os.path.splitext(filename)
            filename = f"{name}_{seen_filenames[filename]}{ext}"
        else:
            seen_filenames[filename] = 0

        filepath = os.path.join(output_dir, filename)

        try:
            response = session.get(url, timeout=30, stream=True)
            response.raise_for_status()

            with open(filepath, "wb") as fh:
                for chunk in response.iter_content(chunk_size=8192):
                    fh.write(chunk)

            logger.info(f"Downloaded: {filename}")
            downloaded.append((url, filepath))

        except Exception as err:
            logger.warning(f"Failed to download {url}: {err}")

        time.sleep(delay)

    return downloaded


def _extract_filename(url):
    parsed = urlparse(url)
    path = unquote(parsed.path)
    filename = os.path.basename(path)
    if not filename:
        filename = "unknown_file"
    filename = "".join(c for c in filename if c.isalnum() or c in "._- ")
    return filename or "unknown_file"


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------

def extract_metadata(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    extractors = {
        ".pdf": _extract_pdf,
        ".docx": _extract_docx,
        ".xlsx": _extract_xlsx,
        ".pptx": _extract_pptx,
        ".doc": _extract_ole,
        ".xls": _extract_ole,
        ".ppt": _extract_ole,
    }

    extractor = extractors.get(ext)
    if not extractor:
        logger.debug(f"No metadata extractor for {ext} files")
        return {}

    try:
        return extractor(filepath)
    except Exception as err:
        logger.warning(f"Failed to extract metadata from {os.path.basename(filepath)}: {err}")
        return {}


def _extract_pdf(filepath):
    from PyPDF2 import PdfReader

    reader = PdfReader(filepath)
    info = reader.metadata
    if not info:
        return {}

    metadata = {}
    field_map = {
        "/Author": "Author",
        "/Creator": "Creator",
        "/Producer": "Producer",
        "/Title": "Title",
        "/Subject": "Subject",
        "/CreationDate": "Created",
        "/ModDate": "Modified",
    }
    for pdf_key, our_key in field_map.items():
        value = info.get(pdf_key)
        if value:
            metadata[our_key] = str(value).strip()

    return metadata


def _extract_docx(filepath):
    from docx import Document

    doc = Document(filepath)
    props = doc.core_properties
    metadata = {}

    if props.author:
        metadata["Author"] = props.author
    if props.last_modified_by:
        metadata["LastModifiedBy"] = props.last_modified_by
    if props.title:
        metadata["Title"] = props.title
    if props.subject:
        metadata["Subject"] = props.subject
    if props.created:
        metadata["Created"] = str(props.created)
    if props.modified:
        metadata["Modified"] = str(props.modified)

    return metadata


def _extract_xlsx(filepath):
    from openpyxl import load_workbook

    wb = load_workbook(filepath, read_only=True, data_only=True)
    props = wb.properties
    metadata = {}

    if props.creator:
        metadata["Author"] = props.creator
    if props.lastModifiedBy:
        metadata["LastModifiedBy"] = props.lastModifiedBy
    if props.title:
        metadata["Title"] = props.title
    if props.created:
        metadata["Created"] = str(props.created)
    if props.modified:
        metadata["Modified"] = str(props.modified)

    wb.close()
    return metadata


def _extract_pptx(filepath):
    from pptx import Presentation

    prs = Presentation(filepath)
    props = prs.core_properties
    metadata = {}

    if props.author:
        metadata["Author"] = props.author
    if props.last_modified_by:
        metadata["LastModifiedBy"] = props.last_modified_by
    if props.title:
        metadata["Title"] = props.title
    if props.subject:
        metadata["Subject"] = props.subject
    if props.created:
        metadata["Created"] = str(props.created)
    if props.modified:
        metadata["Modified"] = str(props.modified)

    return metadata


def _extract_ole(filepath):
    import olefile

    if not olefile.isOleFile(filepath):
        return {}

    ole = olefile.OleFileIO(filepath)
    metadata = {}

    try:
        meta = ole.get_metadata()

        if meta.author:
            metadata["Author"] = meta.author.decode("utf-8", errors="replace")
        if meta.last_saved_by:
            metadata["LastModifiedBy"] = meta.last_saved_by.decode("utf-8", errors="replace")
        if meta.company:
            metadata["Company"] = meta.company.decode("utf-8", errors="replace")
        if meta.title:
            metadata["Title"] = meta.title.decode("utf-8", errors="replace")
        if meta.subject:
            metadata["Subject"] = meta.subject.decode("utf-8", errors="replace")
        if meta.creating_application:
            metadata["CreatingApplication"] = meta.creating_application.decode("utf-8", errors="replace")
        if meta.create_time:
            metadata["Created"] = str(meta.create_time)
        if meta.last_saved_time:
            metadata["Modified"] = str(meta.last_saved_time)
    finally:
        ole.close()

    return metadata


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_metadata_table(results):
    if not results:
        return "No metadata found."

    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("METADATA RESULTS")
    lines.append("=" * 80)

    for entry in results:
        filename = entry["file"]
        metadata = entry["metadata"]

        if not metadata:
            continue

        lines.append(f"\n  {filename}")
        lines.append(f"  {'-' * len(filename)}")
        for key, value in metadata.items():
            lines.append(f"    {key:20s}: {value}")

    lines.append("")
    lines.append("=" * 80)

    unique_users = set()
    unique_software = set()
    for entry in results:
        meta = entry["metadata"]
        for field in ["Author", "LastModifiedBy"]:
            if field in meta and meta[field]:
                unique_users.add(meta[field])
        for field in ["Creator", "Producer", "CreatingApplication"]:
            if field in meta and meta[field]:
                unique_software.add(meta[field])

    if unique_users:
        lines.append("UNIQUE USERS FOUND:")
        for user in sorted(unique_users):
            lines.append(f"  - {user}")
        lines.append("")

    if unique_software:
        lines.append("SOFTWARE IDENTIFIED:")
        for sw in sorted(unique_software):
            lines.append(f"  - {sw}")

    if unique_users or unique_software:
        lines.append("=" * 80)

    return "\n".join(lines)


def export_csv(results, csv_path):
    if not results:
        logger.warning("No results to export.")
        return

    all_keys = set()
    for entry in results:
        all_keys.update(entry["metadata"].keys())
    all_keys = sorted(all_keys)

    fieldnames = ["Filename", "URL"] + all_keys

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for entry in results:
            row = {"Filename": entry["file"], "URL": entry.get("url", "")}
            row.update(entry["metadata"])
            writer.writerow(row)

    logger.info(f"Metadata exported to {csv_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="pyspyder",
        description=(
            "PySpyder - Spider a target domain for publicly available files, "
            "download them, and extract metadata."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pyspyder.py -d targetdomain.com
  python pyspyder.py -d targetdomain.com -f pdf,docx
  python pyspyder.py -d targetdomain.com --depth 4
  python pyspyder.py -d targetdomain.com --csv results.csv
  python pyspyder.py --url-list urls.txt -o ./loot/
        """,
    )

    target_group = parser.add_argument_group("target")
    target_group.add_argument(
        "-d", "--domain",
        help="Target domain to spider for files",
    )
    target_group.add_argument(
        "--url-list",
        help="Path to a file containing URLs to process (one per line). Skips spidering.",
    )

    parser.add_argument(
        "-f", "--file-types",
        default="pdf,docx,xlsx,doc,xls,pptx,ppt",
        help="Comma-separated file extensions to search for (default: pdf,docx,xlsx,doc,xls,pptx,ppt)",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "-o", "--output-dir",
        help="Directory to save downloaded files (default: auto-generated from domain and timestamp)",
    )
    output_group.add_argument(
        "--csv",
        metavar="FILE",
        help="Export all metadata to a CSV file",
    )

    spider_group = parser.add_argument_group("spider options")
    spider_group.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)",
    )
    spider_group.add_argument(
        "--max-pages",
        type=int,
        default=500,
        help="Maximum pages to crawl (default: 500)",
    )
    spider_group.add_argument(
        "--ignore-robots",
        action="store_true",
        help="Ignore robots.txt when spidering",
    )

    request_group = parser.add_argument_group("request options")
    request_group.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between requests (default: 1.0)",
    )
    request_group.add_argument(
        "--user-agent",
        help="Custom User-Agent string",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args(argv)

    if not args.domain and not args.url_list:
        parser.error("Either --domain (-d) or --url-list is required.")

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print(BANNER)
    log = setup_logging(args.verbose)

    file_types = [ft.strip() for ft in args.file_types.split(",")]
    session = get_session(args.user_agent)

    # Phase 1: Discover file URLs
    all_urls = set()

    if args.url_list:
        log.info(f"Loading URLs from {args.url_list}")
        try:
            with open(args.url_list, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        all_urls.add(line)
            log.info(f"Loaded {len(all_urls)} URL(s) from file")
        except FileNotFoundError:
            log.error(f"URL list file not found: {args.url_list}")
            sys.exit(1)
    else:
        try:
            spider_urls = spider_domain(
                args.domain, file_types, session,
                max_depth=args.depth,
                delay=args.delay,
                ignore_robots=args.ignore_robots,
                max_pages=args.max_pages,
            )
            all_urls.update(spider_urls)
        except Exception as err:
            log.error(f"Spider failed: {err}")
            sys.exit(1)

    # Deduplicate
    all_urls = {normalize_url(url) for url in all_urls}
    print(f"\nFound {len(all_urls)} unique file(s) to download.\n")

    if not all_urls:
        log.info("No files found. Exiting.")
        sys.exit(0)

    # Phase 2: Download
    output_dir = args.output_dir
    if not output_dir:
        domain_name = args.domain or "url-list"
        output_dir = generate_output_dir(domain_name)

    log.info(f"Downloading files to: {output_dir}")
    downloaded = download_files(all_urls, output_dir, session, delay=args.delay)
    print(f"\nDownloaded {len(downloaded)} of {len(all_urls)} file(s).\n")

    if not downloaded:
        log.info("No files downloaded. Exiting.")
        sys.exit(0)

    # Phase 3: Extract metadata
    results = []
    for url, filepath in downloaded:
        metadata = extract_metadata(filepath)
        results.append({
            "file": os.path.basename(filepath),
            "url": url,
            "metadata": metadata,
        })

    # Display results
    table = format_metadata_table(results)
    print(table)

    # Export CSV if requested
    if args.csv:
        export_csv(results, args.csv)

    print(f"\nFiles saved to: {os.path.abspath(output_dir)}")


if __name__ == "__main__":
    main()
