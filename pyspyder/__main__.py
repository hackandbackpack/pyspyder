"""Entry point for python -m pyspyder."""

import os
import sys

from pyspyder.cli import parse_args
from pyspyder.downloader import download_files
from pyspyder.metadata import export_csv, extract_metadata, format_metadata_table
from pyspyder.spider import spider_domain
from pyspyder.utils import (
    generate_output_dir,
    get_session,
    normalize_url,
    setup_logging,
)


BANNER = r"""
 ____        ____                  _
|  _ \ _   _/ ___| _ __  _   _  __| | ___ _ __
| |_) | | | \___ \| '_ \| | | |/ _` |/ _ \ '__|
|  __/| |_| |___) | |_) | |_| | (_| |  __/ |
|_|    \__, |____/| .__/ \__, |\__,_|\___|_|
       |___/      |_|    |___/
  Domain File Metadata Extractor
"""


def main():
    args = parse_args()

    print(BANNER)
    logger = setup_logging(args.verbose)

    file_types = [ft.strip() for ft in args.file_types.split(",")]
    session = get_session(args.user_agent)

    # Phase 1: Discover file URLs
    all_urls = set()

    if args.url_list:
        logger.info(f"Loading URLs from {args.url_list}")
        try:
            with open(args.url_list, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        all_urls.add(line)
            logger.info(f"Loaded {len(all_urls)} URL(s) from file")
        except FileNotFoundError:
            logger.error(f"URL list file not found: {args.url_list}")
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
            logger.error(f"Spider failed: {err}")
            sys.exit(1)

    # Deduplicate
    all_urls = {normalize_url(url) for url in all_urls}
    print(f"\nFound {len(all_urls)} unique file(s) to download.\n")

    if not all_urls:
        logger.info("No files found. Exiting.")
        sys.exit(0)

    # Phase 2: Download
    output_dir = args.output_dir
    if not output_dir:
        domain_name = args.domain or "url-list"
        output_dir = generate_output_dir(domain_name)

    logger.info(f"Downloading files to: {output_dir}")
    downloaded = download_files(all_urls, output_dir, session, delay=args.delay)
    print(f"\nDownloaded {len(downloaded)} of {len(all_urls)} file(s).\n")

    if not downloaded:
        logger.info("No files downloaded. Exiting.")
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
