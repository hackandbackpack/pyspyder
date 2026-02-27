import argparse

from pyspyder import __version__


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
  python -m pyspyder -d targetdomain.com
  python -m pyspyder -d targetdomain.com -f pdf,docx
  python -m pyspyder -d targetdomain.com --depth 4
  python -m pyspyder -d targetdomain.com --csv results.csv
  python -m pyspyder --url-list urls.txt -o ./loot/
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
