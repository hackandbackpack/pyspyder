# PySpyder

A Python tool that spiders a target domain, downloads publicly available files, and extracts metadata — all in a single automated pass. Inspired by [PowerMeta](https://github.com/dafthack/PowerMeta) by Beau Bullock ([@dafthack](https://github.com/dafthack)).

```
 ____        ____                  _
|  _ \ _   _/ ___| _ __  _   _  __| | ___ _ __
| |_) | | | \___ \| '_ \| | | |/ _` |/ _ \ '__|
|  __/| |_| |___) | |_) | |_| | (_| |  __/ |
|_|    \__, |____/| .__/ \__, |\__,_|\___|_|
       |___/      |_|    |___/
```

## What It Does

PySpyder crawls a target domain directly, following links to find downloadable files. It downloads them and pulls out metadata that often reveals internal usernames, email addresses, company names, and the software used to author the documents.

### How It Works

- **BFS Web Spider** — Crawls the target domain, following links up to a configurable depth
- **Scope Control** — Only the target host and its subdomains are crawled. Lookalike hosts such as `targetdomain.com.someoneelse.net` are rejected, including when they appear in the target's own sitemap
- **Scheme Detection** — Tries HTTPS first and falls back to HTTP for hosts that only serve plaintext
- **Redirect Resolution** — Automatically follows redirecting domains (e.g., `example.com` -> `www.example.com`)
- **Sitemap Parsing** — Reads `sitemap.xml`, any nested sitemap indexes, and any `Sitemap:` entries in `robots.txt`
- **robots.txt Compliance** — Respects `robots.txt` for both crawled pages and downloaded files, read per host so a subdomain's own rules apply to its own files (override with `--ignore-robots`)
- **Rate Limiting** — Configurable delay between requests to avoid hammering targets

### Supported File Types

By default, PySpyder searches for: `pdf`, `docx`, `xlsx`, `doc`, `xls`, `pptx`, `ppt`

### Metadata Extracted

| File Type | Library | Fields |
|---|---|---|
| PDF | pypdf | Author, Creator, Producer, Title, Subject, Keywords, Created, Modified |
| DOCX | python-docx | Author, Last Modified By, Title, Subject, Keywords, Created, Modified |
| XLSX | openpyxl | Author, Last Modified By, Title, Keywords, Created, Modified |
| PPTX | python-pptx | Author, Last Modified By, Title, Subject, Keywords, Created, Modified |
| DOC/XLS/PPT | olefile | Author, Last Modified By, Company, Manager, Title, Subject, Keywords, Creating Application |

For the OOXML formats (DOCX/XLSX/PPTX), PySpyder also reads `docProps/app.xml` for **Manager**, **Company**, **Template**, and **Application**/**AppVersion** — fields the standard core-properties APIs don't expose.

## Installation

```bash
git clone https://github.com/hackandbackpack/pyspyder.git
cd pyspyder
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Spider a domain, download files, extract metadata
python pyspyder.py -d targetdomain.com
```

`-d` accepts a bare host. A full URL or a trailing path also works — the path is
ignored and the crawl starts at the site root.

### File Types

```bash
# Search for specific file types only
python pyspyder.py -d targetdomain.com -f pdf,docx

# Just PDFs
python pyspyder.py -d targetdomain.com -f pdf
```

### Output

```bash
# Put the run folder inside ./loot/
python pyspyder.py -d targetdomain.com -o ./loot/

# Export all metadata to CSV
python pyspyder.py -d targetdomain.com --csv results.csv
```

Every run creates its own timestamped folder, e.g. `./loot/targetdomain.com-2026-08-03-112953/`, so repeat runs never overwrite each other. `--csv` writes to the path you give it, relative to the current directory.

The CSV is the only output with per-file detail — it has one row per file with the source URL and a column for every metadata field seen across the run. The console prints a deduplicated summary.

### Using a URL List

If you already have a list of file URLs (one per line), skip the spider phase entirely:

```bash
python pyspyder.py --url-list urls.txt
python pyspyder.py --url-list urls.txt --csv results.csv -o ./loot/
```

Lines starting with `#` are treated as comments and ignored. Lines with no scheme are assumed to be `https://`.

### Metadata From Files You Already Have

```bash
# Walk a directory tree and extract metadata, no network traffic
python pyspyder.py --metadata-only ./loot/targetdomain.com-2026-08-03-112953
python pyspyder.py --metadata-only ./old-engagement/ --csv results.csv
```

Subdirectories are included. Only files matching `-f` are read.

### Tuning

```bash
# Increase crawl depth (default: 2)
python pyspyder.py -d targetdomain.com --depth 4

# Increase max pages crawled (default: 500)
python pyspyder.py -d targetdomain.com --max-pages 1000

# Slow down requests (default: 1 second delay)
python pyspyder.py -d targetdomain.com --delay 2

# Ignore robots.txt for both crawling and downloading
python pyspyder.py -d targetdomain.com --ignore-robots

# Skip anything over 25 MB (default: 100, use 0 for no limit)
python pyspyder.py -d targetdomain.com --max-file-size 25

# Download files but skip metadata extraction
python pyspyder.py -d targetdomain.com --download-only

# Custom User-Agent
python pyspyder.py -d targetdomain.com --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

# Verbose output (per-URL detail, skipped out-of-scope links, retry noise)
python pyspyder.py -d targetdomain.com -v
```

## Example Output

```
$ python pyspyder.py -d example.com --csv results.csv -o ./loot/

INFO: Spider: Starting crawl of example.com (depth=2, max_pages=500)
INFO: Spider: example.com redirects to www.example.com
INFO: Sitemap: Found 3 file(s) in sitemap(s)
INFO: Spider: Skipped 2 URL(s) disallowed by robots.txt (use --ignore-robots to collect them)
INFO: Spider: Found 11 file(s) across 47 pages crawled

Found 11 unique file(s) to download.

INFO: Downloading files to: ./loot/example.com-2026-08-03-112953
INFO: [1/11] Downloaded: annual-report-2024.pdf
INFO: [2/11] Downloaded: budget.xlsx
WARNING: [3/11] Skipped (server returned HTML): login-required.pdf
INFO: [4/11] Downloaded: org-chart.docx
...

Downloaded 10 of 11 file(s).

================================================================================
METADATA SUMMARY
  9 file(s) with metadata, 1 without
================================================================================

NAMES / USERNAMES:
  - admin
  - jane.doe
  - jsmith
  - rmanager

EMAILS:
  - jsmith@example.com

COMPANIES:
  - Acme Corporation

SOFTWARE:
  - Acrobat Distiller 21.0
  - Microsoft Office Word 16.0000
  - Microsoft Word 2019

================================================================================

INFO: Metadata exported to results.csv

Files saved to: /home/user/loot/example.com-2026-08-03-112953
```

Names are collected from the Author, Last Modified By, and Manager fields; emails are pulled out of every metadata value with a regex.

## All Options

```
usage: pyspyder [-h] [-d DOMAIN] [--url-list URL_LIST] [--metadata-only DIR]
                [-f FILE_TYPES] [-o OUTPUT_DIR] [--csv FILE] [--depth DEPTH]
                [--max-pages MAX_PAGES] [--ignore-robots] [--download-only]
                [--delay DELAY] [--user-agent USER_AGENT]
                [--max-file-size MB] [-v] [--version]

Target (one required):
  -d, --domain          Target domain to spider for files
  --url-list            File containing URLs to process (skips spidering)
  --metadata-only DIR   Extract metadata from an existing directory tree
                        (skips spidering and downloading)

File Types:
  -f, --file-types      Comma-separated extensions (default: pdf,docx,xlsx,doc,xls,pptx,ppt)

Output:
  -o, --output-dir      Parent directory for the timestamped run folder
  --csv FILE            Export all metadata to CSV (one row per file)

Spider Options:
  --depth               Max crawl depth (default: 2)
  --max-pages           Max pages to crawl (default: 500)
  --ignore-robots       Ignore robots.txt when spidering and downloading
  --download-only       Download files without extracting metadata

Request Options:
  --delay               Seconds between requests (default: 1.0)
  --user-agent          Custom User-Agent string
  --max-file-size MB    Skip files larger than this (default: 100, 0 = no limit)

General:
  -v, --verbose         Debug output
  --version             Show version
```

`--csv` cannot be combined with `--download-only`, since no metadata is collected to export.

## Notes and Limitations

- Only `<a href>` links are followed. Files referenced solely from JavaScript, or behind a login, are not discovered — feed those in with `--url-list`.
- Downloads are written to a `.part` file and renamed on completion, so an interrupted transfer never leaves a truncated file that looks whole.
- A URL that claims to be a document but returns HTML (a login page or soft 404) is skipped. A file whose contents don't match its extension is kept but flagged.
- Metadata is treated as untrusted, because the target wrote it. Terminal control characters are stripped, over-long values are truncated, and CSV values that begin with `=`, `+`, `-` or `@` get a leading apostrophe so a spreadsheet shows them as text instead of running them as a formula.
- Requests are sequential. A 500-page crawl at the default 1 second delay takes a while by design; lower `--delay` if the target can take it.
- If a page redirects to a host outside the target, it isn't crawled. If a *document* redirects offsite — common when files are served from a CDN — it is still downloaded, and the off-scope host is named in the output so it's on the record.

## Dependencies

- [requests](https://pypi.org/project/requests/) — HTTP client
- [beautifulsoup4](https://pypi.org/project/beautifulsoup4/) — HTML parsing for spidering
- [lxml](https://pypi.org/project/lxml/) — XML parsing for sitemaps
- [pypdf](https://pypi.org/project/pypdf/) — PDF metadata extraction
- [python-docx](https://pypi.org/project/python-docx/) — DOCX metadata extraction
- [openpyxl](https://pypi.org/project/openpyxl/) — XLSX metadata extraction
- [python-pptx](https://pypi.org/project/python-pptx/) — PPTX metadata extraction
- [olefile](https://pypi.org/project/olefile/) — Legacy Office (DOC/XLS/PPT) metadata extraction

## Development

```bash
python -m unittest discover -s tests
```

The test suite uses only the stdlib plus the tool's own dependencies, so there is nothing extra to install. Office fixtures are generated at run time into a temp directory. See [TECHNICAL-REFERENCE.md](TECHNICAL-REFERENCE.md) for the internals.

## Legal

Only point this at systems you are authorized to test. Crawling and bulk-downloading
files from a domain you don't own may be unlawful in your jurisdiction.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Inspired by [PowerMeta](https://github.com/dafthack/PowerMeta) by [Beau Bullock](https://github.com/dafthack). PySpyder is a ground-up Python rewrite that uses direct web spidering, pure Python metadata extraction (no ExifTool dependency), and a non-interactive single-pass workflow.
