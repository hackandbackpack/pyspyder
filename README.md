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

PySpyder crawls a target domain directly, following links to find downloadable files. It downloads them and pulls out metadata that often reveals internal usernames, email addresses, software versions, and computer names.

### How It Works

- **BFS Web Spider** — Crawls the target domain, following links up to a configurable depth
- **Redirect Resolution** — Automatically follows redirecting domains (e.g., `tri-c.edu` -> `www.tri-c.edu`)
- **robots.txt Compliance** — Respects `robots.txt` by default (can be overridden)
- **Rate Limiting** — Configurable delay between requests to avoid hammering targets

### Supported File Types

By default, PySpyder searches for: `pdf`, `docx`, `xlsx`, `doc`, `xls`, `pptx`, `ppt`

### Metadata Extracted

| File Type | Library | Fields |
|---|---|---|
| PDF | PyPDF2 | Author, Creator, Producer, Title, Subject, Created, Modified |
| DOCX | python-docx | Author, Last Modified By, Title, Subject, Created, Modified |
| XLSX | openpyxl | Author, Last Modified By, Title, Created, Modified |
| PPTX | python-pptx | Author, Last Modified By, Title, Subject, Created, Modified |
| DOC/XLS/PPT | olefile | Author, Last Author, Company, Title, Subject, Creating Application |

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

### File Types

```bash
# Search for specific file types only
python pyspyder.py -d targetdomain.com -f pdf,docx

# Just PDFs
python pyspyder.py -d targetdomain.com -f pdf
```

### Output

```bash
# Save files to a specific directory
python pyspyder.py -d targetdomain.com -o ./loot/

# Export all metadata to CSV
python pyspyder.py -d targetdomain.com --csv results.csv
```

### Using a URL List

If you already have a list of file URLs (one per line), skip the spider phase entirely:

```bash
python pyspyder.py --url-list urls.txt
python pyspyder.py --url-list urls.txt --csv results.csv -o ./loot/
```

Lines starting with `#` in the URL list are treated as comments and ignored.

### Tuning

```bash
# Increase crawl depth (default: 2)
python pyspyder.py -d targetdomain.com --depth 4

# Increase max pages crawled (default: 500)
python pyspyder.py -d targetdomain.com --max-pages 1000

# Slow down requests (default: 1 second delay)
python pyspyder.py -d targetdomain.com --delay 2

# Ignore robots.txt
python pyspyder.py -d targetdomain.com --ignore-robots

# Custom User-Agent
python pyspyder.py -d targetdomain.com --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

# Verbose output (shows debug-level detail)
python pyspyder.py -d targetdomain.com -v
```

## Example Output

```
================================================================================
METADATA RESULTS
================================================================================

  annual-report-2024.pdf
  ----------------------
    Author              : jsmith
    Creator             : Microsoft Word 2019
    Producer            : Acrobat Distiller 21.0
    Title               : Annual Report
    Created             : 2024-03-15T10:23:00
    Modified            : 2024-03-20T14:55:00

  org-chart.xlsx
  --------------
    Author              : jane.doe
    LastModifiedBy      : admin
    Created             : 2023-11-01T09:00:00
    Modified            : 2024-01-15T16:30:00

================================================================================
UNIQUE USERS FOUND:
  - admin
  - jane.doe
  - jsmith

SOFTWARE IDENTIFIED:
  - Acrobat Distiller 21.0
  - Microsoft Word 2019
================================================================================

Files saved to: /home/user/targetdomain.com-2024-03-25-143022
```

## All Options

```
usage: pyspyder [-h] [-d DOMAIN] [--url-list URL_LIST] [-f FILE_TYPES]
                [-o OUTPUT_DIR] [--csv FILE] [--depth N] [--max-pages N]
                [--ignore-robots] [--delay SECONDS] [--user-agent UA]
                [-v] [--version]

Target:
  -d, --domain          Target domain to spider for files
  --url-list            File containing URLs to process (skips spidering)

File Types:
  -f, --file-types      Comma-separated extensions (default: pdf,docx,xlsx,doc,xls,pptx,ppt)

Output:
  -o, --output-dir      Directory for downloaded files (default: auto-generated)
  --csv FILE            Export all metadata to CSV

Spider Options:
  --depth               Max crawl depth (default: 2)
  --max-pages           Max pages to crawl (default: 500)
  --ignore-robots       Ignore robots.txt

Request Options:
  --delay               Seconds between requests (default: 1.0)
  --user-agent          Custom User-Agent string

General:
  -v, --verbose         Debug output
  --version             Show version
```

## Dependencies

- [requests](https://pypi.org/project/requests/) — HTTP client
- [beautifulsoup4](https://pypi.org/project/beautifulsoup4/) — HTML parsing for spidering
- [PyPDF2](https://pypi.org/project/PyPDF2/) — PDF metadata extraction
- [python-docx](https://pypi.org/project/python-docx/) — DOCX metadata extraction
- [openpyxl](https://pypi.org/project/openpyxl/) — XLSX metadata extraction
- [python-pptx](https://pypi.org/project/python-pptx/) — PPTX metadata extraction
- [olefile](https://pypi.org/project/olefile/) — Legacy Office (DOC/XLS/PPT) metadata extraction

## Acknowledgments

Inspired by [PowerMeta](https://github.com/dafthack/PowerMeta) by [Beau Bullock](https://github.com/dafthack). PySpyder is a ground-up Python rewrite that uses direct web spidering, pure Python metadata extraction (no ExifTool dependency), and a non-interactive single-pass workflow.
