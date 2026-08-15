# PySpyder — Technical Reference

Internal reference for the implementation. For usage see [README.md](README.md).

Single-file tool: `pyspyder.py`. No package, no state on disk beyond the run
folder it writes.

## Pipeline

```
parse_args
  -> [--metadata-only]  find_local_files -> collect_metadata -> summary/CSV -> exit
  -> [--url-list]       read file                     \
  -> [-d]               spider_domain                 / -> normalize + dedup
  -> download_files  -> collect_metadata -> format_metadata_summary -> export_csv
```

Three phases in `main()`: discover URLs, download, extract. `--download-only`
returns after phase 2. `--metadata-only` skips phases 1 and 2 entirely and never
opens a socket.

## Module map

### Setup
| Function | Notes |
|---|---|
| `check_dependencies()` | Runs at import, before argparse. Every entry in `REQUIRED_PACKAGES` must import or the process exits 1 — so `--help` and `--version` also require a complete install. |
| `setup_logging(verbose)` | Root logger at INFO, or DEBUG with `-v`. Non-verbose runs raise the `urllib3` and `pypdf` loggers to ERROR; both are chatty at WARNING and we report fetch and extraction outcomes ourselves. |
| `get_session(user_agent)` | One `requests.Session` for the whole run. Browser-shaped headers. `DEFAULT_USER_AGENT` is a recent desktop **Firefox**, not Chrome: a stock WordPress security rule 403s the Chrome token while letting Firefox through, and a silent 403 on the seed URL reads as "0 files found". `--user-agent` overrides it. `Accept-Encoding` is `gzip, deflate` only: requests decodes `br` solely when a brotli package is installed, so advertising it unconditionally returned undecoded bytes on Brotli servers and the page parsed to zero links. Add brotli to requirements before re-adding `br`. `Retry(total=3, backoff_factor=0.5)` on 429/500/502/503. `respect_retry_after_header=False` on purpose: urllib3 sleeps a `Retry-After` verbatim with no ceiling (`backoff_max` bounds only exponential backoff), so a single `Retry-After: 86400` would park the run for a day. |

### URL and scope handling
| Function | Notes |
|---|---|
| `normalize_domain(raw)` | `(host, discarded_path)`. Accepts `example.com`, `https://example.com`, `EXAMPLE.com/docs/`, `user@example.com`. Lowercased, trailing dot stripped, port preserved. `main()` warns when a path is discarded. |
| `resolve_target(domain, session)` | `(scheme, host)`. Tries HTTPS then HTTP, HEAD then GET per scheme (some servers reject HEAD), follows redirects, and takes scheme and host from the final URL. Falls back to `("https", domain)` when nothing answers. **The returned scheme is what the crawl uses** — this is what makes HTTP-only hosts reachable. |
| `url_key(url)` | Canonical **comparison key**, used for the `visited` set and download dedup. Drops the scheme (so http/https variants of one resource collapse), drops the fragment, strips the trailing slash, removes `TRACKING_PARAMS`, and sorts remaining params. Takes the host off the raw netloc rather than `parsed.port`, which raises `ValueError` on a malformed port — one link to `host:99999` used to abort the entire crawl. |
| `bare_host(host_or_netloc)` | Lowercase hostname with the port removed, via `urlsplit().hostname` so IPv6 literals survive. A naive `split(":")[0]` turns `[::1]:8443` into `[`, which made any two IPv6 hosts compare equal. |
| `host_in_scope(link_host, scope_hosts)` | Exact host match or a true subdomain (`.suffix`) match, port-insensitive. Deliberately **not** a substring test — that admits `example.com.attacker.tld` and `notexample.com`. Applied to crawled links, sitemap entries, and sitemap URLs themselves. |
| `normalize_file_types(raw)` | Splits `-f` into bare lowercase extensions. `.pdf` is the natural way to type one and used to match nothing at all, since the test built `"..pdf"`. |
| `is_target_file(url, file_types)` | Extension test against the URL path only, so query strings don't defeat it, and tolerant of a leading dot regardless of caller. |
| `dedupe_urls(urls)` | One URL per canonical key, returned verbatim, https preferred, sorted for run-to-run stability. Extracted from `main()` so it can be tested directly. |

**`url_key` output is never requested.** It is lossy by design, so fetches always
use the URL exactly as discovered. A rewritten query is a different request to the
server: `?flag` is not `?flag=`, `?a=%20b` is not `?a=+b`, and re-encoding a signed
URL's parameters stops it verifying. The crawler already queued original URLs while
keying `visited`; `main()` now does the same for downloads.

### Spider
`spider_domain()` is a BFS over a `deque` of `(url, depth)`.

- `visited` holds `url_key()` output, so tracking-param, fragment, scheme and
  trailing-slash variants of one page are fetched once. The queue holds the
  original URLs.
- `max_pages` is checked against `len(visited)` at the top of each iteration.
- Links are skipped unless the scheme is `http`/`https` and the host is in scope.
- A link matching `-f` is added to `file_urls`; otherwise it is enqueued at
  `depth + 1` while `depth < max_depth`.
- Responses are parsed only for `text/html` or `application/xhtml`.
- The page GET goes through `_fetch_page()`, and `--delay` is applied once
  immediately after it, before any of the checks that can `continue`. When the
  sleep sat at the bottom of the loop, a 404 or a non-HTML response skipped it
  even though the request had already gone out — a crawl over a site of dead
  links ran with no throttling at all. Same defect the downloader had.
- **Links resolve against `response.url`, not the requested URL.** A redirect
  means the page in hand belongs to a different URL, and `/docs` 301ing to
  `/docs/` is routine; joining a relative `budget.xlsx` onto the pre-redirect
  `/docs` yields `/budget.xlsx`, which does not exist. The final URL's key is
  also added to `visited` so the redirect target isn't fetched again.
- A `<base href>` in the document overrides that base, per HTML semantics.
- `_fetch_page()` returns `(response, status)`. When the seed page (depth 0)
  comes back unusable, `_warn_blocked_seed()` logs a WARNING instead of the run
  finishing on a quiet "Found 0 files": a 401/403/429 is called out as a likely
  WAF/User-Agent block with a `--user-agent` hint, other statuses and outright
  connection failures get their own message. Failures below the seed stay at
  debug — a blocked root is the case an operator has to know about.
- If a redirect lands the page on an out-of-scope host, it is not parsed at all,
  so a target that redirects offsite can't have its links harvested.
- `RobotsPolicy.allowed()` is the single robots gate. It runs on pages before
  fetching, on file URLs before collection, and on sitemap entries — so
  `--ignore-robots` is the one switch governing all three. It counts blocks and
  `spider_domain` reports the total.

`RobotsPolicy` caches one `RobotFileParser` **per host**, because robots.txt is a
per-host document: `www.example.com` saying `Disallow: /docs/` must not suppress
files served from `cdn.example.com`, which has its own rules. It also collects the
`Sitemap:` directives itself (`RobotFileParser` doesn't expose them) and reports,
without enforcing, a `Crawl-delay` larger than `--delay`. With `--ignore-robots`,
`allowed()` short-circuits to `True` and the only robots.txt fetch is the one that
harvests `Sitemap:` hints.

`_parse_sitemap()` walks `sitemap.xml` plus anything from `robots.txt`, following
nested `<sitemap>` indexes with a `visited_sitemaps` guard against loops. Needs
lxml (`BeautifulSoup(text, "xml")`). Notes:

- **Scope is checked when a sitemap URL is popped**, not just on nested entries,
  because a `Sitemap:` line in robots.txt can name any host on the internet.
- `--delay` applies between sitemap fetches, and `MAX_SITEMAPS` caps how many are
  read; anything left is reported rather than silently dropped.
- **The parse is wrapped** — a parser failure logs a warning and skips that
  sitemap rather than propagating out of `spider_domain` into the `except` in
  `main()`, which would discard every file the crawl already found.

Progress goes through `_progress()`/`_progress_clear()`, which no-op unless
`sys.stdout.isatty()`, keeping the `\r` counter out of redirected output.

### Downloader
`download_files(urls, output_dir, session, delay, max_bytes)` returns
`[(url, filepath)]`, which is what feeds metadata extraction and the CSV — so
the file each URL maps to must be correct.

- `_unique_filename(name, used_names)` claims a name against a per-run set,
  incrementing `_1`, `_2` and so on until free, and **registers the name it
  returns**.
  A genuine `report_1.pdf` on the target therefore can't collide with the
  rename of a duplicate `report.pdf`.
- `_fetch_to_file()` does one transfer and returns a bool. Keeping it separate
  from the loop is what makes two things unconditional: the name is released
  (`used_names.discard`) on *every* failure path, and `--delay` is applied after
  every request. When both lived inline, an early `continue` for "server returned
  HTML" or "larger than limit" skipped the delay entirely — the request had
  already gone out, so a run against a site full of soft 404s hammered it with no
  throttling at all. The exists-on-disk skip still bypasses the delay, correctly,
  since it makes no request.
- Every transfer writes `<name>.part` and `os.replace()`s it into position only
  after the body is complete and magic bytes are checked. The `finally` removes
  any surviving `.part` — it runs on `KeyboardInterrupt` too, so Ctrl-C leaves no
  stray fragments. Nothing truncated is ever left under a real filename.
- `max_bytes` is enforced twice: against `Content-Length` before the body is
  read, then against bytes written while streaming (a lying or absent header
  can't get past it).
- A **download** that redirects off-scope is still followed, unlike a page fetch,
  and logged at INFO instead. Documents legitimately live on CDNs under an
  unrelated registrable domain, and refusing those would lose real files with no
  way to opt back in. The log line is the audit trail; if scope needs to be hard
  here, that is a `--no-offsite` flag, not a silent default.
- `_is_html_response()` skips a document URL that returns `text/html` — a login
  page or soft 404. `_validate_file_magic()` warns but keeps a file whose header
  doesn't match its extension; it looks through a `.part` suffix to find the
  real extension.
- The "Skipped (exists)" branch only fires when a run folder is reused, since
  `generate_output_dir()` timestamps to the second.

`_extract_filename()` takes `basename` after `unquote`, normalizing `\` to `/`
first so encoded Windows separators can't leave a path fragment in the name.
Keeps alphanumerics (Unicode included) plus `._-` and space, strips trailing dots
and spaces, prefixes `_` to `WINDOWS_RESERVED_NAMES` (`CON.pdf` -> `_CON.pdf`)
which would otherwise open a device instead of a file, and truncates the stem to
`MAX_FILENAME_LENGTH` so a pathological URL fails as a clear skip rather than an
opaque `OSError` once the output directory pushes it past the path limit.

### Metadata extraction
`extract_metadata()` dispatches on extension, returns `{}` on any failure while
logging a warning, and passes every value through `_clean_metadata_value()`.
Every extractor is best-effort; a corrupt file costs one warning, not the run.

**Metadata is untrusted input.** On an engagement the target authored these
strings, and they land in an operator's terminal and spreadsheet:

- `_clean_metadata_value()` strips C0/C1 control characters (so a crafted Author
  field can't emit ANSI escapes into the console), collapses all whitespace runs
  to single spaces (so embedded newlines can't forge extra bullet lines in the
  printed summary), and caps length at `MAX_METADATA_LENGTH`. Values that reduce
  to nothing are dropped.
- `_csv_safe()` prefixes an apostrophe to any CSV value starting with
  `= + - @ TAB CR`, which is what stops `=cmd|'/c calc'!A0` in an Author field
  from executing when the CSV is opened in Excel. Applied to `Filename` and
  `URL` too, since a filename can legitimately start with `-`.
- `_extract_ooxml_extended()` checks `ZipInfo.file_size` against
  `MAX_APP_XML_BYTES` before reading. Deflate reaches ~1000:1, so an 80 KB
  `app.xml` entry expands to 80 MB in memory, and nothing else capped it.

| Extension | Function | Library |
|---|---|---|
| `.pdf` | `_extract_pdf` | pypdf (`PdfReader.metadata`, `/Author` style keys) |
| `.docx` | `_extract_docx` | python-docx core properties |
| `.xlsx` | `_extract_xlsx` | openpyxl (`read_only=True`, closed in a `finally` — read-only workbooks hold file handles open) |
| `.pptx` | `_extract_pptx` | python-pptx core properties |
| `.doc` `.xls` `.ppt` | `_extract_ole` | olefile, guarded by `isOleFile()`; values through `_ole_text()` |

`_ole_text()` exists because OLE property values are `bytes` for `VT_LPSTR` but
`str` for `VT_LPWSTR`. Calling `.decode()` unconditionally raised
`AttributeError` on the `str` form, and since `extract_metadata` catches
everything, **the entire file's metadata was silently discarded** — not just the
one field.

`_extract_ooxml_extended()` adds Manager, Template, Application, AppVersion and
Company for the three OOXML types by reading `docProps/app.xml` out of the zip
with `xml.etree.ElementTree`. It matches on the namespace-stripped, lowercased
tag name, and uses `setdefault` so core properties win. It uses ElementTree
rather than BeautifulSoup deliberately: an HTML parser on that XML emits
`XMLParsedAsHTMLWarning` on every file, and the `"xml"` parser would make the
tag lookups case-sensitive against `<Manager>`.

Keys are normalized across formats — `Author`, `LastModifiedBy`, `Company`,
`Manager`, `Title`, `Subject`, `Keywords`, `Created`, `Modified`, plus
`Creator`/`Producer`/`CreatingApplication`/`Application`/`AppVersion`/`Template`.
`format_metadata_summary()` and `export_csv()` both rely on those names.

### Output
- `format_metadata_summary(results)` — console summary only: deduplicated
  NAMES / USERNAMES (Author, LastModifiedBy, Manager), EMAILS (`EMAIL_REGEX`
  over every value), COMPANIES, SOFTWARE (Creator, Producer,
  CreatingApplication, and Application + AppVersion joined). No per-file detail.
- `export_csv(results, path)` — the only per-file output. Header is
  `Filename, URL` plus the sorted union of every metadata key in the run.
- `collect_metadata(triples)` — shared by the download path and
  `--metadata-only` so both produce identical result dicts.
- `find_local_files(dir, file_types)` — `os.walk`, so `--metadata-only`
  covers subdirectories. Display names are paths relative to the directory
  given, which keeps same-named files in different folders distinguishable.

## Config and CLI

Defaults live in one place each: `DEFAULT_FILE_TYPES` feeds the `-f` default
string, `DEFAULT_USER_AGENT` feeds `get_session`. `--depth 2`, `--max-pages 500`,
`--delay 1.0`, `--max-file-size 100` (MB, `0` disables).

`parse_args()` rejects, at parse time:
- no `-d` / `--url-list` / `--metadata-only`
- `--csv` with `--download-only` (nothing would be exported)
- negative `--max-file-size`

`main()` dedups on `url_key()` while keeping each URL exactly as discovered,
preferring `https://` when one resource turned up under both schemes. It iterates
`sorted(all_urls)` so the surviving URL — and therefore filename suffixing — is
reproducible run to run rather than following set iteration order.

`--url-list` assumes `https://` for a scheme-less line and skips anything that
isn't `http`/`https`, rather than handing `requests` a URL it has no adapter for.

## Output layout

```
<-o dir>/<domain>-<YYYY-MM-DD-HHMMSS>/   run folder, one per invocation
```

`--csv` is written to the path given, relative to the working directory, not
into the run folder. `--url-list` runs name the folder `url-list-<timestamp>`.

## Dependencies

`requests`, `beautifulsoup4`, `lxml`, `pypdf`, `python-docx`, `openpyxl`,
`python-pptx`, `olefile`.

lxml is required directly for sitemap parsing and is listed explicitly, even
though python-docx and python-pptx would pull it in anyway — installs that
trim those would otherwise lose sitemap support with no warning at install time.

## Resource caps

All of these exist to stop one hostile or broken target from consuming the run.
None are configurable; raise them in the source if a real target needs it.

| Constant | Limit | Guards against |
|---|---|---|
| `MAX_SITEMAPS` | 50 sitemaps | A sitemap index fanning out to thousands of children |
| `MAX_APP_XML_BYTES` | 1 MB | Zip decompression bomb in `docProps/app.xml` |
| `MAX_METADATA_LENGTH` | 500 chars | A metadata field padded to megabytes |
| `MAX_FILENAME_LENGTH` | 120 chars | Path-length failures from a pathological URL |
| `MAX_EXTENSION_LENGTH` | 12 chars | The same, when the *extension* is the long part |
| `--max-file-size` | 100 MB | An endless or enormous download |

`parse_args()` also rejects a negative `--delay` (which would raise inside
`time.sleep` mid-crawl), a negative `--depth`, and `--max-pages` below 1.

Known and deliberately not capped: the body of a crawled HTML page and of a
sitemap are read fully into memory (`response.text`), so a multi-gigabyte
response labelled `text/html` would exhaust memory.

## Tests

```bash
python -m unittest discover -s tests     # or: pytest tests
```

`tests/test_pyspyder.py`, stdlib `unittest`, ~90 tests in well under a second.
No dev dependencies: the suite needs nothing the tool doesn't already require,
so it runs anywhere the tool does.

How it is built:

- **`FakeSession`** routes URLs to canned responses and records every request,
  so scope, robots, redirect and dedup behaviour is asserted without a network.
  `html()` builds a page response, `document()` a file response.
- **`--delay` is asserted, not waited on.** `time.sleep` is patched and the call
  count checked, which is how the throttle bugs are pinned down without making
  the suite slow.
- **Office fixtures are generated at run time** into `tempfile.mkdtemp()` by
  pypdf/python-docx/openpyxl/python-pptx, with known values to assert against.
  Nothing binary is committed and nothing is written inside the tree.
- **OLE is covered by stubbing `olefile`**, since a real `.doc` can't be
  produced without Word. `_ole_text` is unit-tested directly.

Most tests exist because the behaviour they pin down was once wrong, and say so
in a comment. Treat a failure as a regression of a real defect, not as a test
that has become inconvenient.

### Not covered by the suite

- `main()` itself — argument handling is tested through `parse_args`, but the
  three end-to-end modes are not driven in-process.
- TLS, redirects and content negotiation as a real server performs them. These
  were verified manually against a local HTTPS/HTTP server serving a corpus with
  `robots.txt`, a nested sitemap index, a genuine 301 on a directory URL,
  lookalike hosts, a document URL returning HTML, an extension/content mismatch,
  percent-encoded filenames, duplicate basenames, and real OLE `.doc`/`.xls`
  files produced by Word and Excel.
- The one invariant a fake session cannot prove: **the URL the server receives
  is byte-identical to the one discovered.** Check that against a server access
  log, not against the tool's own output — that is how the rewritten-query bug
  was caught.
- each CSV row's `URL` matches the file its metadata came from
