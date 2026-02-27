import logging
import os
import time
from urllib.parse import unquote, urlparse

logger = logging.getLogger("pyspyder")


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
