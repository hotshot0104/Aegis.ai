"""
NSL-KDD Dataset Downloader for Project AEGIS-AI.
Downloads KDDTrain+.txt and KDDTest+.txt from verified public mirrors
into backend/data/nslkdd/.
"""

import os
import sys
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data", "nslkdd")

URL_PAIRS = [
    {
        "name": "jmnwong/NSL-KDD-Dataset mirror",
        "train": "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt",
        "test": "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt",
    },
    {
        "name": "defcom-lab/NSL-KDD mirror",
        "train": "https://raw.githubusercontent.com/defcom-lab/NSL-KDD/master/KDDTrain+.txt",
        "test": "https://raw.githubusercontent.com/defcom-lab/NSL-KDD/master/KDDTest+.txt",
    }
]


def download_file(url: str, dest_path: str) -> bool:
    """Download a file with user-agent header and simple progress reporting."""
    print(f"[*] Downloading: {url}")
    print(f"    -> Destination: {dest_path}")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, "wb") as out_file:
            total_size = int(resp.headers.get("content-length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                downloaded += len(chunk)
                out_file.write(chunk)
                if total_size > 0:
                    percent = downloaded / total_size * 100
                    print(f"\r    -> Progress: {downloaded / (1024*1024):.1f}MB / {total_size / (1024*1024):.1f}MB ({percent:.1f}%)", end="")
                else:
                    print(f"\r    -> Downloaded: {downloaded / (1024*1024):.1f}MB", end="")
            print()
        print(f"[+] Successfully saved {dest_path} ({os.path.getsize(dest_path)} bytes)")
        return True
    except (urllib.error.URLError, TimeoutError, Exception) as e:
        print(f"\n[-] Download failed for {url}: {e}")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False


def ensure_nslkdd_dataset() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    train_dest = os.path.join(DATA_DIR, "KDDTrain+.txt")
    test_dest = os.path.join(DATA_DIR, "KDDTest+.txt")

    train_ok = os.path.exists(train_dest) and os.path.getsize(train_dest) > 1000000
    test_ok = os.path.exists(test_dest) and os.path.getsize(test_dest) > 500000

    if train_ok and test_ok:
        print(f"[+] NSL-KDD dataset already present at {DATA_DIR}:")
        print(f"    - KDDTrain+.txt: {os.path.getsize(train_dest) / (1024*1024):.2f} MB")
        print(f"    - KDDTest+.txt:  {os.path.getsize(test_dest) / (1024*1024):.2f} MB")
        return

    for mirror in URL_PAIRS:
        print(f"\n[*] Trying mirror: {mirror['name']}")
        succeeded = True
        if not train_ok:
            if not download_file(mirror["train"], train_dest):
                succeeded = False
        if succeeded and not test_ok:
            if not download_file(mirror["test"], test_dest):
                succeeded = False

        if succeeded and os.path.exists(train_dest) and os.path.exists(test_dest):
            print(f"[+] All NSL-KDD files ready at {DATA_DIR}")
            return

    raise RuntimeError("Failed to download NSL-KDD dataset from all mirrors. Check network connection.")


if __name__ == "__main__":
    ensure_nslkdd_dataset()
