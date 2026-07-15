import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.provenance.verify_sources import LockError, load_source_lock


class HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise LockError("redirect refused because it is not HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _verify_file(path, source):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return False
    if path.stat().st_size != source["size"]:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest() == source["sha256"]


def fetch_source(source, cache_dir, opener=None):
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / source["filename"]
    if _verify_file(destination, source):
        return "cached"

    opener = opener or build_opener(HTTPSOnlyRedirectHandler())
    temporary = cache / (source["filename"] + ".part-" + uuid.uuid4().hex)
    digest = hashlib.sha256()
    total = 0
    request = Request(
        source["url"],
        headers={"User-Agent": "foxreq-source-fetch/0.1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=60) as response, temporary.open("xb") as output:
            if urlsplit(response.geturl()).scheme != "https":
                raise LockError("final download URL is not HTTPS")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > source["size"]:
                    raise LockError("download exceeds locked size for " + source["id"])
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())

        if total != source["size"]:
            raise LockError(
                "size mismatch for {}: expected {}, received {}".format(
                    source["id"], source["size"], total
                )
            )
        actual_hash = digest.hexdigest()
        if actual_hash != source["sha256"]:
            raise LockError(
                "hash mismatch for {}: expected {}, received {}".format(
                    source["id"], source["sha256"], actual_hash
                )
            )
        os.replace(str(temporary), str(destination))
        return "downloaded"
    except (HTTPError, URLError, OSError) as exc:
        raise LockError("download failed for {}: {}".format(source["id"], exc)) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="fetch checksum-pinned foxreq inputs")
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=Path(".cache/sources"))
    parser.add_argument("--id", action="append", dest="source_ids")
    args = parser.parse_args(argv)

    try:
        sources = load_source_lock(args.lock)
        selected = args.source_ids or list(sources)
        unknown = sorted(set(selected) - set(sources))
        if unknown:
            raise LockError("unknown source ids: " + ", ".join(unknown))
        results = {
            source_id: fetch_source(sources[source_id], args.cache)
            for source_id in selected
        }
    except LockError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps({"sources": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
