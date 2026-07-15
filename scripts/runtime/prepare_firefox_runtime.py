"""Extract and verify the hash-pinned Firefox NSS runtime on Windows."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class RuntimePreparationError(Exception):
    pass


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _verify_file(path, expected_size, expected_hash):
    return (
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size == expected_size
        and _sha256(path) == expected_hash
    )


def _load_lock(path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimePreparationError("could not read pinned runtime lock") from exc
    if document.get("schema_version") != 1:
        raise RuntimePreparationError("unsupported pinned runtime lock schema")
    if document.get("platform") != "windows-x86_64":
        raise RuntimePreparationError("pinned runtime lock platform mismatch")
    if document.get("source_id") != "firefox-windows-x86_64-en-us":
        raise RuntimePreparationError("pinned runtime source identity mismatch")
    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimePreparationError("pinned runtime file list is empty")
    names = set()
    for entry in files:
        name = entry.get("filename") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        size = entry.get("size") if isinstance(entry, dict) else None
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
            or name in names
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise RuntimePreparationError("invalid pinned runtime file entry")
        names.add(name)
    return document


def _under(path, root, label):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    root = root.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(path))))
    except ValueError as exc:
        raise RuntimePreparationError(label + " must be under " + str(root)) from exc
    if common != root:
        raise RuntimePreparationError(label + " must be under " + str(root))
    return path


def prepare_runtime(installer, output, lock, repository=None, runner=None):
    if os.name != "nt":
        raise RuntimePreparationError("Firefox installer extraction requires Windows")
    repository = Path(repository or Path(__file__).parents[2]).resolve()
    cache_root = (repository / ".cache" / "firefox-runtime").resolve()
    output = _under(output, cache_root, "runtime output")
    if output.exists():
        raise RuntimePreparationError("runtime output must not already exist")

    lock_document = _load_lock(Path(lock))
    installer = Path(installer).resolve()
    if not _verify_file(
        installer,
        lock_document.get("source_size"),
        lock_document.get("source_sha256"),
    ):
        raise RuntimePreparationError("Firefox installer does not match the lock")

    cache_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(cache_root)))
    created_output = False
    runner = runner or subprocess.run
    try:
        command = [str(installer), "/ExtractDir=" + str(temporary)]
        try:
            completed = runner(command, check=False, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimePreparationError("Firefox installer extraction failed") from exc
        if completed.returncode != 0:
            raise RuntimePreparationError(
                "Firefox installer extraction returned {}".format(completed.returncode)
            )

        source_root = temporary / "core"
        for entry in lock_document["files"]:
            if not _verify_file(
                source_root / entry["filename"], entry["size"], entry["sha256"]
            ):
                raise RuntimePreparationError(
                    "extracted runtime file does not match lock: " + entry["filename"]
                )

        output.mkdir(parents=True)
        created_output = True
        for entry in lock_document["files"]:
            source = source_root / entry["filename"]
            destination = output / entry["filename"]
            with source.open("rb") as input_file, destination.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            if not _verify_file(destination, entry["size"], entry["sha256"]):
                raise RuntimePreparationError(
                    "prepared runtime file does not match lock: " + entry["filename"]
                )
    except Exception:
        if created_output:
            shutil.rmtree(str(output), ignore_errors=True)
        raise
    finally:
        shutil.rmtree(str(temporary), ignore_errors=True)

    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".cache/firefox-runtime/core"))
    parser.add_argument(
        "--lock", type=Path, default=Path("third_party/firefox-windows-runtime.lock.json")
    )
    args = parser.parse_args(argv)
    try:
        output = prepare_runtime(args.installer, args.output, args.lock)
    except RuntimePreparationError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"runtime": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
