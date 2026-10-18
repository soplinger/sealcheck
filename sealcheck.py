#!/usr/bin/env python3
"""sealcheck: offline directory integrity manifests.

Seal a directory tree into one JSON manifest of file sizes and digests, then
verify, update or summarise that tree later. Standard library only, no network.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

FORMAT_VERSION = 1
ALGORITHMS = ("sha256", "sha512", "sha3-256", "blake2b")
DEFAULT_ALGORITHM = "sha256"
CHUNK_SIZE = 1 << 20
IGNORE_FILE = ".sealignore"

EXIT_OK = 0
EXIT_DIFFERENT = 1
EXIT_ERROR = 2


class SealError(Exception):
    """Bad input: an unreadable or invalid manifest, or a path that is not a directory."""


# --- hashing and walking ----------------------------------------------------

def new_hash(algorithm):
    """hashlib object for a CLI algorithm name, e.g. 'sha3-256' -> hashlib 'sha3_256'."""
    return hashlib.new(algorithm.replace("-", "_"))


def hash_file(path, algorithm):
    """Return the hex digest of a file, read in 1 MiB chunks so big files stay cheap."""
    digest = new_hash(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


class IgnoreRules:
    """Glob rules. A pattern matches a path's full relative form or its basename."""

    def __init__(self, patterns=()):
        cleaned = (p.strip() for p in patterns)
        # dict.fromkeys keeps first-seen order while dropping repeats
        self.patterns = list(dict.fromkeys(p for p in cleaned if p and not p.startswith("#")))

    @classmethod
    def from_root(cls, root, extra=()):
        patterns = list(extra)
        ignore_file = Path(root) / IGNORE_FILE
        if ignore_file.is_file():
            patterns += ignore_file.read_text(encoding="utf-8").splitlines()
        return cls(patterns)

    def matches(self, rel):
        name = rel.rsplit("/", 1)[-1]
        return any(
            fnmatch.fnmatchcase(rel, pat) or fnmatch.fnmatchcase(name, pat)
            for pat in self.patterns
        )


def _abs(path):
    return os.path.abspath(str(path))


def iter_files(root, ignore, follow_symlinks=False, skip=()):
    """Map relative POSIX path -> absolute Path for every sealable file, sorted by path.

    Symlinked directories are never descended into. Symlinked files are skipped
    unless follow_symlinks is set. Anything that is not a regular file (broken
    links, sockets, FIFOs) is skipped. Absolute paths in `skip` are left out.
    """
    root = Path(root)
    skip = {_abs(p) for p in skip}
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            full = here / d
            if full.is_symlink() or ignore.matches(full.relative_to(root).as_posix()):
                continue
            kept.append(d)
        dirnames[:] = kept
        for f in sorted(filenames):
            full = here / f
            rel = full.relative_to(root).as_posix()
            if ignore.matches(rel) or _abs(full) in skip:
                continue
            if full.is_symlink() and not follow_symlinks:
                continue
            if full.is_file():
                found[rel] = full
    return dict(sorted(found.items()))


def snapshot(root, algorithm, ignore, follow_symlinks=False, skip=()):
    """Hash every sealable file under root. Returns rel path -> {size, digest}."""
    entries = {}
    for rel, full in iter_files(root, ignore, follow_symlinks, skip).items():
        entries[rel] = {"size": full.stat().st_size, "digest": hash_file(full, algorithm)}
    return entries


# --- manifests --------------------------------------------------------------

def make_manifest(entries, algorithm, ignore_patterns):
    return {
        "format": FORMAT_VERSION,
        "algorithm": algorithm,
        "sealed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "ignore": list(ignore_patterns),
        "file_count": len(entries),
        "total_bytes": sum(e["size"] for e in entries.values()),
        "files": entries,
    }


def save_manifest(path, manifest):
    """Write the manifest via a temp file and os.replace, so a crash never leaves half a file."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _safe_relpath(rel):
    if not isinstance(rel, str) or not rel or rel.startswith("/"):
        return False
    return all(part not in ("", ".", "..") for part in rel.split("/"))


def load_manifest(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SealError(f"cannot read manifest {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SealError(f"{path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}") from exc
    return _validate(data, path)


def _validate(data, source):
    def bad(msg):
        return SealError(f"{source}: invalid manifest: {msg}")

    if not isinstance(data, dict):
        raise bad("top level must be a JSON object")
    if data.get("format") != FORMAT_VERSION:
        raise bad(f"unsupported format {data.get('format')!r}, expected {FORMAT_VERSION}")
    algorithm = data.get("algorithm")
    if algorithm not in ALGORITHMS:
        raise bad(f"unknown algorithm {algorithm!r}")
    ignore = data.get("ignore", [])
    if not isinstance(ignore, list) or not all(isinstance(p, str) for p in ignore):
        raise bad("'ignore' must be a list of strings")
    files = data.get("files")
    if not isinstance(files, dict):
        raise bad("'files' must be an object")
    digest_len = new_hash(algorithm).digest_size * 2
    for rel, entry in files.items():
        if not _safe_relpath(rel):
            raise bad(f"unsafe path {rel!r}")
        if not isinstance(entry, dict) or type(entry.get("size")) is not int or entry["size"] < 0:
            raise bad(f"{rel}: 'size' must be a non-negative integer")
        digest = entry.get("digest")
        if (not isinstance(digest, str) or len(digest) != digest_len
                or any(c not in "0123456789abcdef" for c in digest)):
            raise bad(f"{rel}: 'digest' must be {digest_len} lowercase hex characters")
    return data


# --- comparing --------------------------------------------------------------

@dataclass
class Report:
    algorithm: str
    unchanged: list = field(default_factory=list)
    modified: list = field(default_factory=list)  # (path, reason) pairs
    missing: list = field(default_factory=list)
    added: list = field(default_factory=list)

    @property
    def clean(self):
        return not (self.modified or self.missing or self.added)

    def summary_line(self):
        verdict = "clean" if self.clean else "DIFFERENT"
        counts = (f"{len(self.unchanged)} ok, {len(self.modified)} modified, "
                  f"{len(self.missing)} missing, {len(self.added)} added")
        return f"sealcheck: {verdict} ({self.algorithm}): {counts}"

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "clean": self.clean,
            "unchanged": self.unchanged,
            "modified": [{"path": p, "reason": r} for p, r in self.modified],
            "missing": self.missing,
            "added": self.added,
        }


def _describe_change(old, new):
    if old["size"] != new["size"]:
        return f"size {old['size']} -> {new['size']}"
    return "digest changed"


def verify(manifest, root, ignore, follow_symlinks=False, skip=()):
    """Compare a tree with a manifest. Sizes are checked before hashing to save time."""
    algorithm = manifest["algorithm"]
    expected = manifest["files"]
    actual = iter_files(root, ignore, follow_symlinks, skip)
    report = Report(algorithm)
    for rel in sorted(expected):
        full = actual.get(rel)
        if full is None:
            report.missing.append(rel)
            continue
        want = expected[rel]
        size = full.stat().st_size
        if size != want["size"]:
            report.modified.append((rel, f"size {want['size']} -> {size}"))
        elif hash_file(full, algorithm) != want["digest"]:
            report.modified.append((rel, "digest changed"))
        else:
            report.unchanged.append(rel)
    report.added = sorted(set(actual) - set(expected))
    return report


def diff_entries(algorithm, old, new):
    """Compare two already-hashed snapshots. Used by `update` to describe what changed."""
    report = Report(algorithm)
    for rel in sorted(old):
        if rel not in new:
            report.missing.append(rel)
        elif old[rel] != new[rel]:
            report.modified.append((rel, _describe_change(old[rel], new[rel])))
        else:
            report.unchanged.append(rel)
    report.added = sorted(set(new) - set(old))
    return report


# --- output -----------------------------------------------------------------

def _human(num):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if num < 1024 or unit == "GiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num} B"


def print_report(report, as_json=False, verbose=False):
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return
    print(report.summary_line())
    for rel, reason in report.modified:
        print(f"  modified  {rel}  ({reason})")
    for rel in report.missing:
        print(f"  missing   {rel}")
    for rel in report.added:
        print(f"  added     {rel}")
    if verbose:
        for rel in report.unchanged:
            print(f"  ok        {rel}")


# --- commands ---------------------------------------------------------------

def check_root(path):
    if not Path(path).is_dir():
        raise SealError(f"not a directory: {path}")
    return Path(path)


def cmd_seal(args):
    root = check_root(args.root)
    ignore = IgnoreRules.from_root(root, args.exclude)
    entries = snapshot(root, args.algorithm, ignore, args.follow_symlinks, skip={args.output})
    save_manifest(args.output, make_manifest(entries, args.algorithm, ignore.patterns))
    print(f"sealed {len(entries)} files ({_human(sum(e['size'] for e in entries.values()))}) "
          f"with {args.algorithm} -> {args.output}")
    return EXIT_OK


def cmd_verify(args):
    root = check_root(args.root)
    manifest = load_manifest(args.manifest)
    ignore = IgnoreRules(manifest["ignore"] + args.exclude)
    report = verify(manifest, root, ignore, args.follow_symlinks, skip={args.manifest})
    print_report(report, as_json=args.json, verbose=args.verbose)
    return EXIT_OK if report.clean else EXIT_DIFFERENT


def cmd_update(args):
    root = check_root(args.root)
    old = load_manifest(args.manifest)
    ignore = IgnoreRules.from_root(root, old["ignore"] + args.exclude)
    entries = snapshot(root, old["algorithm"], ignore, args.follow_symlinks, skip={args.manifest})
    report = diff_entries(old["algorithm"], old["files"], entries)
    print(f"sealcheck: {len(report.added)} added, {len(report.modified)} changed, "
          f"{len(report.missing)} removed, {len(report.unchanged)} unchanged")
    for rel, reason in report.modified:
        print(f"  changed   {rel}  ({reason})")
    for rel in report.missing:
        print(f"  removed   {rel}")
    for rel in report.added:
        print(f"  added     {rel}")
    if args.dry_run:
        print("dry run: manifest not written")
    else:
        save_manifest(args.manifest, make_manifest(entries, old["algorithm"], ignore.patterns))
        print(f"updated {args.manifest}")
    return EXIT_OK


def cmd_show(args):
    manifest = load_manifest(args.manifest)
    files = manifest["files"]
    total = sum(e["size"] for e in files.values())
    print(f"manifest:    {args.manifest}")
    print(f"algorithm:   {manifest['algorithm']}")
    print(f"sealed at:   {manifest.get('sealed_at', 'unknown')}")
    print(f"files:       {len(files)}")
    print(f"total size:  {_human(total)}")
    print(f"ignore:      {', '.join(manifest['ignore']) or '(none)'}")
    return EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sealcheck",
        description="Offline directory integrity manifests: seal, verify, update and show.",
        epilog="exit status: 0 clean, 1 differences found, 2 error",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                       help="extra ignore pattern (repeatable)")
        p.add_argument("--follow-symlinks", action="store_true",
                       help="hash symlinked files as their targets")

    p = sub.add_parser("seal", help="hash a directory into a new manifest")
    p.add_argument("root", help="directory to seal")
    p.add_argument("-o", "--output", required=True, help="manifest file to write")
    p.add_argument("-a", "--algorithm", choices=ALGORITHMS, default=DEFAULT_ALGORITHM)
    add_common(p)
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("verify", help="check a directory against a manifest")
    p.add_argument("root", help="directory to check")
    p.add_argument("-m", "--manifest", required=True, help="manifest to check against")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="also list unchanged files")
    add_common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("update", help="re-seal a directory, keeping its algorithm")
    p.add_argument("root", help="directory to re-seal")
    p.add_argument("-m", "--manifest", required=True, help="manifest to rewrite")
    p.add_argument("--dry-run", action="store_true", help="show changes without writing")
    add_common(p)
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("show", help="summarise a manifest")
    p.add_argument("manifest", help="manifest to summarise")
    p.set_defaults(func=cmd_show)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (SealError, OSError) as exc:
        print(f"sealcheck: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
