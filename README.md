# sealcheck

**Offline directory integrity manifests.** Seal a folder tree into one JSON file of sizes and digests, then verify, update or summarise it later. Standard library only, no network, no accounts.

sealcheck answers one question quickly: *has anything in this tree changed since I sealed it?* It reports modified, missing and unexpected files, and exits with a status code your scripts or CI can act on.

## Features

- **Seal a tree** into a single JSON manifest with SHA-256 by default, or SHA-512, SHA3-256 or BLAKE2b.
- **Verify a tree** against a manifest and report each file as unchanged, modified, missing or added.
- **Size fast path**: a file whose size changed is flagged without reading its contents.
- **Streaming hashes** read 1 MiB at a time, so multi-gigabyte files use constant memory.
- **Ignore rules** in a `.sealignore` file and/or `--exclude` flags, matched by basename or relative-path glob. Ignored directories are pruned, not walked.
- **Rules travel with the manifest**: `seal` records the patterns it used, so `verify` checks the tree the same way.
- **Self-exclusion**: a manifest stored inside the tree it seals is never hashed into itself.
- **Update in place** with `update`, which re-seals the tree and prints what changed. `--dry-run` previews the changes without writing.
- **Atomic manifest writes** through a temp file and `os.replace`, so an interrupted run never leaves a half-written manifest.
- **Symlink safety**: symlinked directories are never followed (no loops), and symlinked files are skipped unless you pass `--follow-symlinks`.
- **Text or JSON reports**: `--json` gives scripts a stable, sorted report; `-v` also lists unchanged files.
- **CI exit codes**: `0` clean, `1` differences found, `2` usage or manifest error.
- **Manifest validation** with `file:line:col` for JSON syntax errors and clear messages for bad algorithms, digests, sizes and unsafe paths such as `../x`.
- **`show`** summarises a manifest: algorithm, seal time, file count, total size and ignore rules.

## Quick start

```bash
mkdir demo && echo hello > demo/a.txt       # 6 bytes
python3 sealcheck.py seal demo -o demo.seal.json
```

```text
sealed 1 files (6 B) with sha256 -> demo.seal.json
```

Later, after an edit:

```bash
echo "hello!" > demo/a.txt                  # 7 bytes
python3 sealcheck.py verify demo -m demo.seal.json
echo "exit status: $?"
```

```text
sealcheck: DIFFERENT (sha256): 0 ok, 1 modified, 0 missing, 0 added
  modified  a.txt  (size 6 -> 7)
exit status: 1
```

Accept the change and re-seal:

```bash
python3 sealcheck.py update demo -m demo.seal.json
```

```text
sealcheck: 0 added, 1 changed, 0 removed, 0 unchanged
  changed   a.txt  (size 6 -> 7)
updated demo.seal.json
```

## How to run

Requires Python 3.8 or newer. Nothing to install.

```bash
python3 sealcheck.py --help
python3 sealcheck.py seal DIR -o MANIFEST [-a sha256|sha512|sha3-256|blake2b] [--exclude GLOB] [--follow-symlinks]
python3 sealcheck.py verify DIR -m MANIFEST [--json] [-v] [--exclude GLOB] [--follow-symlinks]
python3 sealcheck.py update DIR -m MANIFEST [--dry-run] [--exclude GLOB] [--follow-symlinks]
python3 sealcheck.py show MANIFEST
```

### Ignore rules

Put patterns in `DIR/.sealignore`, one per line. Blank lines and lines starting with `#` are skipped.

```text
# build output and editor junk
build
*.log
*.tmp
docs/drafts/*
```

A pattern matches a path's full relative form (`docs/drafts/x.md`) or its basename (`app.log` anywhere in the tree). `*` also crosses `/`, so `docs/*` covers nested folders too.

### Using it in CI

```yaml
- name: Check release artifacts are unchanged
  run: python3 sealcheck.py verify dist -m dist.seal.json
```

A non-zero exit fails the step. Use `--json` when another tool needs to read the result.

## How to test

Tests use pytest, the only third-party dependency.

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

The suite covers hashing against `hashlib`, ignore matching and pruning, `.sealignore` parsing, sorted walks, clean and dirty verification, digest versus size detection, missing and added files, self-exclusion, symlink handling, `update` and `--dry-run`, atomic writes, JSON error positions, manifest validation and CLI exit codes.

## Manifest format

```json
{
  "algorithm": "sha256",
  "file_count": 1,
  "files": {
    "a.txt": {"digest": "<64 hex characters>", "size": 6}
  },
  "format": 1,
  "ignore": ["*.log"],
  "sealed_at": "2026-10-18T05:30:00+00:00",
  "total_bytes": 6
}
```

Keys are sorted so diffs between manifests stay readable. Paths are relative and always use `/`.

## Limits

- Only the content and size of regular files are recorded. Permissions, owners and timestamps are not.
- A manifest is an integrity record, not a signature. Anyone who can rewrite the manifest can rewrite the digests. Store it somewhere the tree's writers cannot reach if you need tamper evidence.
- Symlinked directories are never descended into, even with `--follow-symlinks`.
