import hashlib
import json
import os

import pytest

import sealcheck as sc


def write(path, text, mode="w"):
    path.parent.mkdir(parents=True, exist_ok=True)
    if "b" in mode:
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    write(root / "a.txt", "alpha\n")
    write(root / "docs" / "b.md", "# bee\n")
    write(root / "docs" / "deep" / "c.bin", b"\x00\x01\x02", mode="wb")
    return root


def seal(root, out, *extra):
    return sc.main(["seal", str(root), "-o", str(out), *extra])


def verify(root, manifest, *extra):
    return sc.main(["verify", str(root), "-m", str(manifest), *extra])


def test_hash_file_matches_hashlib(tmp_path):
    data = b"x" * (sc.CHUNK_SIZE + 17)  # spans more than one read chunk
    path = write(tmp_path / "big.bin", data, mode="wb")
    assert sc.hash_file(path, "sha256") == hashlib.sha256(data).hexdigest()
    assert sc.hash_file(path, "blake2b") == hashlib.blake2b(data).hexdigest()


def test_update_does_not_duplicate_ignore_patterns(tree, tmp_path):
    write(tree / ".sealignore", "*.log\n")
    manifest = tmp_path / "m.json"
    seal(tree, manifest)
    for _ in range(2):
        assert sc.main(["update", str(tree), "-m", str(manifest)]) == sc.EXIT_OK
    assert sc.load_manifest(manifest)["ignore"] == ["*.log"]


def test_sha3_algorithm_name_is_accepted(tmp_path):
    data = b"sponge"
    path = write(tmp_path / "s.bin", data, mode="wb")
    assert sc.hash_file(path, "sha3-256") == hashlib.sha3_256(data).hexdigest()


def test_ignore_rules_match_basename_and_full_path():
    rules = sc.IgnoreRules(["*.log", "build", "docs/*.tmp", "# comment", "  "])
    assert rules.matches("app.log")
    assert rules.matches("nested/dir/app.log")
    assert rules.matches("build")
    assert rules.matches("docs/x.tmp")
    assert not rules.matches("docs/x.md")
    assert rules.patterns == ["*.log", "build", "docs/*.tmp"]


def test_sealignore_file_is_read_and_comments_ignored(tree):
    write(tree / ".sealignore", "# skip logs\n*.log\n\ndocs/deep\n")
    write(tree / "run.log", "noise")
    rules = sc.IgnoreRules.from_root(tree)
    files = sc.iter_files(tree, rules)
    assert list(files) == [".sealignore", "a.txt", "docs/b.md"]


def test_iter_files_is_sorted_and_prunes_ignored_dirs(tree):
    write(tree / "cache" / "x.txt", "x")
    files = sc.iter_files(tree, sc.IgnoreRules(["cache"]))
    assert list(files) == sorted(files)
    assert "cache/x.txt" not in files
    assert "docs/deep/c.bin" in files


def test_seal_then_verify_is_clean(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    assert seal(tree, manifest) == sc.EXIT_OK
    assert verify(tree, manifest) == sc.EXIT_OK
    assert "clean" in capsys.readouterr().out


def test_same_size_edit_is_caught_by_digest(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    seal(tree, manifest)
    write(tree / "a.txt", "ALPHA\n")  # same length, different bytes
    assert verify(tree, manifest) == sc.EXIT_DIFFERENT
    out = capsys.readouterr().out
    assert "modified  a.txt  (digest changed)" in out


def test_size_change_is_reported_without_hashing(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    seal(tree, manifest)
    write(tree / "a.txt", "alpha and more\n")
    assert verify(tree, manifest) == sc.EXIT_DIFFERENT
    assert "size 6 -> 15" in capsys.readouterr().out


def test_missing_and_added_files_are_reported(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    seal(tree, manifest)
    capsys.readouterr()  # drop the seal message so only the report is parsed
    (tree / "docs" / "b.md").unlink()
    write(tree / "new.txt", "hello")
    assert verify(tree, manifest, "--json") == sc.EXIT_DIFFERENT
    report = json.loads(capsys.readouterr().out)
    assert report["clean"] is False
    assert report["missing"] == ["docs/b.md"]
    assert report["added"] == ["new.txt"]
    assert report["modified"] == []


def test_manifest_inside_tree_is_not_sealed_into_itself(tree):
    manifest = tree / "manifest.json"
    assert seal(tree, manifest) == sc.EXIT_OK
    assert "manifest.json" not in sc.load_manifest(manifest)["files"]
    assert verify(tree, manifest) == sc.EXIT_OK


def test_symlinks_are_skipped_unless_followed(tree, tmp_path):
    target = write(tmp_path / "outside.txt", "outside")
    os.symlink(target, tree / "link.txt")
    skipped = sc.iter_files(tree, sc.IgnoreRules())
    assert "link.txt" not in skipped
    followed = sc.iter_files(tree, sc.IgnoreRules(), follow_symlinks=True)
    assert "link.txt" in followed


def test_update_rewrites_manifest_and_dry_run_does_not(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    seal(tree, manifest)
    before = manifest.read_text(encoding="utf-8")
    write(tree / "a.txt", "changed!\n")
    (tree / "docs" / "b.md").unlink()
    write(tree / "fresh.txt", "new")

    assert sc.main(["update", str(tree), "-m", str(manifest), "--dry-run"]) == sc.EXIT_OK
    assert manifest.read_text(encoding="utf-8") == before
    assert "dry run" in capsys.readouterr().out

    assert sc.main(["update", str(tree), "-m", str(manifest)]) == sc.EXIT_OK
    assert verify(tree, manifest) == sc.EXIT_OK
    assert sorted(sc.load_manifest(manifest)["files"]) == ["a.txt", "docs/deep/c.bin", "fresh.txt"]


def test_save_manifest_leaves_no_temp_files(tmp_path):
    out = tmp_path / "m.json"
    sc.save_manifest(out, {"format": 1})
    assert sorted(p.name for p in tmp_path.iterdir()) == ["m.json"]


def test_load_manifest_reports_json_position(tmp_path):
    bad = write(tmp_path / "bad.json", '{\n  "format": 1,\n  oops\n}')
    with pytest.raises(sc.SealError, match=r"bad\.json:3:3: invalid JSON"):
        sc.load_manifest(bad)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda m: m.update(algorithm="md5"), "unknown algorithm"),
        (lambda m: m.update(format=99), "unsupported format"),
        (lambda m: m["files"].update({"../escape": {"size": 1, "digest": "0" * 64}}), "unsafe path"),
        (lambda m: m["files"].update({"x": {"size": -1, "digest": "0" * 64}}), "'size'"),
        (lambda m: m["files"].update({"x": {"size": 1, "digest": "ZZ"}}), "'digest'"),
    ],
)
def test_load_manifest_rejects_invalid_content(tmp_path, mutate, message):
    manifest = {"format": 1, "algorithm": "sha256", "ignore": [], "files": {}}
    mutate(manifest)
    path = write(tmp_path / "m.json", json.dumps(manifest))
    with pytest.raises(sc.SealError, match=message):
        sc.load_manifest(path)


def test_bad_arguments_exit_with_error_code(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    assert seal(tree / "nope", manifest) == sc.EXIT_ERROR
    assert "not a directory" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        sc.main(["seal", str(tree), "-o", str(manifest), "-a", "md5"])
    assert exc.value.code == 2


def test_show_summarises_manifest(tree, tmp_path, capsys):
    manifest = tmp_path / "m.json"
    seal(tree, manifest, "--exclude", "*.bin")
    assert sc.main(["show", str(manifest)]) == sc.EXIT_OK
    out = capsys.readouterr().out
    assert "algorithm:   sha256" in out
    assert "files:       2" in out
    assert "ignore:      *.bin" in out
