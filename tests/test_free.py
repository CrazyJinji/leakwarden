"""Tests for the free edition. Fake keys are assembled at runtime so this file holds no key-shaped strings."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(ROOT, "leakwarden.py")
STRIPE = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
GITHUB = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false"] + list(args), check=True, capture_output=True)


def scan(path, *args):
    r = subprocess.run([sys.executable, "-I", SCANNER, str(path), "--format", "json", "--fail-on", "never"] + list(args),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout), r.stdout


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("node_modules\n")
    (tmp_path / "config.js").write_text("export const token = '%s'\n" % GITHUB)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    (tmp_path / "config.js").unlink()
    (tmp_path / "pay.ts").write_text("const stripe = new Stripe('%s')\n" % STRIPE)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "move key")
    return tmp_path


def test_finds_keys_in_files_and_in_history(repo):
    data, _ = scan(repo)
    found = {(f["rule"], f["source"]) for f in data["findings"]}
    assert ("secret.stripe_live", "tree") in found
    assert ("secret.github", "history") in found
    assert data["edition"] == "free"


def test_never_prints_secret_values(repo):
    _, raw = scan(repo)
    assert STRIPE not in raw and GITHUB not in raw
    assert "[REDACTED:" in raw


def test_no_history_flag(repo):
    data, _ = scan(repo, "--no-history")
    assert all(f["source"] == "tree" for f in data["findings"])
    assert data["coverage"]["secrets (git history)"].startswith("skipped")


def test_public_only_env_is_low(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".env").write_text("VITE_SUPABASE_URL=https://abcdefghij.supabase.co\nVITE_SUPABASE_PROJECT_ID=abcdefghij\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    data, _ = scan(tmp_path)
    env = [f for f in data["findings"] if f["rule"] == "env.committed"]
    assert [f["severity"] for f in env] == ["low"]


def test_ignore_comment_and_file(repo):
    (repo / "pay.ts").write_text("const stripe = new Stripe('%s') // leakwarden:ignore\n" % STRIPE)
    (repo / ".leakwardenignore").write_text("rule:secret.github\n")
    data, _ = scan(repo)
    found = {(f["rule"], f["source"]) for f in data["findings"]}
    assert ("secret.stripe_live", "tree") not in found and ("secret.github", "history") not in found
    # The comment only covers lines that carry it. The commit that added the key without the
    # comment is still in history, and that is still reported.
    assert ("secret.stripe_live", "history") in found


def test_reports_what_it_did_not_check(repo):
    data, _ = scan(repo)
    assert data["coverage"]["supabase row level security"].startswith("not included in the free edition")


def test_version():
    r = subprocess.run([sys.executable, "-I", SCANNER, "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "(free edition)" in r.stdout
