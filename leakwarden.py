#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# LeakWarden free edition. Copyright (c) 2026 Leon Krasnik. License text: https://leakwarden.dev/download/LICENSE
"""leakwarden (free edition): find leaked secrets before you deploy.

Single file, standard library only, Python 3.8+.

The free edition finds API keys, tokens, passwords and database URLs in your
files and in git history (keys you deleted but never rotated), and .env files
that are committed or not ignored. LeakWarden Pro (https://leakwarden.dev) adds
Supabase row level security, webhooks, payments, keys exposed to the browser,
framework settings, a Claude Code skill and a GitHub Actions workflow.

It is a heuristic scanner. A clean report does not mean the project is secure,
and the report says which areas it did not assess.
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import html
import json
import math
import os
import re
import subprocess
import stat
import sys
import time
from dataclasses import dataclass, asdict, field

__version__ = "0.2.1"
EDITION = "free"

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

SKIP_DIRS = {
    ".git", "node_modules", ".next", ".nuxt", ".svelte-kit", "dist", "build", "out",
    ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
    ".turbo", ".vercel", ".cache", "vendor", "target", ".idea", ".vscode",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "bun.lockb", "uv.lock", "go.sum",
}
SKIP_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".svg", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".mp3", ".mov", ".wasm", ".so", ".dll", ".exe", ".class", ".jar", ".pyc",
)
CODE_SUFFIXES = (
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".py", ".go", ".rb", ".php", ".java", ".cs", ".kt", ".swift",
)
JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro")
MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 2000


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    advice: str
    source: str = "tree"  # tree | history
    commit: str = ""
    vh: str = field(default="", repr=False)  # hash of a secret value, never printed


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


PLACEHOLDER_WORDS = (
    "example", "your", "xxxx", "changeme", "placeholder", "dummy", "sample", "redacted",
    "<", ">", "${", "{{", "%s", "todo", "insert", "replace", "fake",
)


def looks_placeholder(value: str) -> bool:
    low = value.lower()
    if any(w in low for w in PLACEHOLDER_WORDS):
        return True
    if len(set(value)) <= 3:
        return True
    return False


def redact(line: str, spans, rule: str) -> str:
    out = line
    for start, end in sorted(spans, reverse=True):
        out = out[:start] + "[REDACTED:" + rule + "]" + out[end:]
    out = out.strip()
    if len(out) > 160:
        out = out[:157] + "..."
    return out


GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.quotepath=false", "-c", "core.hooksPath=" + os.devnull,
            "-c", "log.showSignature=false", "-c", "diff.external=", "-c", "gpg.program=false",
            "-c", "gpg.ssh.program=false", "-c", "gpg.x509.program=false", "-c", "gpg.openpgp.program=false",
            "-c", "core.pager=cat", "-c", "core.sshCommand=false"]


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    return env


def redact_all(line: str) -> str:
    if len(line) > MAX_LINE_CHARS:
        line = line[:MAX_LINE_CHARS]
    return redact(line, [h[3] for h in scan_line_for_secrets(line, False)], "redacted")


def run_git(root: str, args, timeout: int = 120):
    cmd = ["git", "-C", root] + GIT_SAFE + list(args)
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=git_env())
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout.decode("utf-8", "replace")


def unquote_git_path(p: str) -> str:
    """Undo git's C-style quoting and the trailing TAB it adds after names with spaces."""
    if p.startswith('"') and p.endswith('"') and len(p) >= 2:
        body = p[1:-1]
        esc = {"t": "\t", "n": "\n", '"': '"', "\\": "\\"}
        raw = bytearray()
        i = 0
        while i < len(body):
            c = body[i]
            if c == "\\" and i + 1 < len(body):
                if body[i + 1] in "01234567" and i + 3 < len(body) + 0 and body[i + 1:i + 4].isdigit():
                    raw.append(int(body[i + 1:i + 4], 8))
                    i += 4
                    continue
                raw += esc.get(body[i + 1], body[i + 1]).encode()
                i += 2
                continue
            raw += c.encode("utf-8", "surrogateescape")
            i += 1
        return raw.decode("utf-8", "replace")
    return p.rstrip("\t")


def is_git_repo(root: str) -> bool:
    return run_git(root, ["rev-parse", "--is-inside-work-tree"]) is not None


def want_file(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False
    name = parts[-1]
    if name in SKIP_FILES:
        return False
    if name.lower().endswith(SKIP_SUFFIXES):
        return False
    return True


def list_files(root: str):
    """Return (relative paths, tracked set or None). Uses git when available so that
    gitignored files are not reported as leaks."""
    files = None
    tracked = None
    if is_git_repo(root):
        out = run_git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        cached = run_git(root, ["ls-files", "-z", "--cached"])
        if out is not None:
            files = [p for p in out.split("\0") if p]
            tracked = set(p for p in (cached or "").split("\0") if p)
    if files is None:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                files.append(os.path.relpath(full, root))
    files = sorted(set(f.replace("\\", "/") for f in files if want_file(f)))
    return files, tracked


def read_text(path: str):
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            data = fh.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")


# ----------------------------------------------------------------------------
# secret detection
# ----------------------------------------------------------------------------

# (rule id, title, regex, severity)
KNOWN_SECRETS = [
    ("secret.aws_access_key", "AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("secret.stripe_live", "Stripe live secret key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b", "high"),
    ("secret.stripe_test", "Stripe test secret key", r"\bsk_test_[0-9A-Za-z]{16,}\b", "low"),
    ("secret.stripe_webhook", "Stripe webhook signing secret", r"\bwhsec_[0-9A-Za-z+/=]{16,}\b", "high"),
    ("secret.anthropic", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{32,}\b", "high"),
    ("secret.openrouter", "OpenRouter API key", r"\bsk-or-v1-[0-9a-f]{64}\b", "high"),
    ("secret.openai", "OpenAI API key", r"\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b", "high"),
    ("secret.github", "GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b", "high"),
    ("secret.slack", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "high"),
    ("secret.sendgrid", "SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "high"),
    ("secret.private_key", "Private key block", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", "high"),
    ("secret.supabase_secret", "Supabase secret key (sb_secret_)", r"\bsb_secret_[A-Za-z0-9_-]{20,}\b", "high"),
    ("secret.polar", "Polar token or webhook secret", r"\bpolar_(?:oat|whs)_[A-Za-z0-9]{16,}\b", "high"),
    ("secret.google_api_key", "Google API key (may be public by design, check restrictions)",
     r"\bAIza[0-9A-Za-z_-]{35}\b", "low"),
]
KNOWN_SECRETS_C = [(r, t, re.compile(rx), sev) for r, t, rx, sev in KNOWN_SECRETS]

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
DB_URL_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://"
    r"([^\s:@/\"'`]+):([^\s@/\"'`]{3,})@([^\s/:\"'`]+)"
)
GENERIC_ASSIGN_RE = re.compile(
    r"""(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,80})["']?\s*[:=]\s*["']([^"'\s]{16,})["']"""
)
GENERIC_NAME_RE = re.compile(r"(?i)secret|passw(?:or)?d|token|api[_-]?key|private[_-]?key|auth[_-]?key|access[_-]?key")
ENVFILE_ASSIGN_RE = re.compile(
    r"""(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*([^\s#"']{16,})\s*$"""
)
SAFE_DB_HOSTS = {"localhost", "127.0.0.1", "db", "postgres", "mysql", "redis", "host.docker.internal"}


def decode_jwt_role(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8", "replace"))
        if isinstance(data, dict) and data.get("iss") == "supabase-demo":
            return None
        return data.get("role") if isinstance(data, dict) else None
    except Exception:
        return None


def generic_value_ok(value: str) -> bool:
    if looks_placeholder(value):
        return False
    if value.startswith(("process.env", "os.environ", "import.meta", "env(", "getenv")):
        return False
    if re.match(r"(?i)https?://", value) or re.match(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-", value):
        return False
    if not (re.search(r"\d", value) and re.search(r"[A-Za-z]", value)):
        return False
    return entropy(value) >= 3.5


PASSWORD_ASSIGN_RE = re.compile(
    r"""(?i)(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{0,60}?(?:password|passwd|pwd))["']?\s*[:=]\s*["']([^"'\s]{6,64})["']"""
)
ENV_PASSWORD_RE = re.compile(
    r"""(?i)^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|PWD))\s*=\s*["']?([^\s#"']{6,64})["']?\s*$"""
)
SEED_PATH_RE = re.compile(r"(^|/)(seeds?|seeders?|fixtures?)(/|\.)|(^|/)seed[^/]*\.[a-z]+$")
PASSWORD_PREFIXES = ("$", "{", "%", "/", "#", ".", "<", "process.env", "os.environ", "os.getenv", "getenv",
                     "env(", "import.meta", "settings.", "config.")


def password_value_ok(value: str) -> bool:
    """A literal that looks like a real password: not a placeholder or a reference, and it mixes
    letters with digits or symbols (pure words are usually labels or field names)."""
    if looks_placeholder(value) or value.startswith(PASSWORD_PREFIXES):
        return False
    if re.match(r"(?i)https?://", value) or value.lower() in ("password", "passwd", "secret"):
        return False
    if not re.search(r"[A-Za-z]", value):
        return False
    # identifiers, enum values and autocomplete tokens: new-password, UPDATE_PASSWORD, current_password
    if re.fullmatch(r"[a-z]+(?:[-_][a-z0-9]+)+|[A-Z][A-Z0-9_]*", value):
        return False
    if re.fullmatch(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        return False
    # a digit or a real symbol; accented letters ("Contraseña") are letters, not symbols
    return bool(re.search(r"[0-9]", value) or any(not ch.isalnum() for ch in value))


DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc")
LOCALE_PATH_RE = re.compile(r"(^|/)(locales?|i18n|l10n|lang|langs|translations?)(/|$)", re.I)
SAMPLE_EMAIL_RE = re.compile(r"@(?:example\.(?:com|org|net)|test\.com|demo\.com|localhost)\b", re.I)
INFRA_PW_NAME_RE = re.compile(r"(?i)(?:db|database|smtp|email|mail|redis|postgres|pg|mysql|mongo|ftp|sftp|ldap|rabbit|amqp|broker|service|root|master)_?\w*(?:pass|pwd)")
LOCAL_SCRIPT_RE = re.compile(r"(^|/)(scripts?|load|loadtest|stress|bench|benchmarks?|k6|perf)(/|[-_.])|(load|stress|bench|perf)[-_]?test", re.I)
LOCALHOST_RE = re.compile(r"localhost|127\.0\.0\.1")
SAMPLE_NAME_RE = re.compile(
    r"\b(?:DEMO|TEST|SAMPLE|MOCK|DUMMY|FAKE)_[A-Z_]*\b|\b(?:demo|test|sample|mock|dummy|fake)(?:Users?|Accounts?|Credentials?|Logins?|Password)\b")
SAMPLE_PATH_RE = re.compile(r"(^|/|[-_.])(demo|mock|mocks|sample|samples|seed|seeds|test[-_]?users|test[-_]?accounts)([-_./]|$)", re.I)


def scan_line_for_secrets(line: str, is_env_file: bool, known_only: bool = False):
    """Yield (rule, severity, title, span, value) for every secret-looking thing on a line."""
    if len(line) > MAX_LINE_CHARS:
        return
    known = []
    for rule, title, rx, sev in KNOWN_SECRETS_C:
        for m in rx.finditer(line):
            val = m.group(0)
            low = val.lower()
            if "example" in low or "xxxx" in low:
                continue
            span = m.span()
            if rule == "secret.private_key":
                # a key on one line ("-----BEGIN ...-----\nMIIE...") carries its body after the header:
                # hide all of it, and tell keys apart by their body rather than the shared header
                span = (m.start(), len(line))
                val = line[m.start():]
            known.append(span)
            yield rule, sev, title, span, val
    for m in JWT_RE.finditer(line):
        role = decode_jwt_role(m.group(0))
        if role == "service_role":
            yield ("secret.supabase_service_role", "high",
                   "Supabase service_role JWT (bypasses row level security)", m.span(), m.group(0))
    for m in DB_URL_RE.finditer(line):
        user, pw, host = m.group(1), m.group(2), m.group(3)
        if (looks_placeholder(pw) or re.search(r"xxx|your|[<{\[]", host.lower()) or pw.startswith(("$", "{", "%")) or re.search(r"[\[<]", user + pw)
                or pw.lower() in {"password", "pass", "postgres", "root", "admin"}):
            continue
        sev = "low" if host.lower() in SAFE_DB_HOSTS else "high"
        yield "secret.db_url", sev, "Database connection string with a password", m.span(), m.group(0)
    if known_only:
        return
    spans = set()

    def overlaps_known(sp):
        return any(sp[0] < k[1] and k[0] < sp[1] for k in known)

    for m in GENERIC_ASSIGN_RE.finditer(line):
        val = m.group(2)
        if GENERIC_NAME_RE.search(m.group(1)) and generic_value_ok(val) and not overlaps_known(m.span(2)):
            spans.add(m.span(2))
            yield ("secret.generic", "medium",
                   "Hard-coded value assigned to '%s'" % m.group(1), m.span(2), val)
    for m in PASSWORD_ASSIGN_RE.finditer(line):
        if m.span(2) not in spans and password_value_ok(m.group(2)):
            spans.add(m.span(2))
            yield ("secret.hardcoded_password", "high",
                   "Hard-coded password assigned to '%s'" % m.group(1), m.span(2), m.group(2))
    if is_env_file:
        m = ENVFILE_ASSIGN_RE.match(line)
        if m and generic_value_ok(m.group(2)) and not overlaps_known(m.span(2)):
            spans.add(m.span(2))
            yield ("secret.generic", "medium",
                   "Secret-looking value in env file ('%s')" % m.group(1), m.span(2), m.group(2))
        m = ENV_PASSWORD_RE.match(line)
        if m and m.span(2) not in spans and password_value_ok(m.group(2)):
            yield ("secret.hardcoded_password", "high",
                   "Password in env file ('%s')" % m.group(1), m.span(2), m.group(2))


SECRET_ADVICE = ("Rotate this credential now, then load it from an environment variable or a secret "
                 "manager. Deleting it from the file does not make it safe, it may already be in git history.")


# ----------------------------------------------------------------------------
# project detection
# ----------------------------------------------------------------------------

@dataclass
class Project:
    uses_supabase: bool = False
    django: bool = False
    next_js: bool = False
    client_only: bool = False  # vite, cra, expo, plain SPA frameworks
    has_sql: bool = False
    deps: set = field(default_factory=set)


def detect_project(root: str, files) -> Project:
    p = Project()
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg):
        txt = read_text(pkg) or ""
        try:
            data = json.loads(txt)
            for key in ("dependencies", "devDependencies"):
                p.deps.update((data.get(key) or {}).keys())
        except ValueError:
            pass
    p.uses_supabase = any(d.startswith("@supabase/") for d in p.deps)
    p.django = "manage.py" in files or any(f.endswith("/manage.py") for f in files)
    p.next_js = "next" in p.deps
    p.client_only = any(d in p.deps for d in ("vite", "react-scripts", "expo", "@vitejs/plugin-react")) and not p.next_js
    for f in files:
        if f.lower().endswith(".sql"):
            p.has_sql = True
        if f.startswith("supabase/"):
            p.uses_supabase = True
    return p


# ----------------------------------------------------------------------------
# per-file rules
# ----------------------------------------------------------------------------

PEM_BODY_RE = re.compile(r"PRIVATE KEY(?: BLOCK)?-----[\s\\n]*[A-Za-z0-9+/=]{40,}")
TEST_PATH_RE = re.compile(r"(^|/)(__tests__|tests?|spec|mocks?|fixtures?|examples?|docs?)(/|$)|\.(test|spec)\.", re.I)


def is_env_filename(rel: str) -> bool:
    base = os.path.basename(rel)
    return bool(re.match(r"^\.env(\..+)?$", base))


def is_env_template(rel: str) -> bool:
    return os.path.basename(rel).endswith((".example", ".sample", ".template", ".dist", ".defaults"))


PUBLIC_ENV_PREFIX_RE = re.compile(r"^(?:VITE|NEXT_PUBLIC|NUXT_PUBLIC|REACT_APP|EXPO_PUBLIC|GATSBY|PUBLIC)_")
SENSITIVE_ENV_NAME_RE = re.compile(r"KEY|SECRET|TOKEN|PASS|PWD|PRIVATE|CREDENTIAL|DSN|AUTH")
PUBLIC_SAFE_ENV_NAME_RE = re.compile(r"(?:ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY)$")
ENV_KEY_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def env_name_is_public(name: str) -> bool:
    """A browser-public variable that is not secret by name (VITE_SUPABASE_URL, NEXT_PUBLIC_..._ANON_KEY)."""
    name = name.upper()
    if not PUBLIC_ENV_PREFIX_RE.match(name):
        return False
    return not SENSITIVE_ENV_NAME_RE.search(name) or bool(PUBLIC_SAFE_ENV_NAME_RE.search(name))


PUBLIC_ENV_NAME_SUFFIX_RE = re.compile(r"(?:_URL|_URI|_HOST|_DOMAIN|_REGION|_PORT|_ENV|_MODE|_PROJECT_ID|_PROJECT_REF|^NODE_ENV)$")


def env_value_is_public(name: str, value: str) -> bool:
    """Values meant for the browser or not secret at all: empty, placeholders, Stripe publishable keys,
    Supabase anon keys, plain URLs without credentials."""
    value = value.strip().strip("'\"")
    if not value or looks_placeholder(value):
        return True
    if re.match(r"pk_(?:live|test)_", value) or decode_jwt_role(value) == "anon":
        return True
    if value.startswith(("sb_publishable_",)):
        return True
    return bool(PUBLIC_ENV_NAME_SUFFIX_RE.search(name.upper())) and "@" not in value


def env_text_public_only(text: str) -> bool:
    pairs = []
    for l in text.splitlines():
        m = ENV_KEY_RE.match(l)
        if m:
            pairs.append((m.group(1), l[m.end():]))
    return bool(pairs) and all(env_name_is_public(n) or env_value_is_public(n, v) for n, v in pairs)


class Scanner:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.findings = []
        self.coverage = {}
        self.files = []
        self.tracked = None
        self.project = Project()
        self.webhook_handlers = 0
        self.history_failed = False
        self.ignore_rules = []

    # -- bookkeeping --------------------------------------------------------
    def add(self, rule, severity, title, rel, line, evidence, advice, source="tree", commit="", vh=""):
        self.findings.append(Finding(rule, severity, title, rel, line, evidence, advice, source, commit, vh))

    def load_ignore(self):
        path = os.path.join(self.root, ".leakwardenignore")
        txt = read_text(path) if os.path.isfile(path) else None
        for raw in (txt or "").splitlines():
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            rule = None
            glob = None
            parts = raw.split()
            for part in parts:
                if part.startswith("rule:"):
                    rule = part[5:]
                else:
                    glob = part
            self.ignore_rules.append((rule, glob))

    def ignored(self, f: Finding) -> bool:
        for rule, glob in self.ignore_rules:
            if rule and not (f.rule == rule or f.rule.startswith(rule.rstrip("*"))):
                continue
            if glob and not fnmatch.fnmatch(f.file, glob):
                continue
            return True
        return False

    # -- main ---------------------------------------------------------------
    def run(self, history: bool, max_commits: int, history_range: str = ""):
        self.load_ignore()
        self.files, self.tracked = list_files(self.root)
        self.project = detect_project(self.root, self.files)
        texts = {}
        scanned = 0
        root_real = os.path.realpath(self.root)
        for rel in self.files:
            full = os.path.join(self.root, rel)
            real = os.path.realpath(full)
            if real != full and not real.startswith(root_real + os.sep):
                continue
            text = read_text(full)
            if text is None:
                continue
            scanned += 1
            texts[rel] = text
            self.scan_file(rel, text)
        self.coverage["secrets (working tree)"] = "checked %d text files" % scanned
        self.check_env_files(texts)
        self.free_coverage()
        if history:
            self.scan_history(max_commits, history_range)
        else:
            self.coverage["secrets (git history)"] = "skipped (--no-history)"
        self.finish()
        return self

    def free_coverage(self):
        note = "not included in the free edition"
        rls = note
        if self.project.uses_supabase:
            rls += " (this project uses Supabase; LeakWarden Pro checks the RLS policies in your migrations)"
        self.coverage["supabase row level security"] = rls
        self.coverage["webhook handlers"] = note
        self.coverage["other checks"] = (note + ": keys exposed to the browser, payments and paywalls, CORS, "
                                         "framework settings, committed databases, risky code")

    def scan_file(self, rel: str, text: str):
        lines = text.splitlines()
        env_file = is_env_filename(rel)
        template = is_env_template(rel)
        low_rel = rel.lower()
        is_code = low_rel.endswith(CODE_SUFFIXES)
        in_tests = bool(TEST_PATH_RE.search(rel)) or bool(re.search(r"\.env\.test$|\.test\.[a-z]+$", low_rel))
        pem_cache = []

        def pem_ok():
            if not pem_cache:
                pem_cache.append(bool(PEM_BODY_RE.search(text)))
            return pem_cache[0]

        for i, line in enumerate(lines, 1):
            if "leakwarden:ignore" in line:
                continue
            if len(line) > MAX_LINE_CHARS:
                hits = []
                for a in range(0, len(line), MAX_LINE_CHARS - 200):
                    win = line[a:a + MAX_LINE_CHARS]
                    for h in scan_line_for_secrets(win, False, known_only=True):
                        hits.append((h[0], h[1], h[2], (h[3][0] + a, h[3][1] + a), h[4]))
                seen_sp = set()
                for rule, sev, title, span, val in hits:
                    if span in seen_sp or (rule == "secret.private_key" and (in_tests or not pem_ok())):
                        continue
                    seen_sp.add(span)
                    if rule == "secret.private_key":
                        ev_long = redact(line[max(0, span[0] - 40):span[0]] + "K", [(min(40, span[0]), min(40, span[0]) + 1)], rule)
                    else:
                        ev_long = redact(line[max(0, span[0] - 40):span[1] + 40], [(min(40, span[0]), min(40, span[0]) + span[1] - span[0])], rule)
                    self.add(rule, sev, title, rel, i, ev_long, SECRET_ADVICE, vh=sha(val))
                continue
            hits = list(scan_line_for_secrets(line, env_file and not template, known_only=template))
            ev = redact(line, [h[3] for h in hits], "redacted")
            for rule, sev, title, span, val in hits:
                if rule in ("secret.generic", "secret.hardcoded_password") and in_tests:
                    continue
                if rule in ("secret.generic", "secret.hardcoded_password") and (
                        low_rel.endswith(DOC_SUFFIXES) or LOCALE_PATH_RE.search(rel)):
                    continue  # documentation examples and UI translations, not credentials
                if rule == "secret.hardcoded_password" and SEED_PATH_RE.search(low_rel):
                    sev, title = "low", title + " (seed script)"
                elif rule == "secret.hardcoded_password" and LOCAL_SCRIPT_RE.search(low_rel) and LOCALHOST_RE.search(text):
                    sev, title = "low", title + " (local test or load script)"
                elif rule == "secret.hardcoded_password" and (
                        SAMPLE_PATH_RE.search(low_rel)
                        or any(SAMPLE_EMAIL_RE.search(l) for l in lines[max(0, i - 7):i + 6])
                        or any(SAMPLE_NAME_RE.search(l) for l in lines[max(0, i - 16):i])):
                    sev, title = "low", title + " (looks like sample or demo credentials)"
                if rule == "secret.private_key" and (in_tests or not pem_ok()):
                    continue
                if (rule == "secret.hardcoded_password" and sev == "high" and not env_file
                        and not INFRA_PW_NAME_RE.search(title.split("'")[1] if "'" in title else "")):
                    # a plain "password: '...'" in code is often a demo login or a fixture; service
                    # credentials (EMAIL_HOST_PASSWORD, DB_PASSWORD, SMTP_PASS) stay high
                    sev = "medium"
                self.add(rule, sev, title, rel, i, ev, SECRET_ADVICE, vh=sha(val))
    def check_env_files(self, texts):
        gitignore = texts.get(".gitignore", "")
        ignored_env = bool(re.search(r"^[ \t]*/?\.env(\*|\.local)?[ \t]*$", gitignore, re.M))
        for rel in self.files:
            if not is_env_filename(rel) or is_env_template(rel):
                continue
            has_secret = any(f.file == rel and f.rule.startswith("secret.") and f.severity != "low" for f in self.findings)
            committed = self.tracked is None or rel in self.tracked
            if self.tracked is not None:
                if rel in self.tracked:
                    public_cfg = bool(re.search(r"\.env\.(development|production|test|staging)$", rel.lower())) and not has_secret
                    exposed = False
                    public_only = not has_secret and not exposed and env_text_public_only(texts.get(rel, ""))
                    if public_only:
                        self.add("env.committed", "low", "Env file is tracked by git (browser-public values only)",
                                 rel, 1, "(file contents not shown)",
                                 "Nothing secret in it today, but the next key someone adds here gets committed too. "
                                 "Move it to .env.example and add .env to .gitignore.")
                    else:
                        self.add("env.committed", "high" if has_secret else ("low" if public_cfg else "medium"),
                                 "Env file is tracked by git", rel, 1, "(file contents not shown)",
                                 "Remove it from git (git rm --cached), add it to .gitignore, and rotate every value "
                                 "in it. Commit a .env.example with placeholders instead.")
            elif not ignored_env:
                self.add("env.not_ignored", "medium", "Env file present and .gitignore does not exclude it",
                         rel, 1, "(file contents not shown)", "Add .env to .gitignore before the first commit.")

    def scan_history(self, max_commits: int, history_range: str = ""):
        if not is_git_repo(self.root):
            self.coverage["secrets (git history)"] = "skipped (not a git repository)"
            return
        cmd = ["git", "-C", self.root] + GIT_SAFE + [
               "log", history_range or "--all", "--no-ext-diff", "--no-textconv", "--no-show-signature", "-p", "-U0", "--no-color",
               "--relative", "--format=@@COMMIT %H", "-n", str(max(0, max_commits))]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=git_env())
        except OSError:
            self.coverage["secrets (git history)"] = "skipped (git not available)"
            return
        commits = 0
        seen = set()
        tree_hashes = set(f.vh for f in self.findings if f.vh)
        commit = ""
        cur_file = None
        lineno = 0
        env_seen = set()
        env_public = {}
        left_old = left_new = 0
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("@@COMMIT "):
                commit = line.split(" ", 1)[1][:8]
                commits += 1
                cur_file = None
                continue
            if left_old <= 0 and left_new <= 0 and line.startswith("+++ "):
                path = unquote_git_path(line[4:])
                cur_file = path[2:] if path.startswith("b/") else None
                if cur_file and not want_file(cur_file):
                    cur_file = None
                continue
            if left_old <= 0 and left_new <= 0 and line.startswith("@@ "):
                m = re.match(r"@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
                if m:
                    left_old = int(m.group(1)) if m.group(1) is not None else 1
                    left_new = int(m.group(3)) if m.group(3) is not None else 1
                    lineno = int(m.group(2)) - 1
                continue
            if line.startswith("-"):
                left_old -= 1
                continue
            if not line.startswith("+"):
                continue
            left_new -= 1
            if cur_file is None:
                continue
            lineno += 1
            added = line[1:]
            if is_env_filename(cur_file) and not is_env_template(cur_file):
                km = ENV_KEY_RE.match(added)
                if km and not env_name_is_public(km.group(1)):
                    env_public[cur_file] = False
                else:
                    env_public.setdefault(cur_file, True)
            if (is_env_filename(cur_file) and not is_env_template(cur_file) and cur_file not in env_seen
                    and not (self.tracked and cur_file in self.tracked)):
                env_seen.add(cur_file)
                self.add("env.in_history", "medium", "Env file was committed at some point", cur_file, lineno,
                         "(file contents not shown)",
                         "Even if it is deleted now, it is in the history. Rotate any real secret that was in it.",
                         source="history", commit=commit)
            if "leakwarden:ignore" in added:
                continue
            for rule, sev, title, span, val in scan_line_for_secrets(added, False, known_only=True):
                if sev == "low":
                    continue
                if rule == "secret.private_key" and not (
                        PEM_BODY_RE.search(added) or cur_file.lower().endswith((".pem", ".key", ".p8"))):
                    continue  # a header in a placeholder, a .replace() call or docs, not a key
                vh = sha(val)
                if vh in tree_hashes:
                    continue
                key = (rule, vh, cur_file)
                if key in seen:
                    continue
                seen.add(key)
                self.add(rule, sev, title + " (in git history)", cur_file, lineno,
                         redact_all(added), SECRET_ADVICE + " Rewriting history (git filter-repo) "
                         "only helps after the key is rotated.", source="history", commit=commit, vh=vh)
        proc.stdout.close()
        proc.wait()
        for f in self.findings:
            if f.rule == "env.in_history" and env_public.get(f.file):
                if not any(g.file == f.file and g.source == "history" and g.rule.startswith("secret.") for g in self.findings):
                    f.severity = "low"
                    f.title = "Env file was committed at some point (browser-public values only)"
        if proc.returncode != 0:
            self.history_failed = True
            self.coverage["secrets (git history)"] = "FAILED: git log could not read %s" % (history_range or "the history")
            return
        where = " in range %s" % history_range if history_range else ""
        self.coverage["secrets (git history)"] = "checked %d commit(s)%s (limit %d), added lines only" % (
            commits, where, max_commits)

    # -- finish -------------------------------------------------------------
    def finish(self):
        uniq = {}
        for f in self.findings:
            if self.ignored(f):
                continue
            uniq[(f.rule, f.file, f.line, f.source, f.commit, f.vh)] = f
        self.findings = sorted(
            uniq.values(), key=lambda f: (-SEV_RANK[f.severity], f.file, f.line))


# ----------------------------------------------------------------------------
# SQL helpers
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------------

FREE_NOTE = ("Free edition: secrets and .env files, in your files and in git history. LeakWarden Pro adds "
             "Supabase RLS, webhooks, payments, browser-exposed keys, framework settings, the Claude Code "
             "skill and the CI workflow: https://leakwarden.dev")
DISCLAIMER = (
    "leakwarden is a heuristic scanner. It reports patterns, not proof of an exploit, and it will miss "
    "problems it has no rule for (authorization logic, business logic, dependency vulnerabilities, "
    "infrastructure). A clean report is not a security guarantee."
)


def edition_label() -> str:
    return " (free edition)" if EDITION == "free" else ""


def summarize(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def to_dict(sc: Scanner, min_sev: str):
    shown = [f for f in sc.findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]]
    items = []
    for f in shown:
        d = asdict(f)
        d.pop("vh", None)
        items.append(d)
    return {
        "tool": "leakwarden", "version": __version__, "edition": EDITION, "target": sc.root,
        "summary": summarize(shown), "coverage": sc.coverage, "findings": items, "disclaimer": DISCLAIMER,
    }


_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def clean(s) -> str:
    s = str(s).encode("utf-8", "replace").decode("utf-8")
    return _CTRL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)) if ord(m.group(0)) < 256 else "\\u%04x" % ord(m.group(0)), s)


def md_escape(s) -> str:
    s = clean(s)
    return re.sub(r"([\\`*_\[\]<>()|#])", r"\\\1", s)


def render_text(data) -> str:
    out = []
    s = data["summary"]
    out.append("leakwarden %s%s  %s" % (data["version"], edition_label(), data["target"]))
    out.append("")
    out.append("Coverage")
    for k, v in data["coverage"].items():
        out.append("  - %s: %s" % (k, v))
    out.append("")
    out.append("Findings: %d high, %d medium, %d low, %d info" % (s["high"], s["medium"], s["low"], s["info"]))
    out.append("")
    for f in data["findings"]:
        f = {k: (clean(v) if isinstance(v, str) else v) for k, v in f.items()}
        loc = "%s:%s" % (f["file"], f["line"])
        extra = "  [history %s]" % f["commit"] if f["source"] == "history" else ""
        out.append("[%s] %s  (%s)%s" % (f["severity"].upper(), f["title"], f["rule"], extra))
        out.append("    %s" % loc)
        if f["evidence"]:
            out.append("    > %s" % f["evidence"])
        out.append("    Fix: %s" % f["advice"])
        out.append("")
    out.append(FREE_NOTE)
    out.append("")
    out.append(DISCLAIMER)
    return "\n".join(out) + "\n"


def render_markdown(data) -> str:
    s = data["summary"]
    out = ["# leakwarden report", "", "Target: `%s`  " % data["target"], "Version: %s%s" % (data["version"], edition_label()), "",
           "## Summary", "",
           "| High | Medium | Low | Info |", "|---|---|---|---|",
           "| %d | %d | %d | %d |" % (s["high"], s["medium"], s["low"], s["info"]), "", "## Coverage", ""]
    for k, v in data["coverage"].items():
        out.append("- **%s**: %s" % (k, v))
    out += ["", "## Findings", ""]
    if not data["findings"]:
        out.append("No findings at the selected severity.")
    for f in data["findings"]:
        f = {k: (md_escape(v) if isinstance(v, str) else v) for k, v in f.items()}
        where = "%s:%s" % (f["file"], f["line"])
        if f["source"] == "history":
            where += " (git history, commit %s)" % f["commit"]
        out.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        out.append("")
        out.append("- Rule: `%s`" % f["rule"])
        out.append("- Where: %s" % where)
        if f["evidence"]:
            out.append("- Evidence: `%s`" % f["evidence"].replace("`", "'"))
        out.append("- Fix: %s" % f["advice"])
        out.append("")
    out += ["---", "", FREE_NOTE]
    out += ["---", "", DISCLAIMER, ""]
    return "\n".join(out)


# Everything in the report comes from the scanned repository (file names, code lines, table names), so the
# HTML report escapes every value, puts no report data in attributes, and ships no script. The CSP below
# blocks scripts, images, fonts and fetches even if something slipped through.
HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
HTML_CSS = """
:root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--fg:#1c2230;--muted:#5b6475;--line:#dde1e8;--code:#f0f2f5;
--high:#b42318;--high-bg:#fdeceb;--medium:#a94a04;--medium-bg:#fff3e2;--low:#1a5bc4;--low-bg:#e9f1ff;
--info:#4a5568;--info-bg:#eceff3;--ok:#0a7343;--ok-bg:#e5f5eb}
@media (prefers-color-scheme:dark){:root{--bg:#0e1117;--card:#161a22;--fg:#e5e8ee;--muted:#9aa3b2;--line:#2a303b;
--code:#0b0d12;--high:#ff8f85;--high-bg:#3b1613;--medium:#ffb76b;--medium-bg:#38240f;--low:#8db6ff;--low-bg:#14254a;
--info:#bac2ce;--info-bg:#232934;--ok:#72d99b;--ok-bg:#11301e}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 20px 48px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:13px}
code{overflow-wrap:anywhere;word-break:break-word}
h1,h2,h3,h4{line-height:1.3;margin:0}
h2{font-size:19px;margin:36px 0 14px}
.top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:12px 24px;
padding-bottom:18px;border-bottom:1px solid var(--line)}
.brand{font-size:26px;font-weight:700;letter-spacing:-.01em}
.brand .ver{font-size:15px;font-weight:500;color:var(--muted);margin-left:6px}
.edition{display:inline-block;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted);vertical-align:middle;margin-left:6px}
.meta{margin:0;display:grid;grid-template-columns:auto 1fr;gap:2px 12px;font-size:14px}
.meta dt{color:var(--muted)}
.meta dd{margin:0}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:24px}
.tile{border-radius:10px;padding:14px 16px;border:1px solid var(--line);border-left-width:5px;background:var(--card)}
.tile .n{display:block;font-size:30px;font-weight:700;line-height:1.1}
.tile .l{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.tile.sev-high{border-left-color:var(--high)}.tile.sev-medium{border-left-color:var(--medium)}
.tile.sev-low{border-left-color:var(--low)}.tile.sev-info{border-left-color:var(--info)}
.tile.sev-high:not(.zero){background:var(--high-bg);color:var(--high)}
.tile.sev-medium:not(.zero){background:var(--medium-bg);color:var(--medium)}
.tile.sev-low:not(.zero){background:var(--low-bg);color:var(--low)}
.tile.sev-info:not(.zero){background:var(--info-bg);color:var(--info)}
.tile.zero{color:var(--muted)}
.group{font-size:15px;text-transform:uppercase;letter-spacing:.06em;margin:24px 0 10px}
.group.sev-high{color:var(--high)}.group.sev-medium{color:var(--medium)}
.group.sev-low{color:var(--low)}.group.sev-info{color:var(--info)}
.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:10px;
padding:14px 18px;margin:0 0 12px}
.finding.sev-high{border-left-color:var(--high)}.finding.sev-medium{border-left-color:var(--medium)}
.finding.sev-low{border-left-color:var(--low)}.finding.sev-info{border-left-color:var(--info)}
.fhead{display:flex;align-items:baseline;gap:10px}
.fhead h4{font-size:16px;overflow-wrap:anywhere}
.badge{flex:none;font-size:11px;font-weight:700;letter-spacing:.06em;padding:2px 7px;border-radius:5px}
.badge.sev-high{background:var(--high-bg);color:var(--high)}
.badge.sev-medium{background:var(--medium-bg);color:var(--medium)}
.badge.sev-low{background:var(--low-bg);color:var(--low)}
.badge.sev-info{background:var(--info-bg);color:var(--info)}
.fmeta{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;margin:10px 0 0;font-size:14px}
.fmeta dt{color:var(--muted)}
.fmeta dd{margin:0;min-width:0}
pre{margin:10px 0 0;padding:10px 12px;background:var(--code);border:1px solid var(--line);border-radius:7px;
white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere}
.fix{margin:10px 0 0}
.fix b{font-weight:600}
.empty{color:var(--muted);background:var(--card);border:1px dashed var(--line);border-radius:10px;padding:14px 18px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;
font-size:14px}
th,td{text-align:left;vertical-align:top;padding:9px 12px;border-top:1px solid var(--line)}
thead th{border-top:0;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
tbody th{font-weight:600;white-space:nowrap}
td{overflow-wrap:anywhere}
.st{display:inline-block;white-space:nowrap;font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px}
.st-ok{background:var(--ok-bg);color:var(--ok)}.st-na{background:var(--info-bg);color:var(--info)}
.st-gap{background:var(--medium-bg);color:var(--medium)}.st-fail{background:var(--high-bg);color:var(--high)}
.note{margin:16px 0 0;padding:12px 16px;border-radius:10px;background:var(--low-bg);color:var(--fg);
border:1px solid var(--line)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
footer p{margin:6px 0}
a{color:var(--low)}
@media (max-width:640px){.summary{grid-template-columns:repeat(2,1fr)}tbody th{white-space:normal}}
@media print{:root{--bg:#fff;--card:#fff;--fg:#000;--muted:#444;--line:#bbb;--code:#f4f4f4;--high:#9b1c13;
--high-bg:#fdeceb;--medium:#8a3c03;--medium-bg:#fff3e2;--low:#164ea8;--low-bg:#e9f1ff;--info:#3d4656;--info-bg:#eceff3;
--ok:#0a6338;--ok-bg:#e5f5eb}
body{font-size:10.5pt}main{max-width:none;padding:0}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
.finding,.tile,tr,.note{break-inside:avoid;page-break-inside:avoid}
h2,.group{break-after:avoid;page-break-after:avoid}
a{color:inherit;text-decoration:none}}
"""


def html_text(s) -> str:
    """Escape one report value for HTML text. Control and bidi characters are made visible first."""
    return html.escape(clean(s), quote=True)


def coverage_status(value: str):
    """CSS class and label for a coverage line; both come from this fixed list, never from the report."""
    low = str(value).lower()
    if low.startswith("failed"):
        return "st-fail", "Failed"
    if low.startswith(("not assessed", "skipped", "not included")):
        return "st-gap", "Not assessed"
    if low.startswith("not applicable"):
        return "st-na", "Not applicable"
    return "st-ok", "Checked"


def render_html(data, generated=None) -> str:
    s = data["summary"]
    when = generated or time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    edition = {"pro": "Pro edition", "free": "Free edition"}.get(data.get("edition"), data.get("edition") or "")
    out = ['<!DOCTYPE html>', '<html lang="en">', '<head>', '<meta charset="utf-8">',
           '<meta http-equiv="Content-Security-Policy" content="%s">' % HTML_CSP,
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta name="color-scheme" content="light dark">', '<meta name="referrer" content="no-referrer">',
           '<title>LeakWarden report: %s</title>' % html_text(data["target"]),
           '<style>%s</style>' % HTML_CSS, '</head>', '<body>', '<main>',
           '<header class="top">',
           '<h1 class="brand">LeakWarden <span class="ver">%s</span> <span class="edition">%s</span></h1>' % (
               html_text(data["version"]), html_text(edition)),
           '<dl class="meta"><dt>Scanned</dt><dd><code>%s</code></dd><dt>Date</dt><dd>%s</dd></dl>' % (
               html_text(data["target"]), html_text(when)),
           '</header>', '<section class="summary" aria-label="Findings by severity">']
    for sev in reversed(SEVERITIES):
        n = int(s.get(sev, 0))
        out.append('<div class="tile sev-%s%s"><span class="n">%d</span><span class="l">%s</span></div>' % (
            sev, "" if n else " zero", n, sev.capitalize()))
    out += ['</section>', '<section class="findings">', '<h2>Findings</h2>']
    groups = {sev: [] for sev in SEVERITIES}
    for f in data["findings"]:
        groups[f.get("severity") if f.get("severity") in groups else "info"].append(f)
    if not data["findings"]:
        out.append('<p class="empty">No findings at the selected severity.</p>')
    for sev in reversed(SEVERITIES):
        if not groups[sev]:
            continue
        out.append('<h3 class="group sev-%s">%s (%d)</h3>' % (sev, sev.capitalize(), len(groups[sev])))
        for f in groups[sev]:
            if f.get("source") == "history":
                src = "git history"
                if f.get("commit"):
                    src += ", commit <code>%s</code>" % html_text(f["commit"])
            else:
                src = "working tree"
            out += ['<article class="finding sev-%s">' % sev,
                    '<div class="fhead"><span class="badge sev-%s">%s</span><h4>%s</h4></div>' % (
                        sev, sev.upper(), html_text(f.get("title", ""))),
                    '<dl class="fmeta"><dt>Rule</dt><dd><code>%s</code></dd>' % html_text(f.get("rule", "")),
                    '<dt>Location</dt><dd><code>%s:%s</code></dd>' % (html_text(f.get("file", "")),
                                                                      html_text(f.get("line", ""))),
                    '<dt>Source</dt><dd>%s</dd></dl>' % src]
            if f.get("evidence"):
                out.append('<pre><code>%s</code></pre>' % html_text(f["evidence"]))
            out += ['<p class="fix"><b>Fix:</b> %s</p>' % html_text(f.get("advice", "")), '</article>']
    out += ['</section>', '<section class="coverage">', '<h2>Coverage</h2>',
            '<table><thead><tr><th scope="col">Area</th><th scope="col">Status</th><th scope="col">Details</th>'
            '</tr></thead><tbody>']
    for k, v in data["coverage"].items():
        cls, label = coverage_status(v)
        out.append('<tr><th scope="row">%s</th><td><span class="st %s">%s</span></td><td>%s</td></tr>' % (
            html_text(k), cls, label, html_text(v)))
    out += ['</tbody></table>']
    out.append('<p class="note">%s</p>' % html_text(FREE_NOTE))
    out += ['</section>', '<footer>', '<p>%s</p>' % html_text(data.get("disclaimer", DISCLAIMER)),
            '<p>Generated by LeakWarden %s on %s. <a href="https://leakwarden.dev">leakwarden.dev</a></p>' % (
                html_text(data["version"]), html_text(when)),
            '</footer>', '</main>', '</body>', '</html>', '']
    return "\n".join(out)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

HISTORY_RANGE_RE = re.compile(r"^(?!-)[A-Za-z0-9._/@^~-]+(?:\.\.\.?(?!-)[A-Za-z0-9._/@^~-]+)?$")


def build_parser():
    p = argparse.ArgumentParser(
        prog="leakwarden",
        description="Static security checks for web projects built with AI coding tools.")
    p.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    p.add_argument("--format", choices=["text", "json", "markdown", "html"], default="text")
    p.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low",
                   help="hide findings below this severity (default: low)")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                   help="exit with status 1 if a finding at or above this severity exists (default: high)")
    p.add_argument("--no-history", action="store_true", help="do not scan git history")
    p.add_argument("--max-commits", type=int, default=500, help="how many commits of history to scan (default: 500)")
    p.add_argument("--history-range", default="",
                   help="scan only the commits in this git range, e.g. origin/main..HEAD (for CI on pull requests)")
    p.add_argument("--version", action="version", version="leakwarden " + __version__ + edition_label())
    return p


def main(argv=None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:
        print("leakwarden: internal error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2


def _main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = args.path
    if not os.path.isdir(root):
        print("leakwarden: not a directory: %s" % root, file=sys.stderr)
        return 2
    if args.history_range and not HISTORY_RANGE_RE.match(args.history_range):
        print("leakwarden: --history-range must look like BASE..HEAD (letters, digits, . _ / @ ^ ~ -)", file=sys.stderr)
        return 2
    sc = Scanner(root).run(history=not args.no_history, max_commits=args.max_commits,
                           history_range=args.history_range)
    if getattr(sc, "history_failed", False) and args.history_range:
        print("leakwarden: could not read git range %s (is the clone deep enough?)" % args.history_range, file=sys.stderr)
        return 2
    data = to_dict(sc, args.min_severity)
    if args.format == "json":
        text = json.dumps(data, indent=2) + "\n"
    elif args.format == "markdown":
        text = render_markdown(data)
    elif args.format == "html":
        text = render_html(data)
    else:
        text = render_text(data)
    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    if args.fail_on != "never":
        threshold = SEV_RANK[args.fail_on]
        threshold = max(threshold, SEV_RANK[args.min_severity])  # hidden findings never fail the run
        if any(SEV_RANK[f.severity] >= threshold for f in sc.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
