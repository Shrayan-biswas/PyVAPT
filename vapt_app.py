#!/usr/bin/env python3
"""
Automated Website VAPT Framework  (single-file Flask app)
Author:   Shrayan Biswas - https://www.linkedin.com/in/shrayan-biswas-a1259225a/
License:  MIT (see LICENSE)

Runs on Kali with:   sudo apt install -y python3-flask
Start:               python3 vapt_app.py        ->  http://127.0.0.1:5000

Everything else uses the Python standard library (no pip).

SAFETY MODEL
- Binds to 127.0.0.1 only.
- Any http(s) target can be scanned. Only scan systems you own or have permission to test.
- Remote (non-lab) targets are rate-limited (max 4 workers, 0.25s delay) so other people's servers are not overloaded.
- Automated checks are non-destructive: GET/HEAD/OPTIONS, a tiny rate-limit
  burst, rate-limited path discovery, header/cookie/TLS/CORS/JS inspection.
- Injection, auth-bypass, IDOR and exploitation phases (4, 5, 6, 10) are NOT
  automated. They are tracked as manual checklists (Burp/ZAP/SQLmap) and the
  findings you confirm are entered into the CVSS-scored register.
- Redirects to other hosts are never followed.
"""
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

from flask import Flask, Response, abort, jsonify, request

# --------------------------------------------------------------------------
# Project layout (matches Phase 0)
# --------------------------------------------------------------------------
__version__ = "1.0.0"
AUTHOR = "Shrayan Biswas"
AUTHOR_URL = "https://www.linkedin.com/in/shrayan-biswas-a1259225a/"

BASE = Path(os.environ.get("VAPT_HOME", Path.home() / "VAPT-Project"))
for _d in ("recon", "scans", "evidence", "reports", "scripts", "logs"):
    (BASE / _d).mkdir(parents=True, exist_ok=True)
FINDINGS_FILE = BASE / "reports" / "findings.json"
LOCK = threading.Lock()
RUNS = {}
app = Flask(__name__)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


# --------------------------------------------------------------------------
# CVSS v3.1 base score
# --------------------------------------------------------------------------
def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31(vector):
    try:
        p = dict(x.split(":") for x in vector.split("/")[1:])
        s = p["S"]
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[p["AV"]]
        ac = {"L": .77, "H": .44}[p["AC"]]
        pr = ({"N": .85, "L": .62, "H": .27} if s == "U" else {"N": .85, "L": .68, "H": .5})[p["PR"]]
        ui = {"N": .85, "R": .62}[p["UI"]]
        cia = lambda k: {"H": .56, "L": .22, "N": 0}[p[k]]
        iss = 1 - (1 - cia("C")) * (1 - cia("I")) * (1 - cia("A"))
        imp = 6.42 * iss if s == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
        if imp <= 0:
            return 0.0
        ex = 8.22 * av * ac * pr * ui
        return _roundup(min(imp + ex if s == "U" else 1.08 * (imp + ex), 10))
    except Exception:
        return None


def severity(score):
    if score is None or score == 0:
        return "Informational"
    return "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


V_INFO = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
V_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
V_LOW_LI = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
V_MED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
V_MED_DISC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
V_HIGH_DISC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V_CORS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"


# --------------------------------------------------------------------------
# Findings register (vuln_manager)
# --------------------------------------------------------------------------
def target_slug(url):
    """File/folder-safe target name: http://example.com -> example.com, 127.0.0.1:3000 -> 127.0.0.1_3000"""
    p = urlparse(url if "://" in str(url) else "http://" + str(url))
    host = (p.hostname or "target").lower()
    default = {"http": 80, "https": 443}.get(p.scheme)
    try:
        port = p.port
    except ValueError:
        port = None
    slug = host if not port or port == default else f"{host}_{port}"
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", slug).strip(".")[:80]
    return slug or "target"


def report_name(slug):
    return f"{slug}_VAPT_Report"


def tdir(kind, slug):
    d = BASE / kind / slug
    d.mkdir(parents=True, exist_ok=True)
    return d


def all_slugs():
    return sorted(p.parent.name for p in (BASE / "reports").glob("*/findings.json"))


def load_findings(slug=None):
    if slug is None:
        out = []
        for sl in all_slugs():
            out += load_findings(sl)
        return out
    try:
        return json.loads((BASE / "reports" / slug / "findings.json").read_text())
    except Exception:
        return []


def save_findings(slug, reg):
    (tdir("reports", slug) / "findings.json").write_text(json.dumps(reg, indent=2))


def load_runs(slug):
    try:
        return json.loads((BASE / "reports" / slug / "runs.json").read_text())
    except Exception:
        return []


def append_run(slug, entry):
    with LOCK:
        runs = load_runs(slug)[-49:] + [entry]
        (tdir("reports", slug) / "runs.json").write_text(json.dumps(runs, indent=2))


def merge_findings(new, default_slug=None):
    groups = {default_slug: []} if default_slug else {}
    for f in new:
        groups.setdefault(target_slug(f["target"]), []).append(f)
    with LOCK:
        for slug, items in groups.items():
            reg = load_findings(slug)
            idx = {(f["title"], f["component"]): f for f in reg}
            for f in items:
                k = (f["title"], f["component"])
                if k in idx:
                    old = idx[k]
                    old["last_seen"], old["evidence"] = now(), f["evidence"]
                    if old["status"] in ("Remediated", "Retest Passed"):
                        old["status"] = "Reopened"
                        old["notes"] = (old["notes"] + f"\n[{now()}] Seen again in a later scan.").strip()
                else:
                    reg.append(f)
                    idx[k] = f
            save_findings(slug, reg)


def migrate_legacy():
    """Split an old single findings.json into one file per target."""
    if not FINDINGS_FILE.exists():
        return
    try:
        old = json.loads(FINDINGS_FILE.read_text())
    except Exception:
        return
    by = {}
    for f in old:
        by.setdefault(target_slug(f.get("target", "")), []).append(f)
    for slug, items in by.items():
        cur = load_findings(slug)
        ids = {f["id"] for f in cur}
        save_findings(slug, cur + [f for f in items if f["id"] not in ids])
    FINDINGS_FILE.rename(FINDINGS_FILE.parent / "findings.legacy.migrated")


def make_finding(target, run_id, title, vector, component, description, impact, recommendation,
                 evidence="", phase=""):
    score = cvss31(vector)
    return {"id": uuid.uuid4().hex[:8], "run_id": run_id, "target": target, "title": title,
            "phase": phase, "vector": vector, "score": score, "severity": severity(score),
            "component": component, "description": description, "impact": impact,
            "recommendation": recommendation, "evidence": evidence, "status": "Open",
            "notes": "", "found": now(), "last_seen": now()}


# --------------------------------------------------------------------------
# Scope validation + scoped HTTP client
# --------------------------------------------------------------------------
def check_scope(url):
    """Validate the URL and resolve the host. Returns (ok, 'lab/private target' | 'external target')."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.hostname.startswith("-"):
        return False, "Target must be a full http(s) URL, e.g. http://127.0.0.1:3000"
    try:
        ips = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(p.hostname, None)}
    except Exception:
        return False, f"Cannot resolve host {p.hostname}"
    if all(ip.is_loopback or ip.is_private for ip in ips):
        return True, "lab/private target"
    return True, "external target"


class Client:
    """Thread-safe scoped HTTP client with a global pacing limiter shared by all workers."""

    def __init__(self, base_url, delay=0.3, insecure=False, timeout=8, extra_headers=None, user_agent=None, stop=None):
        self.host = urlparse(base_url).hostname
        self.delay, self.timeout = delay, timeout
        self.extra = dict(extra_headers or {})
        self.ua = user_agent or "VAPT-Lab-Framework/2.0"
        self.stop = stop or threading.Event()
        self._rl, self._next = threading.Lock(), 0.0
        self.cookies, self.count = set(), 0
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        host = self.host

        class NoOffsite(urllib.request.HTTPRedirectHandler):
            def redirect_request(s, req, fp, code, msg, headers, newurl):
                if urlparse(newurl).hostname != host:
                    return None
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        self.opener = urllib.request.build_opener(NoOffsite, urllib.request.HTTPSHandler(context=ctx))

    def request(self, url, method="GET", headers=None, data=None, max_bytes=1_500_000, nodelay=False):
        out = {"url": url, "status": 0, "h": {}, "cookies": [], "body": "", "error": ""}
        if self.stop.is_set():
            out["error"] = "stopped"
            return out
        if urlparse(url).hostname != self.host:
            out["error"] = "out of scope"
            return out
        if not nodelay and self.delay > 0:
            with self._rl:
                t = time.time()
                slot = max(t, self._next)
                self._next = slot + self.delay
            if slot > t:
                time.sleep(slot - t)
        self.count += 1
        hdrs = {"User-Agent": self.ua, **self.extra, **(headers or {})}
        r = None
        for attempt in (1, 2):
            req = urllib.request.Request(url, method=method, data=data, headers=hdrs)
            try:
                r = self.opener.open(req, timeout=self.timeout)
                out["error"] = ""
                break
            except urllib.error.HTTPError as e:
                r = e
                break
            except Exception as e:
                out["error"] = str(e)
                if method != "GET" or attempt == 2 or self.stop.is_set():
                    return out
                time.sleep(0.3)
        try:
            body = b"" if method == "HEAD" else r.read(max_bytes)
        except Exception:
            body = b""
        out.update(status=getattr(r, "status", None) or r.code,
                   h={k.lower(): v for k, v in r.headers.items()},
                   cookies=r.headers.get_all("Set-Cookie") or [],
                   body=body.decode("utf-8", "replace"))
        for raw in out["cookies"]:
            self.cookies.add(raw)
        return out


def safe_wordlist(path):
    """Only allow wordlists from standard Kali locations or the project folder."""
    if not path or not isinstance(path, str):
        return None
    p = os.path.normpath(path)
    roots = ["/usr/share/wordlists", "/usr/share/seclists", "/usr/share/dirb", "/usr/share/dirbuster",
             "/usr/share/wfuzz", str(BASE)]
    if os.path.isabs(p) and any(p.startswith(r + "/") for r in roots) and os.path.isfile(p):
        return Path(p)
    return None


class Run:
    def __init__(self, target, opts):
        self.id = uuid.uuid4().hex[:8]
        self.target, self.opts = target, opts
        self.slug = target_slug(target)
        self.modules = opts.get("modules", [])
        self.max_pages = int(opts.get("max_pages", 40))
        self.max_dirs = int(opts.get("max_dirs", 200))
        self.workers = max(1, min(int(opts.get("workers", 1)), 64))
        self.exts = [e.strip() for e in str(opts.get("extensions", "")).split(",")
                     if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", e.strip())][:6]
        self.wordlist = safe_wordlist(opts.get("wordlist"))
        self.stop = threading.Event()
        self.current, self.progress = "", 0
        self.status, self.logs, self.findings = "running", [], []
        self.data, self.base, self.js, self.js_urls = {}, None, {}, set()
        self.started = now()

    def log(self, msg):
        self.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def add(self, *a, **k):
        f = make_finding(self.target, self.id, *a, **k)
        self.findings.append(f)
        self.log(f"FINDING [{f['severity']}] {f['title']}")


def is_loopback(host):
    try:
        return all(ipaddress.ip_address(i[4][0]).is_loopback for i in socket.getaddrinfo(host, None))
    except Exception:
        return False


# --------------------------------------------------------------------------
# Phase 1 - Recon
# --------------------------------------------------------------------------
def m_recon(run, c):
    r = c.request(run.target)
    run.base = r
    if not r["status"]:
        run.log("Target unreachable: " + r["error"])
        return
    host = urlparse(run.target).hostname
    title = re.search(r"<title[^>]*>(.*?)</title>", r["body"], re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r["body"], re.I)
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        ips = []
    open_ports = []
    for p in (80, 443, 3000, 5000, 8000, 8080, 8443):
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
    rb = c.request(urljoin(run.target, "/robots.txt"))
    robots = [ln.strip() for ln in rb["body"].splitlines() if ln.lower().startswith(("disallow", "sitemap", "allow"))] \
        if rb["status"] == 200 and "html" not in rb["h"].get("content-type", "") else []
    run.data["recon"] = {
        "status": r["status"], "title": title.group(1).strip() if title else "", "ips": ips,
        "server": r["h"].get("server", ""), "x_powered_by": r["h"].get("x-powered-by", ""),
        "generator": gen.group(1) if gen else "", "content_type": r["h"].get("content-type", ""),
        "open_common_ports": open_ports, "robots_txt": robots,
        "response_headers": r["h"]}
    run.log(f"HTTP {r['status']} | title={run.data['recon']['title']!r} | ips={ips} | ports={open_ports}")
    if robots:
        run.add("robots.txt reveals paths", V_INFO, "/robots.txt",
                "robots.txt lists paths that may hint at sensitive areas.",
                "Information disclosure that helps attackers focus.",
                "Do not rely on robots.txt for secrecy; protect sensitive paths with access control.",
                "\n".join(robots[:15]), "Phase 1")


# --------------------------------------------------------------------------
# Phase 3 / 7 - Headers, cookies, TLS, CORS
# --------------------------------------------------------------------------
HEADER_CHECKS = [
    ("content-security-policy", "Missing Content-Security-Policy header", V_LOW_LI,
     "No CSP is sent, which reduces defence-in-depth against XSS and data injection.",
     "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'  (tune for the app)"),
    ("x-content-type-options", "Missing X-Content-Type-Options header", V_LOW,
     "Browsers may MIME-sniff responses.", "X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Missing Referrer-Policy header", V_INFO,
     "Full URLs may leak to third parties via the Referer header.", "Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "Missing Permissions-Policy header", V_INFO,
     "Browser features are not explicitly restricted.", "Permissions-Policy: geolocation=(), camera=(), microphone=()"),
]


def m_headers(run, c):
    r = run.base
    if not r or not r["status"]:
        return
    h = r["h"]
    for key, title, vec, desc, rec in HEADER_CHECKS:
        if key not in h:
            run.add(title, vec, "/", desc, "Weakens browser-side protections.", "Add: " + rec,
                    f"Header '{key}' absent from response.", "Phase 3")
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        run.add("Missing clickjacking protection", V_LOW_LI, "/",
                "Neither X-Frame-Options nor CSP frame-ancestors is present.",
                "Page may be framed by a malicious site (clickjacking).",
                "Add X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors.", "", "Phase 9")
    if run.target.startswith("https") and "strict-transport-security" not in h:
        run.add("Missing Strict-Transport-Security header", V_LOW, "/",
                "HSTS not set on an HTTPS site.", "Downgrade / SSL-strip risk.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains", "", "Phase 3")
    disc = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if k in h and re.search(r"\d", h[k])]
    if disc:
        run.add("Server/technology version disclosure", V_INFO, "response headers",
                "Headers reveal software and version information.", "Helps attackers match known CVEs.",
                "Remove or genericise Server / X-Powered-By headers.", "\n".join(disc), "Phase 3")
    ac = h.get("access-control-allow-origin")
    if ac == "*":
        run.add("Wildcard CORS policy on landing page", V_LOW, "/",
                "Access-Control-Allow-Origin: * is returned.",
                "Any website can read non-credentialed responses.", "Restrict CORS to trusted origins.",
                "Access-Control-Allow-Origin: *", "Phase 3")


def m_cookies(run, c):
    allraw = (list(run.base["cookies"]) if run.base else []) + sorted(c.cookies)
    names, raws = set(), []
    for raw in allraw:
        n = raw.split("=", 1)[0].strip()
        if n not in names:
            names.add(n)
            raws.append(raw)
    report = []
    for raw in raws:
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        miss = []
        if "secure" not in attrs and run.target.startswith("https"):
            miss.append("Secure")
        if "httponly" not in attrs:
            miss.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            miss.append("SameSite")
        report.append({"name": name, "attributes": attrs, "missing": miss})
        if miss:
            sess = bool(re.search(r"sess|token|auth|jwt|sid", name, re.I))
            run.add(f"Cookie '{name}' missing {', '.join(miss)}", V_LOW_LI if sess else V_LOW, "Set-Cookie",
                    "Cookie lacks recommended security attributes.", "Increased exposure to theft or CSRF.",
                    "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
                    f"{name}=<redacted>; " + "; ".join(attrs), "Phase 7")
    run.data["cookies"] = report
    if not raws:
        run.log("No cookies seen in any response. Log in via Burp and re-check session cookies manually (Phase 4/7).")
    else:
        run.log(f"Inspected {len(raws)} distinct cookies seen across all scan responses")


def m_tls(run, c):
    u = urlparse(run.target)
    if u.scheme != "https":
        vec = V_INFO if is_loopback(u.hostname) else V_MED
        run.add("Application served over plain HTTP", vec, run.target,
                "The target does not use TLS.", "Traffic can be intercepted or modified in transit.",
                "Serve the site over HTTPS and redirect HTTP to HTTPS.", "", "Phase 3")
        return
    port, info = u.port or 443, {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((u.hostname, port), timeout=8) as s, \
                ctx.wrap_socket(s, server_hostname=u.hostname) as t:
            cert = t.getpeercert()
            info = {"version": t.version(), "cipher": t.cipher()[0], "not_after": cert.get("notAfter"),
                    "subject": cert.get("subject"), "verified": True}
            days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
            info["days_left"] = int(days)
            if days < 30:
                run.add("TLS certificate expires soon / expired", V_LOW, run.target,
                        f"Certificate valid for {int(days)} more days.", "Service disruption and browser warnings.",
                        "Renew the certificate and automate renewal.", str(info), "Phase 3")
    except ssl.SSLCertVerificationError as e:
        info = {"verified": False, "error": str(e)}
        run.add("TLS certificate fails validation", V_MED, run.target, "Certificate could not be verified.",
                "Users cannot trust server identity.", "Install a certificate from a trusted CA.", str(e), "Phase 3")
    except Exception as e:
        info = {"error": str(e)}
    run.data["tls"] = info
    run.log(f"TLS: {info}. Use sslscan (External tools) for legacy-protocol and cipher checks.")


def m_cors(run, c):
    origin = "https://evil.example"
    r = c.request(run.target, headers={"Origin": origin})
    acao, acac = r["h"].get("access-control-allow-origin"), r["h"].get("access-control-allow-credentials", "")
    if acao == origin:
        vec = V_CORS if acac.lower() == "true" else V_LOW_LI
        run.add("CORS reflects arbitrary Origin", vec, "/",
                "The server echoes an untrusted Origin in Access-Control-Allow-Origin.",
                "Malicious sites may read responses" + (" with user credentials." if acac.lower() == "true" else "."),
                "Validate Origin against an allow-list; never combine reflection with credentials.",
                f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}", "Phase 3/8")


# --------------------------------------------------------------------------
# Phase 2 - Endpoint mapping
# --------------------------------------------------------------------------
class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms, self._f = set(), set(), [], None

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "a" and a.get("href"):
            self.links.add(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.add(a["src"])
        elif tag == "form":
            self._f = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "inputs": []}
            self.forms.append(self._f)
        elif tag in ("input", "textarea", "select") and self._f is not None and a.get("name"):
            self._f["inputs"].append({"name": a["name"], "type": a.get("type", tag)})

    def handle_endtag(self, tag):
        if tag == "form":
            self._f = None


API_RE = re.compile(r"""["'`](/(?:api|rest|graphql|v[0-9]+)/?[A-Za-z0-9_\-./{}?=&:$]*)["'`]""")


def norm_key(u):
    p = urlparse(u)
    return (p.scheme, p.netloc, p.path.rstrip("/"), tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True))))


def collect_js(run, c):
    if run.js:
        return
    urls = set(run.js_urls)
    if not urls and run.base:
        pg = Page()
        pg.feed(run.base["body"])
        urls = {urljoin(run.target, s) for s in pg.scripts}
    urls = sorted(u for u in urls if urlparse(u).hostname == c.host)[:25]
    with ThreadPoolExecutor(run.workers) as ex:
        for u, r in zip(urls, ex.map(c.request, urls)):
            if r["status"] == 200:
                run.js[u] = r["body"]


def m_endpoints(run, c):
    host = urlparse(run.target).hostname
    seen, queue, urls, forms, params = set(), [run.target], set(), [], {}
    with ThreadPoolExecutor(run.workers) as ex:
        while queue and len(seen) < run.max_pages and not run.stop.is_set():
            batch = []
            while queue and len(batch) < run.workers and len(seen) < run.max_pages:
                u = queue.pop(0)
                k = norm_key(u)
                if k in seen:
                    continue
                seen.add(k)
                batch.append(u)
            for u, r in zip(batch, ex.map(c.request, batch)):
                if not r["status"] or "html" not in r["h"].get("content-type", ""):
                    continue
                pg = Page()
                pg.feed(r["body"])
                for l in pg.links:
                    a = urljoin(u, l).split("#")[0]
                    pa = urlparse(a)
                    if pa.scheme in ("http", "https") and pa.hostname == host and a not in urls:
                        urls.add(a)
                        queue.append(a)
                for sc in pg.scripts:
                    a = urljoin(u, sc)
                    if urlparse(a).hostname == host:
                        run.js_urls.add(a)
                for f in pg.forms:
                    forms.append({"page": u, "action": urljoin(u, f["action"]), "method": f["method"], "inputs": f["inputs"]})
    for u in urls:
        for name, _ in parse_qsl(urlparse(u).query, keep_blank_values=True):
            params.setdefault(name, set()).add(urlparse(u).path)
    collect_js(run, c)
    apis = set()
    for body in run.js.values():
        apis.update(m.group(1) for m in API_RE.finditer(body))
    run.data["endpoints"] = {
        "pages_crawled": len(seen), "urls": sorted(urls), "forms": forms,
        "parameters": {k: sorted(v) for k, v in params.items()},
        "js_files": sorted(run.js_urls), "api_references_in_js": sorted(apis)[:500]}
    (tdir("recon", run.slug) / f"{run.slug}_endpoint_inventory_{run.id}.json").write_text(json.dumps(run.data["endpoints"], indent=2))
    run.log(f"Crawled {len(seen)} pages, {len(urls)} URLs, {len(forms)} forms, {len(run.js_urls)} JS files, {len(apis)} API refs")
    if not urls:
        run.log("Few HTML links found - likely a single-page app. API references from JS are the better map.")


# --------------------------------------------------------------------------
# Directory discovery (rate limited, soft-404 aware)
# --------------------------------------------------------------------------
BUILTIN_PATHS = ["admin", "administrator", "login", "register", "api", "rest", "ftp", "backup", "backups", "uploads",
                 "assets", "static", "config", "console", "dashboard", "docs", "swagger", "api-docs", "metrics",
                 "health", "status", "test", "dev", "old", "tmp", "logs", "private", "public", "robots.txt",
                 "sitemap.xml", ".git/HEAD", ".env", ".htaccess", "backup.zip", "db.sql", "phpinfo.php",
                 "server-status", "actuator", "graphql", "support", "profile", "account", "security.txt",
                 ".well-known/security.txt", "encryptionkeys", "snippets", "promotion"]
RISKY = re.compile(r"(\.git|\.env|\.svn|backup|\.bak|\.sql|dump|phpinfo|\.htpasswd|encryptionkeys|server-status|actuator)", re.I)


def m_directories(run, c):
    words = list(BUILTIN_PATHS)
    if run.wordlist:
        words += [w.strip() for w in run.wordlist.read_text(errors="ignore").splitlines()
                  if w.strip() and not w.startswith("#")]
        run.log(f"Wordlist: {run.wordlist}")
    words = list(dict.fromkeys(w.lstrip("/") for w in words))[:run.max_dirs]
    if run.exts:
        words += [w + e for w in words if "." not in w.rsplit("/", 1)[-1] and not w.endswith("/") for e in run.exts]
    bl = c.request(urljoin(run.target, "/" + secrets.token_hex(8)))
    bl_hash = hashlib.md5(bl["body"].encode()).hexdigest()

    def probe(w):
        if run.stop.is_set():
            return None
        return w, c.request(urljoin(run.target, "/" + w))

    hits, n = [], 0
    run.log(f"Testing {len(words)} paths with {run.workers} workers")
    with ThreadPoolExecutor(run.workers) as ex:
        for res in ex.map(probe, words):
            if not res:
                continue
            w, r = res
            n += 1
            if n % 250 == 0:
                run.log(f"directories: {n}/{len(words)} tested, {len(hits)} hits")
            if r["status"] not in (200, 204, 301, 302, 307, 401, 403):
                continue
            if r["status"] == bl["status"] and hashlib.md5(r["body"].encode()).hexdigest() == bl_hash:
                continue
            hits.append({"path": "/" + w, "status": r["status"], "size": len(r["body"]),
                         "type": r["h"].get("content-type", "")})
            if r["status"] == 200 and RISKY.search(w):
                run.add(f"Sensitive resource reachable: /{w}", V_HIGH_DISC, "/" + w,
                        "A path commonly associated with secrets, backups or debug data returned content.",
                        "Potential disclosure of credentials, source or configuration.",
                        "Remove the resource from the web root or restrict it with authentication.",
                        f"GET /{w} -> {r['status']} ({len(r['body'])} bytes)", "Phase 2/3")
            if r["status"] == 200 and re.search(r"index of /|listing directory", r["body"][:2000], re.I):
                run.add(f"Directory listing enabled: /{w}", V_MED_DISC, "/" + w,
                        "The server returns an automatic directory index.", "Exposes file names and possibly sensitive files.",
                        "Disable directory indexing.", f"GET /{w} -> directory index", "Phase 3")
            if r["status"] in (200, 301, 302, 401, 403) and re.search(r"admin|console|dashboard|manager", w, re.I):
                run.add(f"Administrative interface exposed: /{w}", V_INFO, "/" + w,
                        "An administrative-looking path responds.", "Increases attack surface.",
                        "Restrict by network/IP and enforce strong authentication.", f"HTTP {r['status']}", "Phase 3")
    run.data["directories"] = hits
    (tdir("recon", run.slug) / f"{run.slug}_directories_{run.id}.json").write_text(json.dumps(hits, indent=2))
    run.log(f"{n} paths tested, {len(hits)} interesting responses")


# --------------------------------------------------------------------------
# Phase 8 - API checks (read-only)
# --------------------------------------------------------------------------
API_PATHS = ["/api", "/api/", "/rest", "/rest/", "/graphql", "/swagger.json", "/openapi.json", "/api-docs",
             "/v1", "/v2", "/api/v1", "/actuator", "/actuator/health", "/health", "/api/Users", "/api/Products",
             "/rest/products/search?q=", "/rest/admin/application-version"]
SENSITIVE_KEYS = re.compile(r'"(password|passwd|token|secret|api_?key|email|ssn|card)"', re.I)


API_EXTRA = ["/api/Challenges", "/rest/user/whoami", "/rest/memories", "/api/config", "/config.json",
             "/.well-known/openid-configuration", "/api/v2", "/api/swagger", "/swagger-ui.html", "/v3/api-docs",
             "/server-status", "/api/health", "/api/status", "/api/version"]


def m_api(run, c):
    paths = list(dict.fromkeys(API_PATHS + API_EXTRA))

    def probe(p):
        return p, c.request(urljoin(run.target, p))

    with ThreadPoolExecutor(run.workers) as ex:
        results = list(ex.map(probe, paths))
    rows = []
    for p, r in results:
        rows.append({"method": "GET", "path": p, "status": r["status"], "content_type": r["h"].get("content-type", ""),
                     "size": len(r["body"])})
        if r["status"] != 200:
            continue
        ct = r["h"].get("content-type", "")
        if re.search(r"swagger|openapi|api-docs", p):
            run.add(f"API documentation exposed: {p}", V_INFO, p, "API schema is publicly reachable.",
                    "Gives attackers a map of every endpoint.", "Restrict docs to authenticated/internal users.",
                    f"GET {p} -> 200", "Phase 8")
        if "actuator" in p and "health" not in p:
            run.add("Spring Actuator endpoint exposed", V_MED_DISC, p, "Management endpoints are reachable.",
                    "May leak environment, beans, or heap data.", "Disable or secure actuator endpoints.", "", "Phase 3/8")
        if "json" in ct:
            keys = sorted({m.group(1).lower() for m in SENSITIVE_KEYS.finditer(r["body"])})
            if keys:
                run.add(f"Unauthenticated API returns sensitive-looking fields: {p}", V_MED_DISC, p,
                        "A JSON endpoint reachable without credentials includes field names such as: " + ", ".join(keys) + ".",
                        "Possible excessive data exposure (CANDIDATE - verify manually).",
                        "Require authentication/authorization and return only needed fields.",
                        f"GET {p} -> 200, field names only: {keys} (values not stored)", "Phase 8")
    gq = next((x for x in rows if x["path"] == "/graphql" and x["status"] in (200, 400)), None)
    if gq:
        r = c.request(urljoin(run.target, "/graphql"), "POST", {"Content-Type": "application/json"},
                      json.dumps({"query": "{__schema{queryType{name}}}"}).encode())
        if "queryType" in r["body"]:
            run.add("GraphQL introspection enabled", V_LOW, "/graphql", "Schema introspection answers anonymous queries.",
                    "Reveals the full schema to attackers.", "Disable introspection in production.", "", "Phase 8")
    ok = next((x["path"] for x in rows if x["status"] == 200), None)
    if ok and not run.stop.is_set():
        got429 = False
        for _ in range(15):
            if c.request(urljoin(run.target, ok), nodelay=True)["status"] == 429:
                got429 = True
                break
        if not got429:
            run.add("No rate limiting seen on burst of 15 requests", V_INFO, ok,
                    "A short burst was not throttled. This is only a hint.",
                    "Brute-force and scraping may be possible - test login/reset endpoints manually.",
                    "Add per-IP/per-account rate limits, especially on authentication.", "", "Phase 4/8")
    run.data["api"] = rows
    run.log(f"API probe: {sum(1 for x in rows if x['status'] == 200)} of {len(rows)} paths returned 200")


# --------------------------------------------------------------------------
# Phase 9 - Frontend audit
# --------------------------------------------------------------------------
JS_PATTERNS = {
    "AWS access key id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "Hard-coded JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Generic secret assignment": re.compile(r"""(?i)(?:api[_-]?key|secret|passwd|password)["']?\s*[:=]\s*["'][^"'\s]{8,}["']"""),
}
DANGEROUS_SINKS = re.compile(r"\b(innerHTML|outerHTML|document\.write|eval\(|bypassSecurityTrust\w*)")


JQ_RE = re.compile(r"jQuery(?: JavaScript Library)? v(\d+)\.(\d+)\.(\d+)")
INTERNAL_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")


def m_frontend(run, c):
    collect_js(run, c)
    rep = {"files": list(run.js), "secrets": [], "sinks": {}, "source_maps": [], "storage_use": []}
    for url, body in run.js.items():
        for name, rx in JS_PATTERNS.items():
            for m in list(rx.finditer(body))[:3]:
                s = m.group(0)
                masked = s[:6] + "..." + s[-2:]
                rep["secrets"].append({"file": url, "type": name, "masked": masked})
                run.add(f"Possible secret in JavaScript: {name}", V_MED_DISC, url,
                        "A pattern resembling a credential appears in client-side code.",
                        "Client code is public; secrets here are compromised by design (verify - may be false positive).",
                        "Remove secrets from frontend bundles; rotate if real.", f"{url}: {masked}", "Phase 9")
        jq = JQ_RE.search(body[:3000])
        if jq and tuple(int(x) for x in jq.groups()) < (3, 5, 0):
            run.add(f"Outdated jQuery {'.'.join(jq.groups())}", V_LOW_LI, url,
                    "jQuery older than 3.5.0 has known XSS issues (CVE-2020-11022, CVE-2020-11023).",
                    "Exploitable only if the app passes untrusted HTML to jQuery.",
                    "Upgrade jQuery to the latest 3.x release.", f"{url}: jQuery {'.'.join(jq.groups())}", "Phase 9")
        ips = sorted(set(INTERNAL_IP.findall(body)))[:5]
        if ips:
            run.add("Possible internal IP addresses in JavaScript (verify)", V_INFO, url,
                    "Strings resembling private IP addresses appear in client code (may be version numbers).",
                    "Can reveal internal network layout.", "Remove internal addresses from public bundles.",
                    f"{url}: {ips}", "Phase 9")
        sinks = sorted({m.group(1) for m in DANGEROUS_SINKS.finditer(body)})
        if sinks:
            rep["sinks"][url] = sinks
        if re.search(r"localStorage\.setItem|sessionStorage\.setItem", body):
            rep["storage_use"].append(url)
        if "sourceMappingURL=" in body[-400:]:
            mp = c.request(url + ".map")
            if mp["status"] == 200:
                rep["source_maps"].append(url + ".map")
                run.add("JavaScript source map exposed", V_LOW, url + ".map",
                        "Source maps are publicly downloadable.", "Original source code is easier to analyse.",
                        "Do not deploy .map files to production.", f"GET {url}.map -> 200", "Phase 9")
    if rep["storage_use"]:
        run.log("Client code writes to Web Storage - manually check whether tokens are stored there (XSS-stealable).")
    if rep["sinks"]:
        run.log("Potential DOM sinks found. Review in DevTools/Semgrep for DOM XSS (manual).")
    run.data["frontend"] = rep
    (tdir("recon", run.slug) / f"{run.slug}_frontend_{run.id}.json").write_text(json.dumps(rep, indent=2))


# --------------------------------------------------------------------------
# External tools (Kali) - fixed argument lists, no shell
# --------------------------------------------------------------------------
def m_external(run, c):
    u = urlparse(run.target)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    if not re.fullmatch(r"[A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\]", host) or host.startswith("-"):
        run.log("Host rejected for external tools")
        return
    cmds = {"whatweb": ["whatweb", "-a", "1", run.target],
            "nmap": ["nmap", "-sV", "-Pn", "-p", str(port), "--reason", host],
            "nikto": ["nikto", "-h", run.target, "-maxtime", "120s"],
            "sslscan": ["sslscan", f"{host}:{port}"]}
    run.data["external"] = {}
    for tool in run.opts.get("external", []):
        if run.stop.is_set():
            break
        if tool not in cmds or (tool == "sslscan" and u.scheme != "https"):
            continue
        if not shutil.which(tool):
            run.log(f"{tool}: not installed (sudo apt install {tool})")
            continue
        run.log(f"Running {' '.join(cmds[tool])}")
        path = tdir("scans", run.slug) / f"{run.slug}_{tool}_{run.id}.txt"
        try:
            with open(path, "w") as fh:
                proc = subprocess.Popen(cmds[tool], stdout=fh, stderr=subprocess.STDOUT, text=True)
                t0 = time.time()
                while proc.poll() is None:
                    if run.stop.is_set() or time.time() - t0 > 300:
                        proc.kill()
                        break
                    time.sleep(0.5)
                proc.wait()
        except Exception as e:
            run.log(f"{tool} failed: {e}")
            continue
        out = path.read_text(errors="ignore")
        run.data["external"][tool] = {"file": str(path), "tail": out[-1500:]}
        run.log(f"{tool}: finished, {len(out)} bytes saved to {path}")


def m_methods(run, c):
    r = c.request(run.target, "OPTIONS")
    allow = r["h"].get("allow", "") or r["h"].get("access-control-allow-methods", "")
    bad = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if re.search(rf"\b{m}\b", allow, re.I)]
    if bad:
        run.add("Risky HTTP methods advertised", V_LOW, "/", "The server advertises methods that are rarely needed on a public site: "
                + ", ".join(bad) + ".", "Unneeded methods enlarge the attack surface.",
                "Disable unused HTTP methods at the web server or proxy.", f"Allow: {allow}", "Phase 3")
    t = c.request(run.target, "TRACE")
    if t["status"] == 200 and t["body"].lstrip().upper().startswith("TRACE"):
        run.add("HTTP TRACE enabled", V_LOW, "/", "The server echoes TRACE requests.",
                "Can aid cross-site tracing attacks that expose headers.", "Disable TRACE.", "TRACE / -> 200 echo", "Phase 3")


MODULES = [("recon", m_recon), ("headers", m_headers), ("tls", m_tls), ("cors", m_cors), ("methods", m_methods),
           ("endpoints", m_endpoints), ("directories", m_directories), ("api", m_api),
           ("frontend", m_frontend), ("cookies", m_cookies), ("external", m_external)]


def execute(run):
    t0 = time.time()
    try:
        c = Client(run.target, float(run.opts.get("delay", 0.3)), bool(run.opts.get("insecure")),
                   float(run.opts.get("timeout", 8)), run.opts.get("extra_headers"), None, run.stop)
        active = [(n, f) for n, f in MODULES if n in run.modules]
        for i, (name, fn) in enumerate(active):
            if run.stop.is_set():
                run.log("Stopped by user.")
                break
            run.current, run.progress = name, int(100 * i / max(len(active), 1))
            run.log(f"== {name} ==")
            try:
                fn(run, c)
            except Exception as e:
                run.log(f"{name} failed: {e}")
        el = max(time.time() - t0, 0.01)
        run.data["stats"] = {"requests": c.count, "seconds": round(el, 1), "req_per_sec": round(c.count / el, 1),
                             "workers": run.workers, "delay": run.opts.get("delay")}
        run.log(f"Sent {c.count} requests in {el:.1f}s (~{c.count / el:.1f} req/s, {run.workers} workers)")
        status = "stopped" if run.stop.is_set() else "done"
        run.current, run.progress = "reports", 100
        merge_findings(run.findings, run.slug)
        append_run(run.slug, {"run_id": run.id, "target": run.target, "started": run.started, "finished": now(),
                              "status": status, "modules": run.modules, "stats": run.data["stats"],
                              "findings_in_scan": len(run.findings)})
        (tdir("logs", run.slug) / f"{run.slug}_scan_{run.id}.log").write_text("\n".join(run.logs))
        (tdir("recon", run.slug) / f"{run.slug}_run_{run.id}.json").write_text(json.dumps(
            {"target": run.target, "started": run.started, "data": run.data}, indent=2, default=str))
        run.log("Writing reports...")
        files = write_reports(run.slug)
        run.log("Reports saved: " + ", ".join(Path(f).name for f in files))
        run.log(f"{'Stopped' if status == 'stopped' else 'Done'}. {len(run.findings)} findings merged into the register for {run.slug}.")
        run.status = status
    except Exception as e:
        run.status = "error"
        run.log(f"Fatal: {e}")


# --------------------------------------------------------------------------
# Reporting (HTML + optional PDF)
# --------------------------------------------------------------------------
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
TOOLS_USED = "Python 3 (urllib, ssl, socket), Flask; optional: Nmap, WhatWeb, Nikto, SSLScan; manual: Burp Suite, OWASP ZAP, SQLmap"


def report_data(slug):
    fs = load_findings(slug)
    fs.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), -(f["score"] or 0)))
    target = fs[0]["target"] if fs else slug
    return {"report_name": report_name(slug), "target": target, "slug": slug, "generated": now(),
            "generated_by": f"Automated Website VAPT Framework v{__version__} by {AUTHOR} ({AUTHOR_URL})",
            "summary": {s_: sum(1 for f in fs if f["severity"] == s_) for s_ in SEV_ORDER},
            "total_findings": len(fs),
            "scans": load_runs(slug), "findings": fs}


def build_report(slug):
    e = html.escape
    d = report_data(slug)
    fs, counts, name, target = d["findings"], d["summary"], d["report_name"], d["target"]
    rows = "".join(f"<tr><td>{e(f['id'])}</td><td>{e(f['title'])}</td><td class='s {f['severity']}'>{f['severity']}</td>"
                   f"<td>{f['score'] if f['score'] is not None else '-'}</td><td>{e(f['status'])}</td></tr>" for f in fs)
    det = ""
    for f in fs:
        det += (f"<div class='f'><h3>{e(f['id'])} - {e(f['title'])}</h3>"
                f"<p><b>Severity:</b> <span class='s {f['severity']}'>{f['severity']}</span> (CVSS {f['score']}, <code>{e(f['vector'])}</code>)<br>"
                f"<b>Affected component:</b> <code>{e(f['component'])}</code> &nbsp; <b>Phase:</b> {e(f.get('phase', ''))} &nbsp; <b>Status:</b> {e(f['status'])}</p>"
                f"<p><b>Description:</b> {e(f['description'])}</p><p><b>Impact / business impact:</b> {e(f['impact'])}</p>"
                f"<p><b>Proof of concept / evidence:</b></p><pre>{e(f['evidence'] or 'See evidence/ folder')}</pre>"
                f"<p><b>Recommendation:</b> {e(f['recommendation'])}</p>"
                f"<p><b>Retest notes:</b> {e(f['notes'] or 'Not yet retested')}</p></div>")
    retest = "".join(f"<li>{e(f['id'])} {e(f['title'])}: {e(f['status'])}</li>" for f in fs if f["status"] != "Open") or "<li>No retests recorded yet.</li>"
    scans = "".join(f"<tr><td>{e(r.get('run_id', ''))}</td><td>{e(r.get('started', ''))}</td><td>{e(r.get('status', ''))}</td>"
                    f"<td>{r.get('stats', {}).get('requests', '-')}</td><td>{e(', '.join(r.get('modules', [])))}</td></tr>"
                    for r in d["scans"]) or "<tr><td colspan='5'>No scans recorded.</td></tr>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{e(name)}</title><style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:30px auto;padding:0 16px;color:#111}}*{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}a{{color:#000}}
h1{{font-size:30px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #999;padding:6px;text-align:left}}
pre{{background:#eee;padding:8px;white-space:pre-wrap;word-break:break-word}}.f{{border-top:2px solid #000;margin-top:24px;page-break-inside:avoid}}
.s{{font-weight:700}}.Critical{{color:#fff;background:#000;padding:1px 6px;border-radius:3px}}.High{{color:#000;text-decoration:underline;text-decoration-thickness:2px}}.Medium{{color:#222}}.Low{{color:#555;font-weight:400}}.Informational{{color:#777;font-style:italic;font-weight:400}}
.cover{{text-align:center;padding:80px 0;page-break-after:always}}</style></head><body>
<div class="cover"><h1>Website Vulnerability Assessment &amp; Penetration Test Report</h1><h2>Target: {e(target)}</h2><p>{e(name)}<br>Generated {d['generated']}</p><p style="color:#555">Generated by Automated Website VAPT Framework v{__version__} by {e(AUTHOR)} &middot; <a href="{e(AUTHOR_URL)}">LinkedIn</a></p></div>
<h2>1. Executive summary</h2><p>{d['total_findings']} findings recorded for {e(target)}: {counts['Critical']} Critical, {counts['High']} High, {counts['Medium']} Medium, {counts['Low']} Low, {counts['Informational']} Informational.
Automated checks are indicators and must be validated; items marked CANDIDATE need manual confirmation.</p>
<h2>2. Scope</h2><p>Scope: {e(target)}. Testing consisted of non-destructive automated checks plus any manual findings recorded in this register.</p>
<h2>3. Methodology</h2><p>OWASP WSTG-aligned phases: reconnaissance, attack-surface mapping, configuration, authentication, authorization, input validation, session, API, client-side, validation, CVSS 3.1 scoring.</p>
<h2>4. Environment and tools</h2><p>{e(TOOLS_USED)}</p>
<h2>5. Scans performed</h2><table><tr><th>Scan</th><th>Started (UTC)</th><th>Status</th><th>Requests</th><th>Modules</th></tr>{scans}</table>
<h2>6. Vulnerability summary</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Status</th></tr>{rows}</table>
<h2>7. Detailed findings</h2>{det or '<p>No findings.</p>'}
<h2>8. Retesting results</h2><ul>{retest}</ul>
<h2>9. Conclusion</h2><p>Prioritise Critical/High items, then re-run the scan and update statuses to Retest Passed.</p><hr><p style="font-size:12px;color:#555">Automated Website VAPT Framework v{__version__} &copy; 2026 {e(AUTHOR)} &middot; MIT License &middot; <a href="{e(AUTHOR_URL)}">{e(AUTHOR_URL)}</a></p></body></html>"""


def write_reports(slug, pdf=True):
    """Write <slug>_VAPT_Report.html/.json (and .pdf if an engine exists) into reports/<slug>/."""
    d, name, files = tdir("reports", slug), report_name(slug), []
    (d / f"{name}.html").write_text(build_report(slug))
    files.append(str(d / f"{name}.html"))
    (d / f"{name}.json").write_text(json.dumps(report_data(slug), indent=2))
    files.append(str(d / f"{name}.json"))
    if pdf:
        data = make_pdf(build_report(slug))
        if data:
            (d / f"{name}.pdf").write_bytes(data)
            files.append(str(d / f"{name}.pdf"))
    return files


def make_pdf(html_text):
    if shutil.which("wkhtmltopdf"):
        p = subprocess.run(["wkhtmltopdf", "-q", "-", "-"], input=html_text.encode(), capture_output=True, timeout=120)
        if p.returncode == 0:
            return p.stdout
    try:
        from weasyprint import HTML  # optional
        return HTML(string=html_text).write_pdf()
    except Exception:
        return None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.before_request
def guard():
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)
    if request.method in ("POST", "PATCH", "DELETE") and not request.is_json:
        abort(400)


@app.get("/")
def index():
    return Response(INDEX_HTML.replace("__VERSION__", __version__), mimetype="text/html")


@app.post("/api/scan")
def api_scan():
    d = request.get_json() or {}
    target = (d.get("target") or "").strip()
    ok, why = check_scope(target)
    if not ok:
        return jsonify(error=why), 400
    lab = why.startswith("lab")
    try:
        opts = dict(d)
        opts["workers"] = max(1, min(int(d.get("workers", 1)), 64))
        opts["delay"] = max(0.0, float(d.get("delay", 0.3)))
        opts["timeout"] = max(2.0, min(float(d.get("timeout", 8)), 30.0))
        opts["max_pages"] = max(1, min(int(d.get("max_pages", 40)), 500))
        opts["max_dirs"] = max(1, min(int(d.get("max_dirs", 200)), 50000))
    except (TypeError, ValueError):
        return jsonify(error="Invalid numeric option"), 400
    notes = []
    if not lab:  # be a good citizen on other people's servers
        if opts["workers"] > 4:
            opts["workers"] = 4
            notes.append("workers capped at 4")
        if opts["delay"] < 0.25:
            opts["delay"] = 0.25
            notes.append("delay raised to 0.25s")
        if opts["max_dirs"] > 500:
            opts["max_dirs"] = 500
            notes.append("path list capped at 500")
    extra = {}
    for line in str(d.get("headers") or "").splitlines()[:10]:
        if ":" in line:
            k, v = (x.strip() for x in line.split(":", 1))
            if re.fullmatch(r"[A-Za-z0-9\-]{1,40}", k) and k.lower() not in ("host", "content-length") and len(v) < 300:
                extra[k] = v
    opts["extra_headers"] = extra
    run = Run(target, opts)
    run.log(f"Scope OK: {why}")
    if notes:
        run.log("Remote-target safety limits applied: " + ", ".join(notes))
    RUNS[run.id] = run
    threading.Thread(target=execute, args=(run,), daemon=True).start()
    return jsonify(run_id=run.id)


@app.get("/api/run/<rid>")
def api_run(rid):
    r = RUNS.get(rid) or abort(404)
    return jsonify(status=r.status, log=r.logs, findings=len(r.findings), progress=r.progress, current=r.current, slug=r.slug)


@app.post("/api/run/<rid>/stop")
def api_stop(rid):
    r = RUNS.get(rid) or abort(404)
    r.stop.set()
    return jsonify(ok=True)


@app.get("/api/info")
def api_info():
    cands = ("/usr/share/wordlists/dirb/common.txt", "/usr/share/wordlists/dirb/big.txt",
             "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "/usr/share/seclists/Discovery/Web-Content/common.txt")
    return jsonify(cpu=os.cpu_count() or 2, wordlists=[p for p in cands if os.path.isfile(p)],
                   tools={t: bool(shutil.which(t)) for t in ("whatweb", "nmap", "nikto", "sslscan", "wkhtmltopdf")})


@app.get("/api/targets")
def api_targets():
    out = []
    for slug in all_slugs():
        fs, runs = load_findings(slug), load_runs(slug)
        out.append({"slug": slug, "name": report_name(slug), "target": fs[0]["target"] if fs else slug,
                    "total": len(fs), "counts": {s_: sum(1 for f in fs if f["severity"] == s_) for s_ in SEV_ORDER},
                    "last_scan": runs[-1].get("finished", "") if runs else ""})
    return jsonify(out)


@app.get("/api/findings")
def api_findings():
    slug = request.args.get("t")
    if slug:
        return jsonify(load_findings(slug) if slug in all_slugs() else [])
    return jsonify(load_findings())


@app.post("/api/findings")
def api_add_finding():
    d = request.get_json() or {}
    target = (d.get("target") or "").strip()
    if not target or not d.get("title"):
        return jsonify(error="title and target are required"), 400
    try:
        v = "CVSS:3.1/" + "/".join(f"{k}:{d[k]}" for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"))
    except KeyError:
        return jsonify(error="missing CVSS metric"), 400
    if cvss31(v) is None:
        return jsonify(error="bad vector"), 400
    f = make_finding(target, "manual", d["title"], v, d.get("component", ""), d.get("description", ""),
                     d.get("impact", ""), d.get("recommendation", ""), d.get("evidence", ""), d.get("phase", "Manual"))
    merge_findings([f])
    write_reports(target_slug(target), pdf=False)
    return jsonify(f)


@app.patch("/api/findings/<fid>")
def api_patch(fid):
    d = request.get_json() or {}
    hit = None
    with LOCK:
        for slug in all_slugs():
            reg = load_findings(slug)
            for f in reg:
                if f["id"] == fid:
                    if d.get("status") in ("Open", "In Progress", "Remediated", "Retest Passed", "Reopened", "Accepted Risk"):
                        f["status"] = d["status"]
                    if "notes" in d:
                        f["notes"] = str(d["notes"])[:4000]
                    save_findings(slug, reg)
                    hit = (slug, f)
                    break
            if hit:
                break
    if not hit:
        abort(404)
    write_reports(hit[0], pdf=False)
    return jsonify(hit[1])


@app.get("/report/<slug>/<ext>")
def report_file(slug, ext):
    if slug not in all_slugs() or ext not in ("html", "json", "pdf"):
        abort(404)
    name = report_name(slug)
    disp = "inline" if ext == "html" and not request.args.get("dl") else "attachment"
    hdr = {"Content-Disposition": f'{disp}; filename="{name}.{ext}"'}
    if ext == "html":
        return Response(build_report(slug), mimetype="text/html", headers=hdr)
    if ext == "json":
        return Response(json.dumps(report_data(slug), indent=2), mimetype="application/json", headers=hdr)
    pdf = make_pdf(build_report(slug))
    if not pdf:
        return Response("PDF engine not found. Run: sudo apt install -y wkhtmltopdf  (or open the HTML report and use Print > Save as PDF)",
                        status=501, mimetype="text/plain")
    return Response(pdf, mimetype="application/pdf", headers=hdr)


@app.post("/api/export/<slug>")
def api_export(slug):
    if slug not in all_slugs():
        abort(404)
    files = write_reports(slug)
    note = "" if any(f.endswith(".pdf") for f in files) else "PDF skipped: sudo apt install -y wkhtmltopdf"
    return jsonify(files=files, note=note)


@app.get("/api/cvss")
def api_cvss():
    s = cvss31(request.args.get("v", ""))
    return jsonify(score=s, severity=severity(s))


INDEX_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><title>VAPT Framework</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="author" content="Shrayan Biswas"><style>
:root{--bg:#000;--fg:#f2f2f2;--mid:#9a9a9a;--dim:#5c5c5c;--line:#2a2a2a}
:root.inv{--bg:#f3f3f3;--fg:#0a0a0a;--mid:#555;--dim:#8a8a8a;--line:#c9c9c9}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 "Helvetica Neue",Helvetica,Arial,sans-serif;letter-spacing:.01em;transition:background .4s,color .4s}
a{color:var(--fg);text-decoration:underline;text-underline-offset:3px}a:hover{opacity:.6}
.hero{position:relative;overflow:hidden;border-bottom:1px solid var(--line);padding:64px 28px 36px}
.hero h1{margin:0;font-weight:200;font-size:clamp(48px,11vw,132px);line-height:.88;letter-spacing:-.05em}
.eyebrow{font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--mid)}
.rings{position:absolute;right:-110px;top:-110px;width:520px;height:520px;opacity:.5;pointer-events:none}
.rings circle{fill:none;stroke:var(--fg);stroke-width:.7;transform-origin:200px 200px;animation:spin 80s linear infinite}
.rings circle:nth-child(even){stroke-dasharray:1 7;animation-duration:120s;animation-direction:reverse}
.rings circle:nth-child(3n){stroke-dasharray:30 12;animation-duration:50s}
.rings .dot{fill:var(--fg);stroke:none;animation:pulse 4s ease-in-out infinite}
.live .rings circle{animation-duration:14s}.live .rings .dot{animation-duration:1.2s}
@keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{50%{opacity:.15}}
@media (prefers-reduced-motion:reduce){.rings circle,.rings .dot{animation:none}}
nav{display:flex;gap:4px;border-bottom:1px solid var(--line);padding:0 20px;overflow-x:auto}
nav button{background:none;border:0;border-bottom:1px solid transparent;color:var(--mid);padding:16px 14px;cursor:pointer;font:inherit;font-size:11px;letter-spacing:.24em;text-transform:uppercase;margin-bottom:-1px}
nav button:hover{color:var(--fg)}nav button.on{color:var(--fg);border-bottom-color:var(--fg)}
main{padding:28px 20px;max-width:1120px;margin:auto}
.card{border:1px solid var(--line);padding:24px;margin-bottom:20px}
label{display:block;margin:14px 0 4px;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--mid)}
input,select,textarea{background:transparent;color:var(--fg);border:0;border-bottom:1px solid var(--line);border-radius:0;padding:9px 2px;width:100%;font:inherit;outline:none;transition:border-color .2s}
input:focus,select:focus,textarea:focus{border-bottom-color:var(--fg)}
textarea{border:1px solid var(--line);padding:8px}select option{background:var(--bg);color:var(--fg)}
input[type=checkbox]{accent-color:var(--fg);width:auto;margin-right:8px}
button.go{background:var(--fg);color:var(--bg);border:1px solid var(--fg);border-radius:0;padding:12px 28px;cursor:pointer;margin-top:18px;font:inherit;font-size:11px;letter-spacing:.24em;text-transform:uppercase;transition:all .2s}
button.go:hover{background:transparent;color:var(--fg)}
.mods label{display:inline-block;margin:6px 18px 6px 0;color:var(--fg);letter-spacing:.06em;text-transform:none;font-size:13px}
pre{border:1px solid var(--line);padding:14px;max-height:340px;overflow:auto;white-space:pre-wrap;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;color:var(--mid)}
.tab{display:none}.tab.on{display:block;animation:fade .5s}@keyframes fade{from{opacity:0;transform:translateY(6px)}}
table{width:100%;border-collapse:collapse}th{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--mid);font-weight:400}
td,th{padding:10px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
.Critical{background:var(--fg);color:var(--bg);font-weight:700;padding:2px 8px}
.High{border:1px solid var(--fg);font-weight:700;padding:1px 7px}
.Medium{border:1px dashed var(--mid);padding:1px 7px}
.Low{color:var(--mid)}.Informational{color:var(--dim);font-style:italic}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:6px 22px}
.warn,.mid{color:var(--mid)}.track{height:2px;background:var(--line);margin-top:22px}#bar{height:2px;width:0;background:var(--fg);transition:width .6s}
details{margin:6px 0}summary{cursor:pointer;color:var(--mid)}
footer{padding:36px 20px;text-align:center;color:var(--mid);border-top:1px solid var(--line);margin-top:30px;font-size:12px;letter-spacing:.06em;line-height:2}
</style></head><body>
<header class="hero"><svg class="rings" viewBox="0 0 400 400" aria-hidden="true"><circle cx="200" cy="200" r="190"/><circle cx="200" cy="200" r="170"/><circle cx="200" cy="200" r="150"/><circle cx="200" cy="200" r="130"/><circle cx="200" cy="200" r="110"/><circle cx="200" cy="200" r="90"/><circle cx="200" cy="200" r="70"/><circle cx="200" cy="200" r="50"/><circle class="dot" cx="200" cy="200" r="6"/></svg>
<div class="eyebrow">automated website vulnerability assessment</div><h1>vapt<br>framework</h1>
<div class="eyebrow" style="margin-top:26px">v__VERSION__ &nbsp;/&nbsp; by <a href="https://www.linkedin.com/in/shrayan-biswas-a1259225a/" target="_blank" rel="noopener noreferrer">Shrayan Biswas</a> &nbsp;/&nbsp; <a href="#" id="inv">invert</a></div></header>
<nav><button class="on" data-t="scan">Scan</button><button data-t="find">Findings</button><button data-t="manual">Manual testing</button><button data-t="rep">Report</button></nav>
<main>
<section id="scan" class="tab on"><div class="card">
<label>Target URL</label><input id="target" value="http://127.0.0.1:3000">
<div class="mid" style="margin:10px 0">Lab presets: <a href="#" onclick="preset('http://127.0.0.1:3000');return false">Juice Shop :3000</a> |
<a href="#" onclick="preset('http://127.0.0.1:8081');return false">DVWA :8081</a> |
<a href="#" onclick="preset('http://127.0.0.1:8082/WebGoat');return false">WebGoat :8082</a> |
<a href="#" onclick="preset('http://127.0.0.1:8888');return false">crAPI :8888</a></div>
<label><input type="checkbox" id="insecure" style="width:auto"> Accept self-signed certificates (lab only)</label>
<label>Modules</label><div class="mods" id="mods"></div>
<label>External Kali tools (if installed)</label><div class="mods" id="ext"></div>
<div class="row"><div><label>Intensity profile <span id="hw" class="mid"></span></label>
<select id="prof" onchange="prof()"><option value="gentle">Gentle (1 worker - remote safe)</option><option value="balanced" selected>Balanced (8 workers)</option><option value="max">Lab-max (many workers, no delay)</option></select></div>
<div><label>Workers (parallel threads)</label><input id="workers" type="number" value="8"></div>
<div><label>Global delay between requests (s)</label><input id="delay" type="number" step="0.05" value="0.1"></div>
<div><label>Request timeout (s)</label><input id="timeout" type="number" value="8"></div>
<div><label>Max pages to crawl</label><input id="pages" type="number" value="60"></div>
<div><label>Max paths to test</label><input id="dirs" type="number" value="1000"></div>
<div><label>Wordlist</label><select id="wl"><option value="">Built-in list (~45 paths)</option></select></div>
<div><label>Extra extensions (e.g. .bak,.zip)</label><input id="exts" placeholder="optional"></div></div>
<label>Custom headers (one per line, e.g. bug-bounty ID)</label><textarea id="hdrs" rows="2" placeholder="X-Bug-Bounty: yourhandle"></textarea>
<button class="go" onclick="startScan()">Run scan</button> <button class="go" id="stopb" style="display:none;background:transparent;color:var(--fg)" onclick="stopScan()">Stop</button> <span id="msg" class="warn"></span>
<div class="track"><div id="bar"></div></div>
<div id="cur" class="mid" style="margin-top:8px;font-size:12px"></div></div>
<div class="card"><b>Live log</b><pre id="log">No scan yet.</pre></div></section>

<section id="find" class="tab"><div class="card"><label>Target (each target has its own findings and report)</label><select id="ftarget" onchange="loadFindings()"></select><div id="counts" style="margin:10px 0"></div><table id="ftable"></table></div></section>

<section id="manual" class="tab"><div class="card"><b>Manual phases (not automated on purpose)</b>
<p>Use Burp Suite/ZAP/SQLmap yourself against your lab. Tick items off and record confirmed issues below.</p><div id="check"></div></div>
<div class="card"><b>Add a confirmed finding (CVSS 3.1)</b>
<div class="row"><div><label>Title</label><input id="m_title"></div><div><label>Target</label><input id="m_target" value="http://127.0.0.1:3000"></div>
<div><label>Component</label><input id="m_comp" placeholder="/api/profile/{id}"></div><div><label>Phase</label><input id="m_phase" value="Phase 5"></div></div>
<div class="row" id="vec"></div><p>Score: <b id="m_score">-</b></p>
<label>Description</label><textarea id="m_desc"></textarea><label>Impact</label><textarea id="m_imp"></textarea>
<label>Evidence (sanitized request/response)</label><textarea id="m_evi"></textarea><label>Recommendation</label><textarea id="m_rec"></textarea>
<button class="go" onclick="addManual()">Save finding</button></div></section>

<section id="rep" class="tab"><div class="card"><b>Reports (one per target)</b>
<p class="mid">Named <code>&lt;target&gt;_VAPT_Report</code> in HTML, PDF and JSON. They are also saved automatically to <code>~/VAPT-Project/reports/&lt;target&gt;/</code> after every scan. PDF needs <code>sudo apt install wkhtmltopdf</code>.</p>
<table id="rtable"></table></div></section>
</main>
<footer>Automated Website VAPT Framework v__VERSION__ &copy; 2026 <a href="https://www.linkedin.com/in/shrayan-biswas-a1259225a/" target="_blank" rel="noopener">Shrayan Biswas</a> &middot; <a href="https://www.linkedin.com/in/shrayan-biswas-a1259225a/" target="_blank" rel="noopener">LinkedIn</a> &middot; MIT License<br>Use only on systems you own or have permission to test.</footer>
<script>
const MODS=[["recon","Recon"],["headers","Headers"],["cookies","Cookies"],["tls","TLS"],["cors","CORS"],["methods","HTTP methods"],["endpoints","Endpoint map"],["directories","Directory audit"],["api","API probe"],["frontend","Frontend/JS"],["external","External tools"]];
const EXT=["whatweb","nmap","nikto","sslscan"];
const CHECK={"Phase 4 - Authentication":["Create two test accounts","Capture login in Burp; inspect session cookie","Check password policy and reset flow","Check session invalidation after logout","Controlled login rate-limit test","MFA / remember-me behaviour"],
"Phase 5 - Authorization":["Map resources owned by User A and User B","Replay A's requests with B's session (IDOR/BOLA)","Test admin-only functions as normal user (BFLA)","Forced browsing to unlinked pages"],
"Phase 6 - Input validation (lab only)":["SQL injection (Burp/SQLmap against Juice Shop/DVWA)","Reflected/stored/DOM XSS","Path traversal, command injection, SSTI","XXE and unsafe file upload","Capture evidence and remediation notes"],
"Phase 7/8 - Sessions & APIs":["JWT signature/expiry/alg handling","CSRF protection on state-changing requests","Mass assignment on PUT/POST","Excessive data exposure in API responses"],
"Phase 10 - Validation":["Reproduce each finding twice","Eliminate false positives","Avoid unnecessary data access","Attach evidence to evidence/ folder"]};
const $=id=>document.getElementById(id);const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const J=(u,m,b)=>fetch(u,{method:m||"GET",headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined}).then(r=>r.json());
$("mods").innerHTML=MODS.map(m=>`<label><input type=checkbox value="${m[0]}" checked> ${m[1]}</label>`).join("");
$("ext").innerHTML=EXT.map(m=>`<label><input type=checkbox value="${m}"> ${m}</label>`).join("");
document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>{document.querySelectorAll("nav button,.tab").forEach(x=>x.classList.remove("on"));b.classList.add("on");$(b.dataset.t).classList.add("on");if(b.dataset.t=="find")loadFindings();if(b.dataset.t=="rep")loadReports()});
const vals={AV:"NALP",AC:"LH",PR:"NLH",UI:"NR",S:"UC",C:"NLH",I:"NLH",A:"NLH"},defs={AV:"N",AC:"L",PR:"N",UI:"N",S:"U",C:"L",I:"N",A:"N"};
$("vec").innerHTML=Object.keys(vals).map(k=>`<div><label>${k}</label><select id="v_${k}" onchange="calc()">${[...vals[k]].map(o=>`<option ${o==defs[k]?"selected":""}>${o}</option>`).join("")}</select></div>`).join("");
function vec(){return Object.keys(vals).map(k=>k+":"+$("v_"+k).value).join("/")}
async function calc(){const r=await J("/api/cvss?v=CVSS:3.1/"+vec());$("m_score").textContent=r.score+" ("+r.severity+")"}calc();
let saved=JSON.parse(localStorage.getItem("vapt_check")||"{}");
$("check").innerHTML=Object.entries(CHECK).map(([k,v])=>`<details open><summary><b>${k}</b></summary>${v.map(i=>`<label style="color:#e5e5e5"><input type=checkbox style="width:auto" data-k="${esc(k+i)}" ${saved[k+i]?"checked":""}> ${esc(i)}</label>`).join("")}</details>`).join("");
$("check").onchange=e=>{saved[e.target.dataset.k]=e.target.checked;localStorage.setItem("vapt_check",JSON.stringify(saved))};
let INFO={cpu:4,wordlists:[]},RUN=null;
J("/api/info").then(i=>{INFO=i;$("hw").textContent="("+i.cpu+" CPU cores)";
$("wl").innerHTML='<option value="">Built-in list (~45 paths)</option>'+i.wordlists.map(w=>`<option value="${esc(w)}">${esc(w.split("/").slice(-2).join("/"))}</option>`).join("");prof()});
function prof(){const p=$("prof").value;const c={gentle:[1,0.5],balanced:[8,0.1],max:[Math.min(64,(INFO.cpu||2)*8),0]}[p];$("workers").value=c[0];$("delay").value=c[1]}
function preset(u){$("target").value=u}
async function startScan(){$("msg").textContent="";const modules=[...document.querySelectorAll("#mods input:checked")].map(x=>x.value),external=[...document.querySelectorAll("#ext input:checked")].map(x=>x.value);
const r=await J("/api/scan","POST",{target:$("target").value,insecure:$("insecure").checked,modules,external,workers:$("workers").value,delay:$("delay").value,timeout:$("timeout").value,max_pages:$("pages").value,max_dirs:$("dirs").value,wordlist:$("wl").value,extensions:$("exts").value,headers:$("hdrs").value});
if(r.error){$("msg").textContent=r.error;return}RUN=r.run_id;document.body.classList.add("live");$("stopb").style.display="inline-block";poll(r.run_id)}
async function poll(id){const r=await J("/api/run/"+id);$("log").textContent=r.log.join("\n");$("log").scrollTop=1e9;$("bar").style.width=r.progress+"%";
$("cur").textContent=r.status=="running"?("Running: "+r.current+" ("+r.progress+"%)"):("Status: "+r.status);
if(r.status=="running")setTimeout(()=>poll(id),1500);else{document.body.classList.remove("live");$("stopb").style.display="none";LASTSLUG=r.slug;loadFindings()}}
function stopScan(){if(RUN)J("/api/run/"+RUN+"/stop","POST",{})}
let LASTSLUG="";
async function loadFindings(){const ts=await J("/api/targets");const sel=$("ftarget"),cur=sel.value;
sel.innerHTML=ts.map(t=>`<option value="${esc(t.slug)}">${esc(t.target)} (${t.total} findings)</option>`).join("")||"<option value=''>No targets scanned yet</option>";
if(LASTSLUG&&ts.some(t=>t.slug==LASTSLUG)){sel.value=LASTSLUG;LASTSLUG=""}else if(cur&&ts.some(t=>t.slug==cur))sel.value=cur;
if(!sel.value){$("counts").innerHTML="";$("ftable").innerHTML="";return}
const f=await J("/api/findings?t="+encodeURIComponent(sel.value));const c={};f.forEach(x=>c[x.severity]=(c[x.severity]||0)+1);
$("counts").innerHTML=["Critical","High","Medium","Low","Informational"].map(s=>`<span class="${s}"><b>${c[s]||0}</b> ${s}</span>`).join(" &nbsp; ");
const ord={Critical:0,High:1,Medium:2,Low:3,Informational:4};f.sort((a,b)=>ord[a.severity]-ord[b.severity]);
$("ftable").innerHTML="<tr><th>ID</th><th>Finding</th><th>Sev</th><th>CVSS</th><th>Status</th><th>Notes</th></tr>"+f.map(x=>`<tr><td>${esc(x.id)}</td><td><b>${esc(x.title)}</b><br><small>${esc(x.component)}</small><details><summary>details</summary><small>${esc(x.description)}<br><b>Fix:</b> ${esc(x.recommendation)}<br><code>${esc(x.vector)}</code><pre>${esc(x.evidence)}</pre></small></details></td><td><span class="${x.severity}">${x.severity}</span></td><td>${x.score??"-"}</td>
<td><select onchange="upd('${x.id}',{status:this.value})">${["Open","In Progress","Remediated","Retest Passed","Reopened","Accepted Risk"].map(s=>`<option ${s==x.status?"selected":""}>${s}</option>`).join("")}</select></td>
<td><input value="${esc(x.notes)}" onchange="upd('${x.id}',{notes:this.value})"></td></tr>`).join("")}
async function loadReports(){const ts=await J("/api/targets");
$("rtable").innerHTML=ts.length?"<tr><th>Report</th><th>Findings (C/H/M/L/I)</th><th>Open / download</th></tr>"+ts.map(t=>{const u="/report/"+encodeURIComponent(t.slug);
return `<tr><td><b>${esc(t.name)}</b><br><small>${esc(t.target)} - last scan ${esc(t.last_scan||"-")}</small></td><td>${["Critical","High","Medium","Low","Informational"].map(s=>`<span class="${s}">${t.counts[s]||0}</span>`).join(" / ")}</td>
<td><a href="${u}/html" target="_blank">HTML</a> | <a href="${u}/pdf">PDF</a> | <a href="${u}/json">JSON</a> | <a href="#" onclick="exportT('${esc(t.slug)}');return false">Save all to disk</a></td></tr>`}).join(""):"<tr><td>No targets scanned yet.</td></tr>"}
async function exportT(s){const r=await J("/api/export/"+encodeURIComponent(s),"POST",{});alert(r.error||("Saved:\n"+r.files.join("\n")+(r.note?"\n\n"+r.note:"")))}
function upd(id,b){J("/api/findings/"+id,"PATCH",b)}
async function addManual(){const b={title:$("m_title").value,target:$("m_target").value,component:$("m_comp").value,phase:$("m_phase").value,description:$("m_desc").value,impact:$("m_imp").value,evidence:$("m_evi").value,recommendation:$("m_rec").value};
Object.keys(vals).forEach(k=>b[k]=$("v_"+k).value);const r=await J("/api/findings","POST",b);alert(r.error||"Saved as "+r.id)}

(function(){const root=document.documentElement;if(localStorage.getItem("vapt_inv")=="1")root.classList.add("inv");
$("inv").onclick=e=>{e.preventDefault();localStorage.setItem("vapt_inv",root.classList.toggle("inv")?"1":"0")}})();
</script></body></html>"""

migrate_legacy()

if __name__ == "__main__":
    print(f"Automated Website VAPT Framework v{__version__} - by {AUTHOR} ({AUTHOR_URL})")
    print(f"Project folder: {BASE}")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
