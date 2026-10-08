from __future__ import annotations
import argparse, base64, concurrent.futures as _cf
import csv, dataclasses, datetime as _dt, enum, hashlib
import html, http.client, ipaddress, json, math, os, re
import platform, queue, random, signal, socket, ssl, struct
import sys, textwrap, threading, time, traceback
import urllib.parse, urllib.request, xml.etree.ElementTree as ET
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

APP_NAME = "SafeAssess"
APP_VERSION = "0.0.1"
APP_URL = "https://example.invalid/safeassess"
REQUIRES_PY = (3, 9)
CONFIG_DIR = Path.home() / ".safeassess"
CONFIG_FILE = CONFIG_DIR / "config.json"
PROFILES_FILE = CONFIG_DIR / "profiles.json"
HISTORY_FILE = CONFIG_DIR / "history.jsonl"
AUDIT_LOG = CONFIG_DIR / "audit.log"
RESUME_FILE = CONFIG_DIR / "resume.json"
VULN_DB_FILE = CONFIG_DIR / "vulndb.json"
AUDIT_LOG_MAX = 5 * 1024 * 1024
DEFAULT_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

PORT_PROFILES: dict[str, list[int]] = {
    "Top 20 (safe default)": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 587, 993, 995, 1433, 3306, 3389, 8080,
    ],
    "Top 100": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
        135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 464, 465, 500,
        514, 515, 520, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995,
        1080, 1194, 1433, 1434, 1521, 1701, 1723, 1883, 1900, 2049,
        2082, 2083, 2181, 2375, 2376, 2483, 2484, 3000, 3128, 3260,
        3306, 3389, 3478, 4000, 4369, 4443, 4505, 4506, 5000, 5060,
        5061, 5222, 5353, 5432, 5555, 5601, 5672, 5683, 5800, 5900,
        5984, 5985, 5986, 6000, 6379, 6443, 7001, 7002, 8000, 8008,
        8009, 8080, 8081, 8088, 8090, 8161, 8200, 8443, 8500, 8888,
        9000, 9042, 9092, 9200, 9300, 9443, 10000, 11211, 15672,
        27017, 27018, 50000,
    ],
    "Web only": [80, 443, 8000, 8080, 8443, 8888, 4443],
    "Common services": [22, 25, 53, 80, 110, 143, 443, 587, 993, 995],
    "Mail": [25, 110, 143, 465, 587, 993, 995],
    "Databases": [1433, 1521, 3306, 5432, 6379, 27017],
    "Windows/AD": [88, 135, 139, 389, 445, 464, 636, 3268, 3269, 3389],
    "Containers/Orchestration": [2375, 2376, 6443, 10250, 10255, 10256],
    "Message queues": [5672, 15672, 9092, 61616, 6379, 11211, 27017],
    "Custom": [],
}
BUILTIN_PROFILE_NAMES = set(PORT_PROFILES.keys())
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 4443, 9000, 9443}
TLS_PORTS = {443, 8443, 9443, 4443, 993, 995, 465, 636, 990, 992, 994}
UDP_SERVICES: dict[int, tuple[str, bytes, str]] = {
    53: ("DNS", b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07version\x04bind\x00\x00\x10\x00\x03", "dns"),
    123: ("NTP", b"\x1b" + b"\x00" * 47, "ntp"),
    161: ("SNMP", b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
                 b"\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
                 b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01"
                 b"\x05\x00", "snmp"),
    1900: ("SSDP", b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
           "ssdp"),
    5353: ("mDNS", b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                   b"\x05local\x00\x00\xff\x00\x01", "mdns"),
}

CONNECT_TIMEOUT = 2.0
BANNER_TIMEOUT = 2.0
HTTP_TIMEOUT = 6.0
TLS_TIMEOUT = 6.0
UDP_TIMEOUT = 2.0
DNS_TIMEOUT = 3.0
DELAY_BETWEEN_PROBES = 0.05
MAX_WORKERS = 16
MAX_CUSTOM_PORTS = 2048
MAX_REDIRECTS = 3
MAX_BANNER = 4096
MAX_HTTP_BODY = 262144
DEFAULT_RATE = 10.0
MAX_RETRIES = 2
RETRY_BACKOFF = 0.5
USER_AGENT = f"SafeAssess/{APP_VERSION} (authorized, non-destructive)"
SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "Strict-Transport-Security":    ("medium", "HSTS missing (downgrade risk)"),
    "Content-Security-Policy":      ("medium", "CSP missing (XSS mitigation weakened)"),
    "X-Frame-Options":              ("low",    "Clickjacking protection missing"),
    "X-Content-Type-Options":       ("low",    "MIME sniffing protection missing"),
    "Referrer-Policy":              ("low",    "Referrer leakage policy missing"),
    "Permissions-Policy":           ("info",   "Feature-permissions policy missing"),
    "Cross-Origin-Opener-Policy":   ("info",   "COOP missing"),
    "Cross-Origin-Resource-Policy": ("info",   "CORP missing"),
    "Cross-Origin-Embedder-Policy": ("info",   "COEP missing"),
}

INFO_LEAK_HEADERS = (
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Runtime", "X-Debug-Token",
    "X-Backend-Server", "Via", "X-Varnish", "X-Served-By",
    "X-Cache", "X-Forwarded-For", "X-Real-IP",
)

VULN_BANNERS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"OpenSSH[_ ]([0-7]\.\d)", re.I), "high",
     "OpenSSH < 8.0 has multiple CVEs; upgrade.",
     "https://www.openssh.com/security.html"),
    (re.compile(r"OpenSSH[_ ]8\.[0-8]\b", re.I), "medium",
     "OpenSSH 8.0-8.8 has multiple CVEs; upgrade.",
     "https://www.openssh.com/security.html"),
    (re.compile(r"OpenSSH[_ ]9\.[0-7]\b", re.I), "low",
     "OpenSSH 9.0-9.7 — check advisories.", ""),
    (re.compile(r"vsftpd[_ ]2\.3\.4", re.I), "critical",
     "vsftpd 2.3.4 backdoor (CVE-2011-2523).",
     "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"),
    (re.compile(r"ProFTPD[_ ]1\.3\.[0-5]\b", re.I), "high",
     "ProFTPD 1.3.0-1.3.5 has multiple RCEs.", ""),
    (re.compile(r"Apache/2\.4\.49\b", re.I), "critical",
     "Apache 2.4.49 path traversal (CVE-2021-41773).",
     "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
    (re.compile(r"Apache/2\.4\.50\b", re.I), "critical",
     "Apache 2.4.50 path traversal (CVE-2021-42013).",
     "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"),
    (re.compile(r"Apache/2\.2\b", re.I), "high", "Apache 2.2 EOL.", ""),
    (re.compile(r"nginx/1\.(1[0-9]|2[0-1])\.", re.I), "low",
     "Older nginx — check CVE-2021-23017.", ""),
    (re.compile(r"Microsoft-IIS/6\.0", re.I), "critical",
     "IIS 6.0 EOL, many RCEs.", ""),
    (re.compile(r"Microsoft-IIS/[67]\.", re.I), "high", "Legacy IIS EOL.", ""),
    (re.compile(r"PHP/([45]\.|7\.[0-3])", re.I), "high", "EOL PHP version.", ""),
    (re.compile(r"MySQL.*5\.[0-6]\.", re.I), "medium", "Legacy MySQL.", ""),
    (re.compile(r"Exim[_ ]4\.(8[0-9]|9[0-1])", re.I), "high",
     "Exim 4.80-4.91 RCE (CVE-2019-10149).", ""),
    (re.compile(r"Exim[_ ]4\.9[2-4]", re.I), "high",
     "Exim 4.92-4.94 (CVE-2020-28017 series).", ""),
    (re.compile(r"Redis.*2\.[0-9]\.", re.I), "medium", "Legacy Redis.", ""),
    (re.compile(r"MongoDB.*[23]\.[0-9]\.", re.I), "medium", "Legacy MongoDB.", ""),
    (re.compile(r"lighttpd/1\.[0-4]\.", re.I), "medium",
     "Legacy lighttpd.", ""),
    (re.compile(r"Tomcat/[5-8]\.", re.I), "medium",
     "Legacy Tomcat — multiple RCEs.", ""),
    (re.compile(r"Jetty\(?[5-8]\.", re.I), "medium", "Legacy Jetty.", ""),
    (re.compile(r"OpenSSL/1\.0\.[01]", re.I), "high",
     "OpenSSL 1.0.0/1.0.1 — Heartbleed-era. Upgrade.", ""),
    (re.compile(r"Samba\s+[23]\.", re.I), "high",
     "Legacy Samba — SMBv1/2 risks.", ""),
    (re.compile(r"Postfix", re.I), "info", "Postfix detected.", ""),
    (re.compile(r"Dovecot", re.I), "info", "Dovecot detected.", ""),
]

TECH_FINGERPRINTS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"wordpress", re.I), "WordPress", "cms"),
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress", "cms"),
    (re.compile(r"drupal", re.I), "Drupal", "cms"),
    (re.compile(r"joomla", re.I), "Joomla", "cms"),
    (re.compile(r"django", re.I), "Django", "framework"),
    (re.compile(r"laravel", re.I), "Laravel", "framework"),
    (re.compile(r"rails", re.I), "Ruby on Rails", "framework"),
    (re.compile(r"express", re.I), "Express.js", "framework"),
    (re.compile(r"next\.js|__NEXT_DATA__", re.I), "Next.js", "framework"),
    (re.compile(r"react", re.I), "React", "javascript"),
    (re.compile(r"vue\.js|vuejs", re.I), "Vue.js", "javascript"),
    (re.compile(r"angular", re.I), "Angular", "javascript"),
    (re.compile(r"jquery", re.I), "jQuery", "javascript"),
    (re.compile(r"bootstrap", re.I), "Bootstrap", "css"),
    (re.compile(r"cloudflare", re.I), "Cloudflare", "cdn"),
    (re.compile(r"akamai", re.I), "Akamai", "cdn"),
    (re.compile(r"fastly", re.I), "Fastly", "cdn"),
    (re.compile(r"amazon ?s3", re.I), "AWS S3", "cloud"),
    (re.compile(r"nginx", re.I), "nginx", "server"),
    (re.compile(r"apache", re.I), "Apache", "server"),
    (re.compile(r"iis", re.I), "IIS", "server"),
    (re.compile(r"graphql", re.I), "GraphQL", "api"),
    (re.compile(r"swagger", re.I), "Swagger", "api"),
    (re.compile(r"openapi", re.I), "OpenAPI", "api"),
]

WAF_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"akamaighost", "Akamai"),
    ("server", r"awselb", "AWS ELB"),
    ("server", r"big-?ip", "F5 BIG-IP"),
    ("server", r"incapsula", "Imperva Incapsula"),
    ("server", r"sucuri", "Sucuri"),
    ("x-sucuri-id", r".", "Sucuri"),
    ("x-cdn", r".", "CDN (generic)"),
    ("cf-ray", r".", "Cloudflare"),
    ("x-akamai-transformed", r".", "Akamai"),
    ("x-amzn-requestid", r".", "AWS"),
    ("x-iinfo", r".", "Imperva Incapsula"),
]

SAFE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/.well-known/change-password", "/.well-known/openid-configuration",
    "/.well-known/dnt-policy.txt", "/humans.txt", "/favicon.ico",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/.git/HEAD",
    "/.env", "/.htaccess", "/admin/", "/login", "/api/", "/api/v1/",
    "/health", "/healthz", "/status", "/metrics", "/version",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/.well-known/acme-challenge/",
    "/server-status", "/phpinfo.php", "/wp-admin/", "/wp-login.php",
    "/.DS_Store", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/config.json", "/package.json", "/composer.json",
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
    "dev", "test", "staging", "api", "app", "admin", "portal", "vpn",
    "remote", "blog", "shop", "cdn", "static", "assets", "docs", "support",
    "help", "status", "monitor", "grafana", "kibana", "jenkins", "git",
    "gitlab", "github", "bitbucket", "jira", "confluence", "wiki",
    "sso", "auth", "login", "account", "accounts", "my", "secure",
    "internal", "intranet", "extranet", "db", "mysql", "postgres",
    "redis", "mongo", "elastic", "search", "log", "logs", "backup",
    "old", "new", "beta", "alpha", "preview", "demo", "sandbox",
    "m", "mobile", "wap", "img", "images", "media", "video", "download",
    "uploads", "files", "cloud", "ns", "dns", "mx", "relay", "gw",
    "gateway", "proxy", "lb", "edge", "origin", "cache", "k8s", "kube",
    "docker", "registry", "ci", "cd", "build", "deploy", "release",
    "prod", "production", "uat", "qa", "stage", "preprod", "pilot",
    "v2", "v3", "legacy", "archive", "backup2", "bak", "tmp", "temp",
]

SECRET_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"),
     "API key", "high"),
    (re.compile(r"(?i)(secret|passwd|password|pass)\s*[:=]\s*['\"]?([^\s'\"]{6,})"),
     "Password/secret", "high"),
    (re.compile(r"(?i)aws[_-]?(access|secret)[_-]?key"),
     "AWS credential", "critical"),
    (re.compile(r"(?i)private[_-]?key"),
     "Private key", "high"),
    (re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
     "Private key block", "critical"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"),
     "Bearer token", "high"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
     "JWT", "medium"),
    (re.compile(r"(?i)(mysql|postgres|mongodb|redis)://[^\s\"']+"),
     "DB connection string", "high"),
    (re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
     "AWS access key ID", "critical"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),
     "GitHub personal access token", "critical"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"),
     "GitHub OAuth token", "critical"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
     "Stripe live key", "critical"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]+"),
     "Slack token", "high"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "Google API key", "high"),
    (re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
     "Google OAuth token", "high"),
]

CVE_DB: dict[str, list[tuple[str, str, str, float]]] = {
    "Apache/2.4.49": [("CVE-2021-41773", "Path traversal & RCE in Apache 2.4.49",
                       "critical", 9.8)],
    "Apache/2.4.50": [("CVE-2021-42013", "Path traversal in Apache 2.4.50",
                       "critical", 9.8)],
    "vsftpd 2.3.4": [("CVE-2011-2523", "vsftpd 2.3.4 backdoor",
                      "critical", 10.0)],
    "OpenSSH_7": [("CVE-2016-10009", "OpenSSH < 7.4 ssh-agent RCE",
                   "high", 7.5)],
    "OpenSSH_8.0": [("CVE-2019-6109", "OpenSSH < 8.1 scp client spoof",
                     "medium", 6.8)],
    "OpenSSH_8.5": [("CVE-2021-41617", "OpenSSH 6.2-8.7 privilege escalation",
                     "high", 7.0)],
    "Exim 4.92": [("CVE-2020-28017", "Exim 4.92-4.94 RCE series",
                   "critical", 9.8)],
    "Samba 3": [("CVE-2017-7494", "SambaCry RCE",
                 "critical", 9.8)],
}

MITRE_MAP: dict[str, list[str]] = {
    "TCP": ["T1046"],
    "HTTP": ["T1595.002"],
    "TLS": ["T1595.002"],
    "VULN": ["T1190"],
    "TECH": ["T1592.002"],
    "WAF": ["T1590.005"],
    "PATH": ["T1083"],
    "SUBDOMAIN": ["T1590.002"],
    "SCOPE": ["T1595"],
    "WEB": ["T1595.002"],
    "SERVICE": ["T1046"],
    "SECRET": ["T1552"],
}

OWASP_MAP: dict[str, list[str]] = {
    "Strict-Transport-Security": ["A02:2021"],
    "Content-Security-Policy": ["A03:2021"],
    "X-Frame-Options": ["A05:2021"],
    "X-Content-Type-Options": ["A05:2021"],
    "Referrer-Policy": ["A05:2021"],
    "Permissions-Policy": ["A05:2021"],
    "Cross-Origin-Opener-Policy": ["A05:2021"],
    "Cookie missing Secure": ["A02:2021"],
    "Cookie missing HttpOnly": ["A03:2021"],
    "Cookie missing SameSite": ["A01:2021"],
    "Weak cipher": ["A02:2021"],
    "TLS 1.0": ["A02:2021"],
    "TLS 1.1": ["A02:2021"],
    "Certificate EXPIRED": ["A02:2021"],
    "Self-signed": ["A02:2021"],
}

TEMPLATES: dict[str, dict[str, Any]] = {
    "quick": {
        "profile": "Top 20 (safe default)",
        "http": True, "tls": True, "ciphers": False,
        "web": False, "subdomains": False,
        "tls_versions": False, "paths": False,
        "udp": False, "service_detect": False,
    },
    "standard": {
        "profile": "Top 100",
        "http": True, "tls": True, "ciphers": False,
        "web": True, "subdomains": False,
        "tls_versions": True, "paths": True,
        "udp": False, "service_detect": True,
    },
    "deep": {
        "profile": "Top 100",
        "http": True, "tls": True, "ciphers": True,
        "web": True, "subdomains": True,
        "tls_versions": True, "paths": True,
        "udp": True, "service_detect": True,
    },
    "web": {
        "profile": "Web only",
        "http": True, "tls": True, "ciphers": True,
        "web": True, "subdomains": False,
        "tls_versions": True, "paths": True,
        "udp": False, "service_detect": False,
    },
    "compliance": {
        "profile": "Top 100",
        "http": True, "tls": True, "ciphers": True,
        "web": True, "subdomains": False,
        "tls_versions": True, "paths": False,
        "udp": False, "service_detect": False,
    },
}

SEVERITY_SCORE = {"info": 0.0, "low": 3.0, "medium": 5.5, "high": 8.0, "critical": 9.5}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLORS = {
    "critical": "#8b0000", "high": "#a30000", "medium": "#b35c00",
    "low": "#7a6000", "info": "#1a1a1a",
}

WEAK_CIPHERS = [
    "RC4-SHA", "RC4-MD5", "DES-CBC3-SHA", "DES-CBC-SHA",
    "EXP-RC4-MD5", "EXP-DES-CBC-SHA", "NULL-SHA", "NULL-MD5",
    "aNULL", "ADH", "AECDH", "3DES",
]

DANGEROUS_HTTP_METHODS = {"put", "delete", "trace", "connect", "patch"}

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def utc_ts() -> float:
    return time.time()

def esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))

def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(path: Path, data: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass

def _rotate_audit_if_needed() -> None:
    try:
        if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > AUDIT_LOG_MAX:
            backup = AUDIT_LOG.with_suffix(".log.1")
            try:
                if backup.exists():
                    backup.unlink()
                os.replace(AUDIT_LOG, backup)
            except OSError:
                pass
    except OSError:
        pass

def append_audit(entry: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        _rotate_audit_if_needed()
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass

def append_history(entry: dict) -> None:
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass

def append_log(path: Optional[Path], entry: dict) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass

def validate_target(host: str) -> tuple[bool, str]:
    host = (host or "").strip()
    if not host:
        return False, "Target is empty."
    if len(host) > 253:
        return False, "Target is too long."
    try:
        ipaddress.ip_address(host)
        return True, ""
    except ValueError:
        pass
    if any(c in host for c in "/@ "):
        return False, "Enter only a hostname or IP (no scheme, port, or path)."
    if host.startswith("["):
        return False, "Enter the bare IPv6 address without brackets."
    if ":" in host:
        return False, "Invalid hostname (unexpected ':')."
    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False, "Invalid hostname."
        if not all(c.isalnum() or c == "-" for c in label):
            return False, "Invalid hostname characters."
        if label.startswith("-") or label.endswith("-"):
            return False, "Hostname label may not start/end with '-'."
    return True, ""

def parse_custom_ports(text: str) -> tuple[bool, Any]:
    text = (text or "").strip()
    if not text:
        return False, "Custom port list is empty."
    tokens = re.split(r"[\s,;]+", text)
    ports: list[int] = []
    seen: set[int] = set()
    for token in tokens:
        if not token:
            continue
        if "-" in token:
            a, _, b = token.partition("-")
            if not a.isdigit() or not b.isdigit():
                return False, f"Invalid port range: {token!r}"
            lo, hi = int(a), int(b)
            if not (1 <= lo <= hi <= 65535):
                return False, f"Port range out of bounds: {token!r}"
            for p in range(lo, hi + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
        else:
            if not token.isdigit():
                return False, f"Invalid port token: {token!r}"
            p = int(token)
            if not (1 <= p <= 65535):
                return False, f"Port out of range: {p}"
            if p not in seen:
                seen.add(p)
                ports.append(p)
    if not ports:
        return False, "No valid ports provided."
    if len(ports) > MAX_CUSTOM_PORTS:
        return False, f"Too many ports (max {MAX_CUSTOM_PORTS})."
    return True, sorted(ports)

def resolve_host(host: str, prefer_ipv6: bool = False) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        return (v6 + v4) if prefer_ipv6 else (v4 + v6)
    except Exception:
        return []

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def dns_records(host: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [],
                                 "TXT": [], "CNAME": []}
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            fam, addr = info[0], info[4][0]
            if fam == socket.AF_INET and addr not in out["A"]:
                out["A"].append(addr)
            elif fam == socket.AF_INET6 and addr not in out["AAAA"]:
                out["AAAA"].append(addr)
    except Exception:
        pass
    return out

def calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def favicon_hash(data: bytes) -> str:
    try:
        import mmh3  # type: ignore
        return str(mmh3.hash(base64.encodebytes(data)))
    except ImportError:
        return "sha256:" + hashlib.sha256(data).hexdigest()[:16]

def _bracket_host(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: Optional[float] = None,
                 jitter: float = 0.1):
        self.rate = max(float(rate_per_sec), 0.01)
        self.capacity = burst if burst is not None else max(self.rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = threading.Lock()
        self.jitter = max(0.0, float(jitter))

    def take(self, n: float = 1.0, timeout: float = 15.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.updated = now
                if self.tokens >= n:
                    self.tokens -= n
                    jitter = random.uniform(0.0, self.jitter) if self.jitter else 0.0
                    break
                need = (n - self.tokens) / self.rate
            if time.monotonic() + need > deadline:
                return False
            time.sleep(max(0.0, need))
        if jitter:
            time.sleep(jitter / max(self.rate, 0.01))
        return True

@dataclass
class Finding:
    ts: str
    target: str
    category: str
    message: str
    severity: str = "info"
    score: float = 0.0
    evidence: str = ""
    port: int = 0
    refs: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cve: str = ""
    cvss: float = 0.0
    remediation: str = ""
    service: str = ""

    def pretty(self) -> str:
        tag = self.severity.upper()
        loc = f":{self.port}" if self.port else ""
        svc = f" ({self.service})" if self.service else ""
        cve = f" [{self.cve}]" if self.cve else ""
        return f"[{self.ts}] [{self.category}/{tag}]{loc}{svc} {self.message}{cve}"

    def key(self) -> tuple:
        ev = hashlib.sha1(self.evidence.encode("utf-8", "replace")).hexdigest()[:8]
        return (self.category, self.port, self.message, self.severity, ev)

    def redacted(self) -> "Finding":
        d = asdict(self)
        for k, v in list(d.items()):
            if isinstance(v, str):
                v = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "x.x.x.x", v)
                v = re.sub(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\b",
                           "x:x::x", v)
                d[k] = v
        return Finding(**d)

@dataclass
class ScanReport:
    target: str = ""
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0
    resolved_ips: list[str] = field(default_factory=list)
    reverse_dns: str = ""
    dns: dict[str, list[str]] = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)
    open_udp_ports: list[int] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    aborted: bool = False
    aborted_reason: str = ""
    subdomains: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    waf: list[str] = field(default_factory=list)
    phase_times: dict[str, float] = field(default_factory=dict)
    risk_score: float = 0.0
    whois: dict[str, str] = field(default_factory=dict)
    ct_logs: list[str] = field(default_factory=list)
    tls_certs: dict[str, dict] = field(default_factory=dict)
    security_txt: dict[str, str] = field(default_factory=dict)
    robots_paths: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    def to_dict(self) -> dict:
        d = asdict(self)
        return d

class Scope:
    def __init__(self, allowed_hosts: Optional[Iterable[str]] = None,
                 allowed_networks: Optional[Iterable[Any]] = None):
        self.hosts: set[str] = set(allowed_hosts or DEFAULT_ALLOWED_HOSTS)
        self.networks: list[Any] = list(allowed_networks or LOOPBACK_NETWORKS)
        self.lock = threading.RLock()

    def add_host(self, host: str) -> bool:
        host = (host or "").strip()
        if not host:
            return False
        ok, _ = validate_target(host)
        if not ok:
            return False
        with self.lock:
            self.hosts.add(host)
        return True

    def remove_host(self, host: str) -> None:
        with self.lock:
            self.hosts.discard(host)

    def add_network(self, cidr: str) -> tuple[bool, str]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            return False, f"Invalid network: {e}"
        with self.lock:
            if net not in self.networks:
                self.networks.append(net)
        return True, ""

    def remove_network(self, cidr: str) -> None:
        with self.lock:
            self.networks = [n for n in self.networks if str(n) != cidr]

    def contains_literal(self, host: str) -> bool:
        with self.lock:
            if host in self.hosts:
                return True
            for net in self.networks:
                if str(net) == host or str(net.network_address) == host:
                    return True
        return False

    def contains_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        with self.lock:
            if ip_str in self.hosts:
                return True
            return any(ip in net for net in self.networks)

    def contains(self, host: str) -> bool:
        if self.contains_literal(host):
            return True
        try:
            ipaddress.ip_address(host)
            return self.contains_ip(host)
        except ValueError:
            pass
        ips = resolve_host(host)
        if not ips:
            return False
        return all(self.contains_ip(ip) for ip in ips)

    def snapshot(self) -> tuple[set[str], list[Any]]:
        with self.lock:
            return set(self.hosts), list(self.networks)

    def describe(self) -> str:
        with self.lock:
            parts = sorted(self.hosts)
            parts += [str(n) for n in self.networks if str(n) not in parts]
        return ", ".join(parts)

    def to_dict(self) -> dict:
        with self.lock:
            return {
                "hosts": sorted(self.hosts),
                "networks": [str(n) for n in self.networks],
            }

    @classmethod
    def from_dict(cls, d: dict) -> "Scope":
        nets = []
        for s in d.get("networks", []):
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                pass
        return cls(allowed_hosts=d.get("hosts") or DEFAULT_ALLOWED_HOSTS,
                   allowed_networks=nets or LOOPBACK_NETWORKS)

@dataclass
class Config:
    scope: Scope = field(default_factory=Scope)
    rate_limit: float = DEFAULT_RATE
    workers: int = MAX_WORKERS
    last_target: str = "127.0.0.1"
    connect_timeout: float = CONNECT_TIMEOUT
    banner_timeout: float = BANNER_TIMEOUT
    http_timeout: float = HTTP_TIMEOUT
    tls_timeout: float = TLS_TIMEOUT
    udp_timeout: float = UDP_TIMEOUT
    user_agent: str = USER_AGENT
    custom_headers: dict[str, str] = field(default_factory=dict)
    proxy: str = ""
    severity_threshold: str = "info"
    redact: bool = False
    log_file: str = ""

    @classmethod
    def load(cls) -> "Config":
        raw = load_json(CONFIG_FILE, {}) or {}
        cfg = cls()
        if raw.get("scope"):
            cfg.scope = Scope.from_dict(raw["scope"])
        for k in ("rate_limit", "connect_timeout", "banner_timeout",
                  "http_timeout", "tls_timeout", "udp_timeout",
                  "user_agent", "proxy", "severity_threshold", "log_file"):
            if k in raw and raw[k] is not None:
                setattr(cfg, k, raw[k])
        if "workers" in raw:
            try:
                cfg.workers = int(raw["workers"])
            except (TypeError, ValueError):
                pass
        if isinstance(raw.get("custom_headers"), dict):
            cfg.custom_headers = {str(k): str(v) for k, v in raw["custom_headers"].items()}
        if "redact" in raw:
            cfg.redact = bool(raw["redact"])
        if "last_target" in raw:
            cfg.last_target = str(raw["last_target"])
        return cfg

    def save(self) -> None:
        save_json(CONFIG_FILE, {
            "scope": self.scope.to_dict(),
            "rate_limit": self.rate_limit,
            "workers": self.workers,
            "last_target": self.last_target,
            "connect_timeout": self.connect_timeout,
            "banner_timeout": self.banner_timeout,
            "http_timeout": self.http_timeout,
            "tls_timeout": self.tls_timeout,
            "udp_timeout": self.udp_timeout,
            "user_agent": self.user_agent,
            "custom_headers": self.custom_headers,
            "proxy": self.proxy,
            "severity_threshold": self.severity_threshold,
            "redact": self.redact,
            "log_file": self.log_file,
        })

def _ip_scope_check(ips: list[str], snap_hosts: set[str],
                    snap_nets: list[Any]) -> list[str]:
    out = []
    for ip in ips:
        try:
            i = ipaddress.ip_address(ip)
        except ValueError:
            out.append(ip)
            continue
        if ip in snap_hosts:
            continue
        if not any(i in n for n in snap_nets):
            out.append(ip)
    return out

def tcp_connect_check(host: str, port: int,
                      stop_event: Optional[threading.Event] = None,
                      connect_timeout: float = CONNECT_TIMEOUT,
                      banner_timeout: float = BANNER_TIMEOUT
                      ) -> tuple[bool, str, str]:
    if stop_event is not None and stop_event.is_set():
        return False, "stopped", ""
    try:
        with socket.create_connection((host, port), timeout=connect_timeout) as s:
            s.settimeout(banner_timeout)
            banner = ""
            if port in (21, 22, 23, 25, 110, 143, 587, 993, 995,
                        1433, 3306, 5432, 6379, 27017, 11211, 9200,
                        389, 636, 465, 5900, 5984, 2375, 2376, 6443):
                try:
                    data = s.recv(MAX_BANNER)
                    banner = data.decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    banner = ""
            if port == 6379 and not banner:
                try:
                    s.sendall(b"PING\r\n")
                    data = s.recv(256)
                    banner = data.decode("utf-8", errors="replace").strip()
                except OSError:
                    pass
            if port == 11211 and not banner:
                try:
                    s.sendall(b"version\r\n")
                    data = s.recv(256)
                    banner = data.decode("utf-8", errors="replace").strip()
                except OSError:
                    pass
            if port == 27017 and not banner:
                try:
                    payload = (
                        b"\x3a\x00\x00\x00"
                        b"\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00"
                        b"\xd4\x07\x00\x00"
                        b"\x00\x00\x00\x00"
                        b"admin.$cmd\x00"
                        b"\x00\x00\x00\x00"
                        b"\xff\xff\xff\xff"
                        b"\x13\x00\x00\x00"
                        b"\x10isMaster\x00\x01\x00\x00\x00"
                        b"\x00"
                    )
                    s.sendall(payload)
                    data = s.recv(MAX_BANNER)
                    banner = data.decode("utf-8", errors="replace").strip()
                except OSError:
                    pass
            return True, "open", banner
    except socket.timeout:
        return False, "timeout", ""
    except ConnectionRefusedError:
        return False, "refused", ""
    except socket.gaierror as exc:
        return False, f"dns: {exc}", ""
    except OSError as exc:
        return False, f"error: {exc}", ""

def udp_probe(host: str, port: int, payload: bytes,
              stop_event: Optional[threading.Event] = None,
              timeout: float = UDP_TIMEOUT) -> tuple[bool, str]:
    if stop_event is not None and stop_event.is_set():
        return False, "stopped"
    families = [socket.AF_INET, socket.AF_INET6]
    for fam in families:
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(payload, (host, port))
                try:
                    data, _ = s.recvfrom(4096)
                    return True, data[:64].hex()
                except socket.timeout:
                    continue
        except OSError:
            continue
    return False, "open|filtered"

def service_detect(host: str, port: int,
                   stop_event: Optional[threading.Event] = None
                   ) -> str:
    if stop_event is not None and stop_event.is_set():
        return ""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(BANNER_TIMEOUT)
            banner = ""
            try:
                banner = s.recv(MAX_BANNER).decode("utf-8", errors="replace")
            except Exception:
                pass
            if not banner:
                try:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                    banner = s.recv(MAX_BANNER).decode("utf-8", errors="replace")
                except Exception:
                    pass
            return banner.strip()
    except Exception:
        return ""

_SERVICE_HINTS = [
    (re.compile(r"^SSH-", re.I), "ssh"),
    (re.compile(r"^220[\s-].*(FTP|Ftp)", re.I), "ftp"),
    (re.compile(r"^220[\s-].*(SMTP|ESMTP|Postfix|Exim)", re.I), "smtp"),
    (re.compile(r"^\+OK.*(Dovecot|Courier)", re.I), "pop3"),
    (re.compile(r"^\* OK.*(Dovecot|Courier)", re.I), "imap"),
    (re.compile(r"^HTTP/", re.I), "http"),
    (re.compile(r"^\x00\x00\x00", re.I), "mysql"),
    (re.compile(r"^\-ERR|^\*[0-9]+", re.I), "redis"),
    (re.compile(r"^220.*(ProFTPD|vsftpd|FileZilla)", re.I), "ftp"),
]

def _nmap_service_name(banner: str, port: int) -> str:
    if not banner:
        return ""
    for pat, name in _SERVICE_HINTS:
        if pat.search(banner):
            return name
    return ""

def check_vuln_banner(banner: str) -> list[tuple[str, str, str]]:
    hits: list[tuple[str, str, str]] = []
    if not banner:
        return hits
    for pat, sev, note, ref in VULN_BANNERS:
        if pat.search(banner):
            hits.append((sev, note, ref))
    return hits

def _make_http_conn(scheme: str, host: str, port: int, timeout: float,
                    proxy: str = "") -> Any:
    if scheme == "https":
        ctx = ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)

def http_probe(host: str, port: int, follow_redirects: bool = True,
               stop_event: Optional[threading.Event] = None,
               path: str = "/",
               custom_headers: Optional[dict[str, str]] = None,
               user_agent: str = USER_AGENT,
               timeout: float = HTTP_TIMEOUT) -> tuple[bool, dict, str]:
    scheme = "https" if port in TLS_PORTS else "http"
    result: dict[str, Any] = {
        "scheme": scheme, "status": 0, "reason": "", "headers": {},
        "raw_headers": [], "redirect_chain": [], "body_snippet": "",
        "body_bytes": b"", "final_url": f"{scheme}://{_bracket_host(host)}:{port}{path}",
        "methods": {}, "timings": {},
    }
    hops = 0
    current_host = host
    current_port = port
    current_scheme = scheme
    current_path = path
    base_headers = {"User-Agent": user_agent, "Accept": "*/*",
                    "Connection": "close"}
    if custom_headers:
        base_headers.update(custom_headers)
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                return False, result, "cancelled"
            hops += 1
            if hops > MAX_REDIRECTS + 1:
                return False, result, "Too many redirects"
            t0 = time.monotonic()
            conn = _make_http_conn(current_scheme, current_host,
                                   current_port, timeout)
            conn.request("GET", current_path, headers=base_headers)
            resp = conn.getresponse()
            result["timings"]["ttfb"] = round(time.monotonic() - t0, 3)
            result["status"] = resp.status
            result["reason"] = resp.reason
            result["headers"] = {}
            result["raw_headers"] = list(resp.getheaders())
            for k, v in resp.getheaders():
                result["headers"].setdefault(k.lower(), []).append(v)
            try:
                body = resp.read(MAX_HTTP_BODY)
                result["body_bytes"] = body
                result["body_snippet"] = body.decode("utf-8", errors="replace")
            except Exception:
                pass
            conn.close()
            if (follow_redirects and resp.status in (301, 302, 303, 307, 308)
                    and "location" in result["headers"]):
                loc = result["headers"]["location"][0]
                result["redirect_chain"].append((result["status"], loc))
                p = urlparse_safe(urljoin_safe(result["final_url"], loc))
                if p.hostname and p.hostname != host:
                    break
                if p.scheme:
                    current_scheme = p.scheme
                if p.port:
                    current_port = p.port
                current_path = p.path or "/"
                if p.query:
                    current_path += "?" + p.query
                continue
            result["final_url"] = (
                f"{current_scheme}://{_bracket_host(current_host)}:"
                f"{current_port}{current_path}"
            )
            break
        for method in ("HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"):
            if stop_event is not None and stop_event.is_set():
                break
            try:
                conn = _make_http_conn(scheme, host, port, timeout)
                conn.request(method, "/", headers=base_headers)
                r = conn.getresponse()
                result["methods"][method] = r.status
                r.read(1024)
                conn.close()
            except Exception:
                pass
        return True, result, ""
    except Exception as exc:
        return False, result, f"{exc}"

def urlparse_safe(u: str):
    return urllib.parse.urlparse(u)

def urljoin_safe(base: str, loc: str) -> str:
    return urllib.parse.urljoin(base, loc)

def tls_probe(host: str, port: int = 443,
              stop_event: Optional[threading.Event] = None,
              timeout: float = TLS_TIMEOUT) -> tuple[bool, dict, str]:
    info: dict[str, Any] = {"verified": False}
    cert: Optional[dict] = None
    if stop_event is not None and stop_event.is_set():
        return False, info, "cancelled"
    def _handshake(verify: bool) -> tuple[Any, Any, Any, Any, Any]:
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                c = ssock.getpeercert()
                cipher = ssock.cipher() or ("", "", 0)
                ver = ssock.version() or ""
                chain = None
                try:
                    chain = ssock.get_verified_chain()
                except Exception:
                    chain = None
                cert_der = None
                try:
                    cert_der = ssock.getpeercert(binary_form=True)
                except Exception:
                    cert_der = None
                return c, cipher, ver, chain, cert_der
    cert_der: Optional[bytes] = None
    try:
        try:
            cert, cipher, version, chain, cert_der = _handshake(True)
            info["verified"] = True
        except ssl.SSLCertVerificationError as exc:
            info["verified"] = False
            info["verify_error"] = str(exc)
            cert, cipher, version, chain, cert_der = _handshake(False)
        info["protocol"] = version
        info["cipher"] = cipher[0]
        info["cipher_bits"] = cipher[2]
        info["chain_len"] = len(chain) if chain else None
    except Exception as exc:
        return False, info, f"TLS check failed: {exc}"
    if not cert:
        return False, info, "No certificate returned."
    subject = {k: v for k, v in (x[0] for x in cert.get("subject", []))}
    issuer = {k: v for k, v in (x[0] for x in cert.get("issuer", []))}
    info.update({
        "subject_cn": subject.get("commonName", ""),
        "subject_org": subject.get("organizationName", ""),
        "issuer_cn": issuer.get("commonName", ""),
        "issuer_org": issuer.get("organizationName", ""),
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "san": cert.get("subjectAltName", []),
        "serial": cert.get("serialNumber", ""),
    })
    try:
        not_after_epoch = ssl.cert_time_to_seconds(info["not_after"])
        info["days_left"] = int((not_after_epoch - utc_ts()) / 86400)
    except Exception:
        info["days_left"] = None
    info["self_signed"] = (
        info.get("subject_cn") == info.get("issuer_cn")
        and info.get("subject_org") == info.get("issuer_org")
    )
    info.update(_pubkey_info(cert_der))
    return True, info, ""

def _pubkey_info(cert_der: Optional[bytes]) -> dict:
    out: dict[str, Any] = {"key_type": "", "key_bits": 0,
                           "sig_algo": "", "weak_key": False}
    if not cert_der:
        return out
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa  # type: ignore
        cert_obj = x509.load_der_x509_certificate(cert_der)
        pub = cert_obj.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            out["key_type"] = "RSA"
            out["key_bits"] = pub.key_size
            out["weak_key"] = pub.key_size < 2048
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            out["key_type"] = "EC"
            out["key_bits"] = pub.key_size
            out["weak_key"] = pub.key_size < 224
        elif isinstance(pub, dsa.DSAPublicKey):
            out["key_type"] = "DSA"
            out["key_bits"] = pub.key_size
            out["weak_key"] = pub.key_size < 2048
        out["sig_algo"] = cert_obj.signature_hash_algorithm.name.upper()
    except Exception:
        pass
    return out

def enumerate_weak_ciphers(host: str, port: int,
                           stop_event: Optional[threading.Event] = None,
                           timeout: float = TLS_TIMEOUT) -> list[str]:
    accepted: list[str] = []
    for cipher in WEAK_CIPHERS:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers(cipher)
            except ssl.SSLError:
                continue
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    accepted.append(ssock.cipher()[0])
        except Exception:
            continue
    return accepted

def tls_version_probe(host: str, port: int,
                      stop_event: Optional[threading.Event] = None,
                      timeout: float = TLS_TIMEOUT) -> dict[str, bool]:
    results: dict[str, bool] = {}
    versions = [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for name, ver in versions:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    results[name] = True
        except Exception:
            results[name] = False
    return results

def ct_log_lookup(domain: str, stop_event: Optional[threading.Event] = None
                  ) -> list[str]:
    if stop_event is not None and stop_event.is_set():
        return []
    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read(262144).decode("utf-8", errors="replace"))
        names: set[str] = set()
        for entry in data:
            for n in (entry.get("name_value") or "").split("\n"):
                n = html.unescape(n).strip().lower()
                if n and "*" not in n:
                    names.add(n)
        return sorted(names)[:200]
    except Exception:
        return []

def whois_lookup(domain: str, stop_event: Optional[threading.Event] = None
                 ) -> dict[str, str]:
    if stop_event is not None and stop_event.is_set():
        return {}
    if not re.match(r"^[a-z0-9.\-]+$", domain.lower()):
        return {}
    tld = domain.rsplit(".", 1)[-1].lower()
    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "dev": "whois.nic.google",
        "co": "whois.nic.co",
        "info": "whois.afilias.net",
        "biz": "whois.biz",
        "me": "whois.nic.me",
    }
    server = servers.get(tld)
    if not server:
        return {}
    try:
        with socket.create_connection((server, 43), timeout=6) as s:
            s.sendall((domain + "\r\n").encode())
            buf = b""
            while len(buf) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        text = buf.decode("utf-8", errors="replace")
        out: dict[str, str] = {}
        last_key = None
        for line in text.splitlines():
            if ":" in line and not line.startswith(" "):
                k, _, v = line.partition(":")
                k, v = k.strip().lower(), v.strip()
                if k and v:
                    out[k] = v
                    last_key = k
            elif last_key and line.strip():
                out[last_key] += " " + line.strip()
        return {k: out[k] for k in
                ("registrar", "creation date", "registry expiry date",
                 "updated date", "name server", "registrant organization",
                 "registrant country", "dnssec")
                if k in out}
    except Exception:
        return {}

def check_cors(headers: dict[str, list[str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    acao = headers.get("access-control-allow-origin", [])
    acac = headers.get("access-control-allow-credentials", [])
    if "null" in acao:
        out.append(("medium", "CORS allows null origin (bypassable)"))
    if "*" in acao and "true" in [c.lower() for c in acac]:
        out.append(("high",
                    "CORS wildcard origin with credentials — misconfiguration"))
    if acao and any(o != "*" for o in acao) and "true" in [c.lower() for c in acac]:
        out.append(("info",
                    f"CORS reflects origins ({', '.join(acao)}) with credentials — verify allowlist"))
    return out

def check_csp(csp: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    lower = csp.lower()
    if "unsafe-inline" in lower:
        out.append(("low", "CSP contains 'unsafe-inline'"))
    if "unsafe-eval" in lower:
        out.append(("low", "CSP contains 'unsafe-eval'"))
    if re.search(r"default-src\s+\*(\s|;|$)", lower):
        out.append(("medium", "CSP default-src wildcard"))
    if "object-src" not in lower and "default-src" in lower:
        out.append(("info", "CSP does not set object-src explicitly"))
    if "base-uri" not in lower:
        out.append(("info", "CSP missing base-uri directive"))
    if "frame-ancestors" not in lower:
        out.append(("info", "CSP missing frame-ancestors"))
    if "nonce-" in lower:
        out.append(("info", "CSP uses nonces"))
    if re.search(r"'sha(256|384|512)-", lower):
        out.append(("info", "CSP uses script hashes"))
    return out

def check_referrer_policy(value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    lower = value.lower()
    if "unsafe-url" in lower or "no-referrer-when-downgrade" in lower:
        out.append(("low", "Referrer-Policy leaks full URL"))
    return out

def check_cookies(cookies: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen_names: dict[str, int] = {}
    for c in cookies:
        name = c.split("=", 1)[0].strip().lower()
        seen_names[name] = seen_names.get(name, 0) + 1
        lower = c.lower()
        if name.startswith("__host-"):
            if "secure" not in lower:
                out.append(("medium", f"__Host- cookie {name} missing Secure"))
            if "path=/" not in lower.replace(" ", ""):
                out.append(("medium", f"__Host- cookie {name} missing Path=/"))
            if "domain=" in lower:
                out.append(("medium", f"__Host- cookie {name} must not set Domain"))
        if name.startswith("__secure-") and "secure" not in lower:
            out.append(("medium", f"__Secure- cookie {name} missing Secure"))
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if "samesite=none" in lower and "secure" not in lower:
            out.append(("medium", f"Cookie {name} SameSite=None without Secure"))
        if missing:
            out.append(("low", f"Cookie {name} missing {'/'.join(missing)}"))
    for name, n in seen_names.items():
        if n > 1 and name:
            out.append(("info", f"Duplicate Set-Cookie name: {name}"))
    return out

def detect_jwt(body: str) -> list[str]:
    return re.findall(
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        body)[:10]

def detect_secrets(body: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    if not body:
        return out
    for pat, label, sev in SECRET_PATTERNS:
        for m in pat.finditer(body[:262144]):
            text = m.group(0)[:120]
            out.append((sev, label, text))
            if len(out) > 50:
                return out
    return out

def extract_js_endpoints(body: str) -> list[str]:
    endpoints: set[str] = set()
    for m in re.finditer(r"""["'](/[a-zA-Z0-9_\-./?=&%]+)["']""", body):
        p = m.group(1)
        if len(p) < 200 and not p.startswith("//") and "://" not in p:
            endpoints.add(p)
    for m in re.finditer(r"""https?://[a-zA-Z0-9_\-./]+""", body):
        endpoints.add(m.group(0))
    return sorted(endpoints)[:100]

def parse_robots(text: str) -> list[str]:
    paths: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k in ("disallow", "allow") and v and v != "/":
            paths.append(v)
        if k == "sitemap" and v:
            paths.append(v)
    seen = set()
    out = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:200]

def parse_sitemap(text: str) -> list[str]:
    urls: list[str] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1]
        if tag == "loc" and el.text:
            urls.append(el.text.strip())
    return urls[:200]

def parse_security_txt(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k and v:
            out[k] = v
    return out

class ScanEngine:
    PHASES = ("DNS", "WHOIS", "CT", "Subdomains", "Ports", "UDP",
              "Services", "HTTP", "TLS", "Web", "Done")
    def __init__(self, target: str, ports: list[int], scope: Scope,
                 out_queue: "queue.Queue",
                 stop_event: threading.Event,
                 rate_limit: float = DEFAULT_RATE,
                 workers: int = MAX_WORKERS,
                 enable_http: bool = True,
                 enable_tls: bool = True,
                 enable_ciphers: bool = True,
                 enable_web_discovery: bool = True,
                 enable_subdomains: bool = True,
                 enable_tls_versions: bool = True,
                 enable_path_probe: bool = True,
                 enable_udp: bool = True,
                 enable_service_detect: bool = True,
                 enable_whois: bool = True,
                 enable_ct: bool = True,
                 enable_secret_scan: bool = True,
                 max_retries: int = MAX_RETRIES,
                 config: Optional[Config] = None):
        self.target = target
        self.ports = list(ports)
        self.scope = scope
        self.q = out_queue
        self.stop = stop_event
        self.rate = TokenBucket(rate_limit)
        self.workers = max(1, int(workers))
        self.enable_http = enable_http
        self.enable_tls = enable_tls
        self.enable_ciphers = enable_ciphers
        self.enable_web_discovery = enable_web_discovery
        self.enable_subdomains = enable_subdomains
        self.enable_tls_versions = enable_tls_versions
        self.enable_path_probe = enable_path_probe
        self.enable_udp = enable_udp
        self.enable_service_detect = enable_service_detect
        self.enable_whois = enable_whois
        self.enable_ct = enable_ct
        self.enable_secret_scan = enable_secret_scan
        self.max_retries = max_retries
        self.cfg = config or Config()
        self.report = ScanReport(target=target, started=now_iso())
        self._start_mono = time.monotonic()
        self._lock = threading.RLock()
        self._snap_hosts, self._snap_nets = scope.snapshot()
        self._authorized_ips: list[str] = []
        self._phase_start: dict[str, float] = {}
        self._phase_order: list[str] = []
        self._pool: Optional[ThreadPoolExecutor] = None

    def _literal_in_scope(self, host: str) -> bool:
        if host in self._snap_hosts:
            return True
        return any(str(n) == host or str(n.network_address) == host
                   for n in self._snap_nets)

    def _ip_in_scope(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip_str in self._snap_hosts:
            return True
        return any(ip in n for n in self._snap_nets)

    def authorize(self) -> tuple[bool, str]:
        ips = resolve_host(self.target)
        self.report.resolved_ips = ips
        if not ips:
            return False, "DNS resolution failed."
        out = [ip for ip in ips if not self._ip_in_scope(ip)]
        if out:
            return False, (f"Resolved IP(s) outside authorized scope: "
                           f"{', '.join(out)}")
        self._authorized_ips = ips
        return True, ""

    def _emit(self, category: str, message: str, severity: str = "info",
              port: int = 0, evidence: str = "",
              refs: Optional[list[str]] = None,
              cve: str = "", cvss: float = 0.0,
              remediation: str = "",
              service: str = "") -> None:
        mitre = MITRE_MAP.get(category, [])
        owasp: list[str] = []
        for key, vals in OWASP_MAP.items():
            if key.lower() in message.lower():
                owasp.extend(vals)
        f = Finding(
            ts=now_iso(), target=self.target, category=category,
            message=message, severity=severity,
            score=SEVERITY_SCORE.get(severity, 0.0),
            evidence=(evidence or "")[:8192], port=port, refs=refs or [],
            mitre=mitre, owasp=sorted(set(owasp)),
            cve=cve, cvss=cvss, remediation=remediation,
            service=service,
        )
        with self._lock:
            self.report.findings.append(f)
        self.q.put(("finding", f))

    def _guard(self) -> bool:
        return not self.stop.is_set()

    def _phase(self, name: str) -> None:
        now = time.monotonic()
        if self._phase_start:
            last_name = self._phase_order[-1]
            self.report.phase_times[last_name] = round(
                now - self._phase_start[last_name], 3)
        self._phase_start[name] = now
        self._phase_order.append(name)
        self.q.put(("phase", name))

    def run(self) -> None:
        try:
            self._emit("INFO", f"Scan started for {self.target}")
            self._emit("INFO", f"Scope: {self.scope.describe()}")
            self._phase("DNS")
            ok, reason = self.authorize()
            if not ok:
                self._emit("SCOPE", f"Not authorized: {reason}",
                           severity="critical")
                self._finish(aborted=True, reason=reason)
                return
            ips = self.report.resolved_ips
            if ips:
                self._emit("DNS", f"Resolved to: {', '.join(ips)}")
            rev = reverse_dns(ips[0]) if ips else ""
            self.report.reverse_dns = rev
            if rev:
                self._emit("DNS", f"Reverse DNS: {rev}")
            dns = dns_records(self.target)
            self.report.dns = dns
            for rtype in ("A", "AAAA"):
                if dns.get(rtype):
                    self._emit("DNS", f"  {rtype}: {', '.join(dns[rtype])}")
            if self.enable_whois and self._guard() and not _is_ip(self.target):
                self._phase("WHOIS")
                who = whois_lookup(self.target, self.stop)
                self.report.whois = who
                for k, v in who.items():
                    self._emit("WHOIS", f"  {k}: {v}", severity="info")
            if self.enable_ct and self._guard() and not _is_ip(self.target):
                self._phase("CT")
                names = ct_log_lookup(self.target, self.stop)
                self.report.ct_logs = names
                if names:
                    self._emit("CT", f"  CT logs found {len(names)} names",
                               severity="info")
                    for n in names[:30]:
                        self._emit("CT", f"  {n}", severity="info")
            if self.enable_subdomains and self._guard() and not _is_ip(self.target):
                self._phase("Subdomains")
                self._enumerate_subdomains()
            self._phase("Ports")
            self._emit("INFO", f"Scanning {len(self.ports)} port(s)")
            open_ports = self._scan_ports()
            self.report.open_ports = open_ports
            if self.enable_udp and self._guard():
                self._phase("UDP")
                self._scan_udp()
            if self.enable_service_detect and self._guard():
                self._phase("Services")
                for port in open_ports:
                    if not self._guard():
                        break
                    if not self.rate.take():
                        continue
                    svc = service_detect(self.target, port, self.stop)
                    if svc:
                        first = svc.splitlines()[0][:200] if svc.splitlines() else ""
                        if first:
                            self.report.services[str(port)] = first
                            nmap_name = _nmap_service_name(svc, port)
                            self._emit("SERVICE",
                                       f"Port {port}: {first}",
                                       port=port, evidence=svc[:500],
                                       service=nmap_name)
            if self.enable_http and self._guard():
                self._phase("HTTP")
                http_ports = [p for p in open_ports if p in WEB_PORTS]
                for port in http_ports:
                    if not self._guard():
                        break
                    if not self.rate.take():
                        continue
                    self._probe_http(port)
            if self.enable_tls and self._guard():
                self._phase("TLS")
                tls_ports = [p for p in open_ports if p in TLS_PORTS]
                for port in tls_ports:
                    if not self._guard():
                        break
                    if not self.rate.take():
                        continue
                    self._probe_tls(port)
            if self.enable_path_probe and self._guard():
                self._phase("Web")
                http_ports = [p for p in open_ports if p in WEB_PORTS]
                for port in http_ports:
                    if not self._guard():
                        break
                    self._probe_paths(port)
            self._compute_risk_score()
            self._finish()
        except Exception as exc:
            self._emit("ERROR", f"Unexpected scan error: {exc}",
                       severity="high", evidence=traceback.format_exc()[:2000])
            self._finish(aborted=True, reason=str(exc))

    def _compute_risk_score(self) -> None:
        weights = {"critical": 10.0, "high": 6.0, "medium": 3.0,
                   "low": 1.0, "info": 0.0}
        total = 0.0
        for f in self.report.findings:
            total += weights.get(f.severity, 0.0)
        self.report.risk_score = round(min(100.0, total * 2.5), 2)

    def _finish(self, aborted: bool = False, reason: str = "") -> None:
        if self._phase_start:
            now = time.monotonic()
            last_name = self._phase_order[-1]
            self.report.phase_times[last_name] = round(
                now - self._phase_start[last_name], 3)
        self.report.finished = now_iso()
        self.report.duration_s = round(time.monotonic() - self._start_mono, 3)
        self.report.aborted = aborted
        self.report.aborted_reason = reason
        if aborted:
            self._emit("INFO", f"Scan aborted: {reason}", severity="low")
        else:
            self._emit("INFO",
                       f"Scan finished in {self.report.duration_s:.2f}s. "
                       f"{len(self.report.open_ports)} open port(s). "
                       f"Risk score: {self.report.risk_score}/100")
        self.q.put(("phase", "Done"))
        self.q.put(("done", self.report))

    def _enumerate_subdomains(self) -> None:
        base = self.target
        try:
            ipaddress.ip_address(base)
            return
        except ValueError:
            pass
        parts = base.split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else base
        words = set(SUBDOMAIN_WORDLIST)
        for w in list(SUBDOMAIN_WORDLIST)[:20]:
            for suffix in ("1", "2", "01", "-dev", "-test", "-stage", "-prod"):
                words.add(w + suffix)
        found: list[str] = []
        lock = threading.Lock()

        def _check(label: str) -> None:
            if not self._guard():
                return
            if not self.rate.take():
                return
            host = f"{label}.{apex}"
            try:
                infos = socket.getaddrinfo(host, None)
                ips_here = sorted({i[4][0] for i in infos})
                if ips_here:
                    with lock:
                        found.append(host)
                    if all(self._ip_in_scope(ip) for ip in ips_here):
                        self._emit("SUBDOMAIN",
                                   f"{host} -> {', '.join(ips_here)}",
                                   severity="info")
                    else:
                        self._emit("SUBDOMAIN",
                                   f"{host} -> {', '.join(ips_here)} "
                                   f"(out of scope)",
                                   severity="info")
            except Exception:
                return

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            list(pool.map(_check, sorted(words)))
        self.report.subdomains = sorted(set(found))

    def _scan_ports(self) -> list[int]:
        open_ports: list[int] = []
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures: dict[Future, int] = {}
            for port in self.ports:
                if not self._guard():
                    break
                if not self.rate.take():
                    self._emit("RATE", f"Rate limit timeout before port {port}",
                               severity="low", port=port)
                    continue
                futures[pool.submit(self._probe_port, port)] = port
            for fut in as_completed(futures):
                port = futures[fut]
                try:
                    is_open, _, _ = fut.result(
                        timeout=CONNECT_TIMEOUT + BANNER_TIMEOUT + 4)
                except Exception as exc:
                    self._emit("TCP", f"Port {port}: probe error ({exc})",
                               severity="low", port=port)
                    self.q.put(("progress", None))
                    continue
                if is_open:
                    with lock:
                        open_ports.append(port)
                self.q.put(("progress", None))
                if not self._guard():
                    for f in futures:
                        f.cancel()
                    break
        open_ports.sort()
        return open_ports

    def _probe_port(self, port: int) -> tuple[bool, str, str]:
        if not self._guard():
            return False, "stopped", ""
        is_open, detail, banner = tcp_connect_check(
            self.target, port, self.stop,
            connect_timeout=self.cfg.connect_timeout,
            banner_timeout=self.cfg.banner_timeout)
        if is_open:
            sev = "low" if port in (23, 21, 135, 139, 445, 3389) else "info"
            msg = f"Port {port}: open"
            if banner:
                lines = banner.splitlines()
                first = lines[0][:200] if lines else ""
                if first:
                    msg += f" | banner: {first}"
            nmap_name = _nmap_service_name(banner, port)
            self._emit("TCP", msg, severity=sev, port=port,
                       evidence=banner[:MAX_BANNER], service=nmap_name)
            for sev2, note, ref in check_vuln_banner(banner):
                cve = ""
                cvss = 0.0
                for key, entries in CVE_DB.items():
                    if key.lower() in banner.lower():
                        for c, desc, s, cv in entries:
                            cve, cvss = c, cv
                            sev2 = s
                            note = f"{desc} ({c})"
                            break
                self._emit("VULN", f"Port {port}: {note}",
                           severity=sev2, port=port,
                           evidence=banner[:300],
                           refs=[ref] if ref else [],
                           cve=cve, cvss=cvss,
                           remediation="Upgrade to a supported version.")
        else:
            self._emit("TCP", f"Port {port}: {detail}", port=port)
        return is_open, detail, banner

    def _scan_udp(self) -> None:
        udp_ports = sorted(set(
            [p for p in UDP_SERVICES if p in self.ports] +
            [53, 123, 161]
        ))
        open_udp: list[int] = []
        for port in udp_ports:
            if not self._guard():
                break
            if not self.rate.take():
                continue
            name, payload, _kind = UDP_SERVICES[port]
            is_open, detail = udp_probe(self.target, port, payload, self.stop,
                                        timeout=self.cfg.udp_timeout)
            if is_open:
                open_udp.append(port)
                self._emit("UDP", f"Port {port}/udp: {name} responded",
                           severity="info", port=port, evidence=detail,
                           service=name.lower())
            elif detail == "open|filtered":
                self._emit("UDP", f"Port {port}/udp: open|filtered ({name})",
                           severity="info", port=port)
        self.report.open_udp_ports = open_udp

    def _probe_http(self, port: int) -> None:
        ok, info, err = http_probe(
            self.target, port, stop_event=self.stop,
            custom_headers=self.cfg.custom_headers,
            user_agent=self.cfg.user_agent,
            timeout=self.cfg.http_timeout)
        if not ok:
            self._emit("HTTP", f"Port {port}: probe failed ({err})",
                       severity="low", port=port)
            return
        status = info.get("status", 0)
        reason = info.get("reason", "")
        ttfb = info.get("timings", {}).get("ttfb", 0)
        self._emit("HTTP", f"Port {port}: HTTP {status} {reason} (TTFB {ttfb}s)",
                   port=port, evidence=info.get("body_snippet", "")[:300])
        for from_status, loc in info.get("redirect_chain", []):
            self._emit("HTTP", f"  {from_status} -> {loc}", port=port)
        headers: dict[str, list[str]] = info.get("headers", {})
        for h in INFO_LEAK_HEADERS:
            if h.lower() in headers:
                v = ", ".join(headers[h.lower()])
                sev = "low" if h.lower() == "server" else "info"
                self._emit("HTTP", f"  {h}: {v}", severity=sev, port=port)
        for h, (sev, note) in SECURITY_HEADERS.items():
            if h.lower() in headers:
                v = ", ".join(headers[h.lower()])
                self._emit("HTTP", f"  {h}: {v}", port=port)
                if h == "Strict-Transport-Security":
                    for s2, msg in check_hsts(v):
                        self._emit("HTTP", f"  {msg}", severity=s2, port=port)
                elif h == "Content-Security-Policy":
                    for s2, msg in check_csp(v):
                        self._emit("HTTP", f"  {msg}", severity=s2, port=port)
                elif h == "Referrer-Policy":
                    for s2, msg in check_referrer_policy(v):
                        self._emit("HTTP", f"  {msg}", severity=s2, port=port)
            else:
                self._emit("HTTP", f"  Missing {h}: {note}",
                           severity=sev, port=port)
        for s2, msg in check_cookies(headers.get("set-cookie", [])):
            self._emit("HTTP", f"  {msg}", severity=s2, port=port)
        for s2, msg in check_cors(headers):
            self._emit("HTTP", f"  {msg}", severity=s2, port=port)
        for s2, msg in check_http2(headers):
            self._emit("HTTP", f"  {msg}", severity=s2, port=port)
        for s2, msg in check_host_header(headers):
            self._emit("HTTP", f"  {msg}", severity=s2, port=port)
        srv = ", ".join(headers.get("server", []))
        for sev2, note, ref in check_vuln_banner(srv):
            cve, cvss = "", 0.0
            for key, entries in CVE_DB.items():
                if key.lower() in srv.lower():
                    for c, desc, s, cv in entries:
                        cve, cvss, sev2 = c, cv, s
                        note = f"{desc} ({c})"
                        break
            self._emit("VULN", f"HTTP Server banner: {note}",
                       severity=sev2, port=port, evidence=srv[:300],
                       refs=[ref] if ref else [], cve=cve, cvss=cvss)
        for method, st in info.get("methods", {}).items():
            if method in ("PUT", "DELETE", "TRACE") and st in (200, 204, 301, 302):
                self._emit("HTTP",
                           f"  Method {method} returned {st} — review",
                           severity="medium", port=port)
        if "allow" in headers:
            allow = ", ".join(headers["allow"])
            self._emit("HTTP", f"  Allow: {allow}", port=port)
            present = {m.strip().lower() for m in allow.split(",")}
            bad = present & DANGEROUS_HTTP_METHODS
            if bad:
                self._emit("HTTP",
                           f"  Dangerous methods advertised: "
                           f"{', '.join(sorted(bad))}",
                           severity="medium", port=port)
        body = info.get("body_snippet", "")
        self._fingerprint(port, body)
        self._detect_waf(port, headers)
        for tok in detect_jwt(body):
            self._emit("HTTP", f"  JWT in body: {tok[:60]}...",
                       severity="medium", port=port, evidence=tok[:120])
        eps = extract_js_endpoints(body)
        if eps:
            with self._lock:
                for e in eps:
                    if e not in self.report.js_endpoints:
                        self.report.js_endpoints.append(e)
            self._emit("HTTP", f"  {len(eps)} endpoint(s) in body",
                       severity="info", port=port,
                       evidence="\n".join(eps[:20]))
        if self.enable_secret_scan:
            for sev2, label, text in detect_secrets(body):
                self._emit("HTTP", f"  Possible {label} in body",
                           severity=sev2, port=port, evidence=text)
        fav = self._fetch_favicon(port, info.get("scheme", "http"))
        if fav:
            h = favicon_hash(fav)
            self._emit("HTTP", f"  Favicon hash: {h}", port=port)

    def _fetch_favicon(self, port: int, scheme: str) -> Optional[bytes]:
        try:
            conn = _make_http_conn(scheme, self.target, port,
                                   self.cfg.http_timeout)
            conn.request("GET", "/favicon.ico",
                         headers={"User-Agent": self.cfg.user_agent,
                                  "Connection": "close"})
            r = conn.getresponse()
            data = r.read(65536)
            conn.close()
            if r.status == 200 and len(data) > 0:
                return data
        except Exception:
            return None
        return None

    def _fingerprint(self, port: int, blob: str) -> None:
        found: set[str] = set()
        for pat, name, _kind in TECH_FINGERPRINTS:
            if pat.search(blob):
                found.add(name)
        for name in sorted(found):
            with self._lock:
                if name not in self.report.technologies:
                    self.report.technologies.append(name)
            self._emit("TECH", f"Port {port}: detected {name}", port=port)

    def _detect_waf(self, port: int, headers: dict[str, list[str]]) -> None:
        hits: set[str] = set()
        for hname, pat, waf in WAF_SIGNATURES:
            vs = headers.get(hname.lower(), [])
            for v in vs:
                if pat == "." or re.search(pat, v, re.I):
                    hits.add(waf)
        for w in sorted(hits):
            with self._lock:
                if w not in self.report.waf:
                    self.report.waf.append(w)
            self._emit("WAF", f"Port {port}: WAF/CDN detected: {w}",
                       severity="info", port=port)

    def _probe_paths(self, port: int) -> None:
        scheme = "https" if port in TLS_PORTS else "http"
        baseline_status: Optional[int] = None
        baseline_len: Optional[int] = None
        try:
            if not self.rate.take():
                return
            conn = _make_http_conn(scheme, self.target, port,
                                   self.cfg.http_timeout)
            conn.request("GET", "/__safeassess_404_" + str(random.randint(
                100000, 999999)),
                headers={"User-Agent": self.cfg.user_agent,
                         "Connection": "close"})
            r = conn.getresponse()
            baseline_status = r.status
            baseline_len = len(r.read(4096))
            conn.close()
        except Exception:
            pass
        paths = list(SAFE_PATHS)
        if self.enable_web_discovery:
            try:
                if not self.rate.take():
                    return
                conn = _make_http_conn(scheme, self.target, port,
                                       self.cfg.http_timeout)
                conn.request("GET", "/robots.txt",
                             headers={"User-Agent": self.cfg.user_agent,
                                      "Connection": "close"})
                r = conn.getresponse()
                body = r.read(65536).decode("utf-8", errors="replace")
                conn.close()
                if r.status == 200:
                    rp = parse_robots(body)
                    with self._lock:
                        self.report.robots_paths = rp
                    if rp:
                        self._emit("WEB",
                                   f"Port {port}: robots.txt → "
                                   f"{len(rp)} entries",
                                   severity="info", port=port,
                                   evidence="\n".join(rp[:20]))
                        for p in rp[:30]:
                            if p.startswith("http"):
                                continue
                            if p not in paths:
                                paths.append(p)
            except Exception:
                pass
            try:
                if not self.rate.take():
                    return
                conn = _make_http_conn(scheme, self.target, port,
                                       self.cfg.http_timeout)
                conn.request("GET", "/sitemap.xml",
                             headers={"User-Agent": self.cfg.user_agent,
                                      "Connection": "close"})
                r = conn.getresponse()
                body = r.read(131072).decode("utf-8", errors="replace")
                conn.close()
                if r.status == 200:
                    urls = parse_sitemap(body)
                    with self._lock:
                        self.report.sitemap_urls = urls
                    if urls:
                        self._emit("WEB",
                                   f"Port {port}: sitemap.xml → "
                                   f"{len(urls)} URLs",
                                   severity="info", port=port,
                                   evidence="\n".join(urls[:20]))
            except Exception:
                pass

        for path in paths:
            if not self._guard():
                return
            if not self.rate.take():
                return
            try:
                conn = _make_http_conn(scheme, self.target, port,
                                       self.cfg.http_timeout)
                conn.request("GET", path, headers={
                    "User-Agent": self.cfg.user_agent, "Connection": "close"})
                r = conn.getresponse()
                body = r.read(65536)
                status = r.status
                length = len(body)
                ctype = r.getheader("Content-Type", "") or ""
                conn.close()
            except Exception:
                continue
            interesting = status in (200, 201, 204, 301, 302, 307, 308, 401, 403)
            if interesting:
                if (baseline_status == status and baseline_len is not None
                        and abs(length - baseline_len) < 32
                        and status in (404, 200)):
                    continue
                sev = "info"
                if path in ("/.git/HEAD", "/.env", "/.htaccess"):
                    sev = "medium" if status == 200 else "low"
                elif path.startswith("/actuator") or path.startswith("/api"):
                    sev = "low"
                snippet = body[:200].decode("utf-8", errors="replace")
                text = body.decode("utf-8", errors="replace")
                if path in ("/security.txt", "/.well-known/security.txt") and status == 200:
                    sec = parse_security_txt(text)
                    if sec:
                        with self._lock:
                            self.report.security_txt = sec
                        self._emit("WEB", f"Port {port}: security.txt parsed",
                                   severity="info", port=port,
                                   evidence=json.dumps(sec)[:300])
                secret_hits = (detect_secrets(text)
                               if self.enable_secret_scan else [])
                self._emit("PATH",
                           f"Port {port}: {path} -> {status} ({length}B) "
                           f"{ctype.split(';')[0]}",
                           severity=sev, port=port, evidence=snippet)
                for s2, label, ev in secret_hits:
                    self._emit("SECRET",
                               f"Port {port}: {label} in {path}",
                               severity=s2, port=port, evidence=ev)

    def _probe_tls(self, port: int) -> None:
        ok, info, err = tls_probe(self.target, port, self.stop,
                                  timeout=self.cfg.tls_timeout)
        if not ok:
            self._emit("TLS", f"Port {port}: {err}", severity="low", port=port)
            return
        with self._lock:
            self.report.tls_certs[str(port)] = {
                "protocol": info.get("protocol", ""),
                "cipher": info.get("cipher", ""),
                "subject_cn": info.get("subject_cn", ""),
                "issuer_cn": info.get("issuer_cn", ""),
                "not_after": info.get("not_after", ""),
                "days_left": info.get("days_left"),
                "self_signed": info.get("self_signed", False),
                "key_type": info.get("key_type", ""),
                "key_bits": info.get("key_bits", 0),
            }
        proto = info.get("protocol", "")
        cipher = info.get("cipher", "")
        self._emit("TLS", f"Port {port}: protocol={proto} cipher={cipher}",
                   port=port)
        if proto in ("TLSv1", "TLSv1.0"):
            self._emit("TLS", "  TLS 1.0 in use — deprecated, disable.",
                       severity="high", port=port)
        elif proto == "TLSv1.1":
            self._emit("TLS", "  TLS 1.1 in use — deprecated, disable.",
                       severity="medium", port=port)

        weak = ("RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "anon")
        if any(m.lower() in cipher.lower() for m in weak):
            self._emit("TLS", f"  Weak cipher negotiated: {cipher}",
                       severity="high", port=port)

        if self.enable_tls_versions and self._guard():
            versions = tls_version_probe(self.target, port, self.stop,
                                         timeout=self.cfg.tls_timeout)
            supported = [v for v, ok2 in versions.items() if ok2]
            if "TLSv1" in supported or "TLSv1.1" in supported:
                legacy = [v for v in supported if v in ("TLSv1", "TLSv1.1")]
                self._emit("TLS",
                           f"  Legacy protocols accepted: {', '.join(legacy)}",
                           severity="high", port=port)
            if "TLSv1.3" not in supported:
                self._emit("TLS", "  TLS 1.3 not supported.",
                           severity="low", port=port)

        if not info.get("verified", True):
            self._emit("TLS",
                       f"  Certificate not trusted: "
                       f"{info.get('verify_error','')}",
                       severity="medium", port=port)
        if info.get("self_signed"):
            self._emit("TLS", "  Self-signed certificate detected.",
                       severity="low", port=port)
        if info.get("weak_key"):
            self._emit("TLS",
                       f"  Weak public key: {info.get('key_type','')} "
                       f"{info.get('key_bits','')} bits",
                       severity="high", port=port)
        self._emit("TLS", f"  Subject CN: {info.get('subject_cn','')} "
                          f"({info.get('subject_org','')})", port=port)
        self._emit("TLS", f"  Issuer: {info.get('issuer_cn','')} "
                          f"({info.get('issuer_org','')})", port=port)
        self._emit("TLS", f"  Valid: {info.get('not_before','')}  ->  "
                          f"{info.get('not_after','')}", port=port)
        days = info.get("days_left")
        if days is not None:
            if days < 0:
                self._emit("TLS", f"  Certificate EXPIRED {-days} day(s) ago.",
                           severity="critical", port=port)
            elif days < 7:
                self._emit("TLS", f"  Certificate expires in {days} day(s).",
                           severity="high", port=port)
            elif days < 14:
                self._emit("TLS", f"  Certificate expires in {days} day(s).",
                           severity="medium", port=port)
            elif days < 30:
                self._emit("TLS", f"  Certificate expires in {days} day(s).",
                           severity="low", port=port)
            else:
                self._emit("TLS", f"  Certificate expires in {days} day(s).",
                           port=port)
        cn = info.get("subject_cn", "")
        san = [v for _, v in info.get("san", [])]
        host = self.target

        def _matches(name: str) -> bool:
            if not name:
                return False
            if name == host:
                return True
            if name.startswith("*."):
                return (host.endswith(name[1:])
                        and host.count(".") >= name.count("."))
            return False

        if cn and not _matches(cn) and not any(_matches(n) for n in san):
            self._emit("TLS", f"  Certificate CN/SAN does not match target "
                              f"'{host}'.", severity="medium", port=port)
        if san:
            names = san[:20]
            self._emit("TLS", f"  SAN: {', '.join(names)}", port=port)
        chain_len = info.get("chain_len")
        if chain_len is not None:
            self._emit("TLS", f"  Chain length: {chain_len}", port=port)
        if info.get("key_type"):
            self._emit("TLS", f"  Public key: {info.get('key_type')} "
                              f"{info.get('key_bits')} bits "
                              f"({info.get('sig_algo','')})", port=port)
        if self.enable_ciphers and self._guard():
            if not self.rate.take():
                return
            accepted = enumerate_weak_ciphers(self.target, port, self.stop,
                                              timeout=self.cfg.tls_timeout)
            if accepted:
                self._emit("TLS",
                           f"  Weak ciphers accepted: "
                           f"{', '.join(sorted(set(accepted)))}",
                           severity="high", port=port,
                           evidence=", ".join(sorted(set(accepted))))

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def check_hsts(value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    lower = value.lower()
    if "max-age" not in lower:
        out.append(("low", "HSTS missing max-age"))
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", lower)
        if m and int(m.group(1)) < 15552000:
            out.append(("low",
                        f"HSTS max-age too low ({m.group(1)} < 15552000)"))
    if "includesubdomains" not in lower:
        out.append(("info", "HSTS missing includeSubDomains"))
    if "preload" not in lower:
        out.append(("info", "HSTS missing preload"))
    return out

def check_http2(headers: dict[str, list[str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if "alt-svc" in headers:
        for v in headers["alt-svc"]:
            if "h3" in v.lower():
                out.append(("info", f"HTTP/3 advertised via Alt-Svc: {v}"))
            if "h2" in v.lower():
                out.append(("info", f"HTTP/2 advertised via Alt-Svc: {v}"))
    return out

def check_host_header(headers: dict[str, list[str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if "x-forwarded-host" in headers:
        out.append(("info",
                    "X-Forwarded-Host present — verify host-header validation"))
    return out

def diff_reports(old: dict, new: dict) -> list[str]:
    out: list[str] = []
    old_ports = set(old.get("report", {}).get("open_ports", [])
                    or old.get("open_ports", []))
    new_ports = set(new.get("report", {}).get("open_ports", [])
                    or new.get("open_ports", []))
    opened = new_ports - old_ports
    closed = old_ports - new_ports
    if opened:
        out.append(f"[+] Ports newly open: {sorted(opened)}")
    if closed:
        out.append(f"[-] Ports now closed: {sorted(closed)}")
    def _fkeys(d: dict) -> set[tuple]:
        return {(f.get("category"), f.get("port"), f.get("message"),
                 f.get("severity")) for f in d.get("findings", [])}
    ofk = _fkeys(old)
    nfk = _fkeys(new)
    added = nfk - ofk
    removed = ofk - nfk
    for cat, port, msg, sev in sorted(added, key=lambda x: x[3]):
        out.append(f"[+] NEW  [{cat}/{str(sev).upper()}]:{port} {msg}")
    for cat, port, msg, sev in sorted(removed, key=lambda x: x[3]):
        out.append(f"[-] GONE [{cat}/{str(sev).upper()}]:{port} {msg}")
    for key in ("technologies", "waf", "subdomains"):
        o = set((old.get("report", {}) or {}).get(key, []) or [])
        n = set((new.get("report", {}) or {}).get(key, []) or [])
        for v in sorted(n - o):
            out.append(f"[+] NEW  {key}: {v}")
        for v in sorted(o - n):
            out.append(f"[-] GONE {key}: {v}")
    if not out:
        out.append("No differences detected.")
    return out

class App:
    def __init__(self, root: Any, cfg: Optional[Config] = None):
        self.root = root
        self.cfg = cfg or Config.load()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1360x900")
        self.root.minsize(1080, 720)
        self.scope = self.cfg.scope
        self.rate_limit = self.cfg.rate_limit
        self.workers = self.cfg.workers
        self._load_profiles()
        self.queue: "queue.Queue[tuple]" = queue.Queue()
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.report: Optional[ScanReport] = None
        self._all_findings: list[Finding] = []
        self._seen_keys: set[tuple] = set()
        self._expected_ticks = 0
        self._done_ticks = 0
        self._after_id: Optional[str] = None
        self._last_target: str = self.cfg.last_target
        self._start_mono = 0.0
        try:
            from tkinter import ttk
            style = ttk.Style()
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except Exception:
            pass
        self._build_ui()
        self._bind_shortcuts()
        self._after_id = self.root.after(80, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_profiles(self) -> None:
        extra = load_json(PROFILES_FILE, {}) or {}
        for name, ports in extra.items():
            if (isinstance(ports, list)
                    and name not in PORT_PROFILES):
                cleaned = []
                for p in ports:
                    try:
                        ip = int(p)
                    except (TypeError, ValueError):
                        continue
                    if 1 <= ip <= 65535:
                        cleaned.append(ip)
                if cleaned:
                    PORT_PROFILES[name] = cleaned

    def _save_profiles(self) -> None:
        user = {k: v for k, v in PORT_PROFILES.items()
                if k not in BUILTIN_PROFILE_NAMES}
        save_json(PROFILES_FILE, user)

    def _build_ui(self) -> None:
        from tkinter import ttk, StringVar, BooleanVar, Text, END, DISABLED, NORMAL
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Target:").grid(row=0, column=0, sticky="w")
        self.target_var = StringVar(value=self._last_target)
        ttk.Entry(top, textvariable=self.target_var, width=32).grid(
            row=0, column=1, padx=6, sticky="w")
        ttk.Label(top, text="Template:").grid(row=0, column=2, sticky="w",
                                              padx=(12, 0))
        self.template_var = StringVar(value="standard")
        ttk.Combobox(top, textvariable=self.template_var,
                     values=list(TEMPLATES.keys()), state="readonly",
                     width=12).grid(row=0, column=3, padx=6, sticky="w")
        ttk.Label(top, text="Port profile:").grid(row=0, column=4, sticky="w",
                                                  padx=(12, 0))
        self.profile_var = StringVar(value="Top 20 (safe default)")
        self.profile_cb = ttk.Combobox(
            top, textvariable=self.profile_var,
            values=list(PORT_PROFILES.keys()), state="readonly", width=22)
        self.profile_cb.grid(row=0, column=5, padx=6, sticky="w")
        self.profile_cb.bind("<<ComboboxSelected>>",
                             lambda _e: self._on_profile_change())

        ttk.Label(top, text="Custom ports:").grid(row=1, column=0, sticky="w",
                                                  pady=(6, 0))
        self.custom_ports_var = StringVar(value="")
        self.custom_ports_entry = ttk.Entry(
            top, textvariable=self.custom_ports_var, width=32)
        self.custom_ports_entry.grid(row=1, column=1, padx=6, pady=(6, 0),
                                     sticky="w")
        self.custom_ports_entry.configure(state="disabled")
        ttk.Label(top, text="(comma/space separated, ranges ok, max 2048)").grid(
            row=1, column=2, columnspan=4, sticky="w", pady=(6, 0))

        ttk.Label(top, text="Rate (probes/s):").grid(row=2, column=0,
                                                     sticky="w", pady=(6, 0))
        self.rate_var = StringVar(value=str(self.rate_limit))
        ttk.Entry(top, textvariable=self.rate_var, width=8).grid(
            row=2, column=1, padx=6, pady=(6, 0), sticky="w")
        ttk.Label(top, text="Workers:").grid(row=2, column=2, sticky="w",
                                             padx=(12, 0), pady=(6, 0))
        self.workers_var = StringVar(value=str(self.workers))
        ttk.Entry(top, textvariable=self.workers_var, width=6).grid(
            row=2, column=3, padx=6, pady=(6, 0), sticky="w")
        toggles = ttk.Frame(self.root, padding=(10, 0, 10, 4))
        toggles.pack(fill="x")
        self.enable_http = BooleanVar(value=True)
        self.enable_tls = BooleanVar(value=True)
        self.enable_ciphers = BooleanVar(value=False)
        self.enable_web_disc = BooleanVar(value=True)
        self.enable_subdomains = BooleanVar(value=True)
        self.enable_tls_versions = BooleanVar(value=True)
        self.enable_path_probe = BooleanVar(value=True)
        self.enable_udp = BooleanVar(value=True)
        self.enable_service_detect = BooleanVar(value=True)
        self.enable_whois = BooleanVar(value=True)
        self.enable_ct = BooleanVar(value=True)
        self.enable_secret_scan = BooleanVar(value=True)
        for text, var in (
            ("HTTP", self.enable_http),
            ("TLS", self.enable_tls),
            ("Ciphers", self.enable_ciphers),
            ("TLS versions", self.enable_tls_versions),
            ("Paths", self.enable_path_probe),
            ("Subdomains", self.enable_subdomains),
            ("UDP", self.enable_udp),
            ("Services", self.enable_service_detect),
            ("WHOIS", self.enable_whois),
            ("CT logs", self.enable_ct),
            ("Secrets", self.enable_secret_scan),
            ("Web discovery", self.enable_web_disc),
        ):
            ttk.Checkbutton(toggles, text=text,
                            variable=var).pack(side="left", padx=3)
        btns = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        btns.pack(fill="x")
        self.start_btn = ttk.Button(btns, text="Start",
                                    command=self.start_check)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="Stop",
                                   command=self.stop_check, state=DISABLED)
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="Scope…",
                   command=self.open_scope_manager).pack(side="left", padx=6)
        for label, fmt in (("TXT", "txt"), ("JSON", "json"), ("CSV", "csv"),
                           ("MD", "md"), ("HTML", "html"),
                           ("SARIF", "sarif"), ("JUnit", "junit")):
            ttk.Button(btns, text=label,
                       command=lambda f=fmt: self.save(f)).pack(side="left",
                                                                padx=3)
        ttk.Button(btns, text="Diff…",
                   command=self.diff_json).pack(side="left", padx=6)
        ttk.Button(btns, text="Clear",
                   command=self.clear_output).pack(side="left", padx=6)
        filt = ttk.Frame(self.root, padding=(10, 0, 10, 4))
        filt.pack(fill="x")
        ttk.Label(filt, text="Show:").pack(side="left")
        self.show_info = BooleanVar(value=True)
        self.show_low = BooleanVar(value=True)
        self.show_med = BooleanVar(value=True)
        self.show_high = BooleanVar(value=True)
        self.show_crit = BooleanVar(value=True)
        for label, var in (("info", self.show_info), ("low", self.show_low),
                           ("medium", self.show_med), ("high", self.show_high),
                           ("critical", self.show_crit)):
            ttk.Checkbutton(filt, text=label, variable=var,
                            command=self._reapply_filter).pack(side="left",
                                                                padx=4)
        self.filter_var = StringVar(value="")
        ttk.Label(filt, text="Search:").pack(side="left", padx=(12, 2))
        ttk.Entry(filt, textvariable=self.filter_var, width=22).pack(side="left")
        self.filter_var.trace_add("write", lambda *_: self._reapply_filter())
        self.category_var = StringVar(value="All")
        ttk.Label(filt, text="Cat:").pack(side="left", padx=(12, 2))
        self.category_cb = ttk.Combobox(
            filt, textvariable=self.category_var, width=12, state="readonly",
            values=["All", "INFO", "DNS", "WHOIS", "CT", "SUBDOMAIN", "TCP",
                    "UDP", "SERVICE", "HTTP", "TLS", "VULN", "TECH", "WAF",
                    "PATH", "SECRET", "WEB", "SCOPE", "RATE", "ERROR"])
        self.category_cb.pack(side="left")
        self.category_cb.bind("<<ComboboxSelected>>",
                              lambda _e: self._reapply_filter())
        mid = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        mid.pack(fill="both", expand=True)
        self.output = Text(mid, wrap="word", state=DISABLED, height=24,
                           font=("Consolas" if os.name == "nt"
                                 else "Monospace", 10))
        self.output.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, command=self.output.yview)
        sb.pack(side="right", fill="y")
        self.output.config(yscrollcommand=sb.set)
        for sev, color in SEVERITY_COLORS.items():
            weight = "bold" if sev == "critical" else "normal"
            self.output.tag_configure(
                sev, foreground=color,
                font=("Consolas" if os.name == "nt"
                      else "Monospace", 10, weight))
        status = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        status.pack(fill="x")
        self.status_var = StringVar(value="Idle.")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")
        self.phase_var = StringVar(value="")
        ttk.Label(status, textvariable=self.phase_var).pack(side="left", padx=12)
        self.eta_var = StringVar(value="")
        ttk.Label(status, textvariable=self.eta_var).pack(side="left", padx=12)
        self.progress = ttk.Progressbar(status, mode="determinate", length=240)
        self.progress.pack(side="right")

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Control-Return>", lambda _e: self.start_check())
        self.root.bind("<Escape>", lambda _e: self.stop_check())
        self.root.bind("<Control-s>", lambda _e: self.save("json"))
        self.root.bind("<Control-l>", lambda _e: self.clear_output())
        self.root.bind("<F5>", lambda _e: self.start_check())
        self.root.bind("<Control-d>", lambda _e: self.diff_json())

    def _on_profile_change(self) -> None:
        if self.profile_var.get() == "Custom":
            self.custom_ports_entry.configure(state="normal")
        else:
            self.custom_ports_entry.configure(state="disabled")

    def open_scope_manager(self) -> None:
        from tkinter import (Toplevel, Listbox, StringVar, END, ttk,
                             filedialog, messagebox)
        win = Toplevel(self.root)
        win.title("Manage Authorized Scope")
        win.geometry("600x520")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Authorized hosts and networks (CIDR ok):",
                  padding=8).pack(anchor="w")
        lb = Listbox(win, height=12, selectmode="extended")
        lb.pack(fill="both", expand=True, padx=8)
        self._scope_items: list[tuple[str, str]] = []

        def refresh():
            lb.delete(0, END)
            self._scope_items.clear()
            hosts, nets = self.scope.snapshot()
            for h in sorted(hosts):
                lb.insert(END, h)
                self._scope_items.append(("host", h))
            for n in nets:
                lb.insert(END, f"{n}  [network]")
                self._scope_items.append(("network", str(n)))
        refresh()
        row = ttk.Frame(win, padding=8)
        row.pack(fill="x")
        entry_var = StringVar()
        ttk.Entry(row, textvariable=entry_var, width=32).pack(side="left")

        def add():
            val = entry_var.get().strip()
            if not val:
                return
            if "/" in val:
                ok, err = self.scope.add_network(val)
                if not ok:
                    messagebox.showerror("Invalid network", err, parent=win)
                    return
            else:
                if not self.scope.add_host(val):
                    messagebox.showerror(
                        "Invalid host",
                        f"'{val}' is not a valid hostname or IP.", parent=win)
                    return
            entry_var.set("")
            refresh()
        ttk.Button(row, text="Add", command=add).pack(side="left", padx=4)
        def remove():
            sel = lb.curselection()
            if not sel:
                return
            for idx in reversed(sel):
                kind, value = self._scope_items[idx]
                if kind == "host":
                    self.scope.remove_host(value)
                else:
                    self.scope.remove_network(value)
            refresh()
        ttk.Button(row, text="Remove selected",
                   command=remove).pack(side="left", padx=4)
        def clear_scope():
            if not messagebox.askyesno(
                    "Clear scope",
                    "Remove ALL authorized hosts and networks?", parent=win):
                return
            self.scope.hosts = set()
            self.scope.networks = []
            refresh()
        ttk.Button(row, text="Clear all", command=clear_scope).pack(
            side="left", padx=4)
        btns2 = ttk.Frame(win, padding=8)
        btns2.pack(fill="x")

        def import_scope():
            path = filedialog.askopenfilename(
                filetypes=[("Text", "*.txt"), ("All", "*.*")], parent=win)
            if not path:
                return
            try:
                added = 0
                for line in Path(path).read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "/" in line:
                        ok, _ = self.scope.add_network(line)
                        added += 1 if ok else 0
                    else:
                        added += 1 if self.scope.add_host(line) else 0
                refresh()
                messagebox.showinfo("Import", f"Added {added} entries.",
                                    parent=win)
            except OSError as e:
                messagebox.showerror("Import failed", str(e), parent=win)

        def export_scope():
            path = filedialog.asksaveasfilename(
                defaultextension=".txt", parent=win)
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("# Authorized scope\n")
                    hosts, nets = self.scope.snapshot()
                    for h in sorted(hosts):
                        fh.write(h + "\n")
                    for n in nets:
                        fh.write(str(n) + "\n")
            except OSError as e:
                messagebox.showerror("Export failed", str(e), parent=win)
        ttk.Button(btns2, text="Import…", command=import_scope).pack(
            side="left", padx=4)
        ttk.Button(btns2, text="Export…", command=export_scope).pack(
            side="left", padx=4)
        ttk.Button(btns2, text="Close", command=win.destroy).pack(
            side="right", padx=4)
        ttk.Label(win, text=("Warning: add only systems you have explicit "
                             "written authorization to test."),
                  foreground="#a30000", padding=8).pack(anchor="w")

    def _selected_ports(self) -> Optional[list[int]]:
        from tkinter import messagebox
        profile = self.profile_var.get()
        if profile == "Custom":
            ok, ports = parse_custom_ports(self.custom_ports_var.get())
            if not ok:
                messagebox.showerror("Invalid ports", str(ports))
                return None
            return ports
        return list(PORT_PROFILES.get(profile, []))

    def _apply_template(self, name: str) -> None:
        t = TEMPLATES.get(name)
        if not t:
            return
        self.profile_var.set(t["profile"])
        self.enable_http.set(t["http"])
        self.enable_tls.set(t["tls"])
        self.enable_ciphers.set(t["ciphers"])
        self.enable_web_disc.set(t["web"])
        self.enable_subdomains.set(t["subdomains"])
        self.enable_tls_versions.set(t["tls_versions"])
        self.enable_path_probe.set(t["paths"])
        self.enable_udp.set(t["udp"])
        self.enable_service_detect.set(t["service_detect"])

    def start_check(self) -> None:
        from tkinter import messagebox, DISABLED, NORMAL, END
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Busy", "A check is already running.")
            return
        self._apply_template(self.template_var.get())
        host = self.target_var.get().strip()
        ok, err = validate_target(host)
        if not ok:
            messagebox.showerror("Invalid target", err)
            return
        ips = resolve_host(host)
        if not ips:
            messagebox.showerror("DNS failed", f"Could not resolve '{host}'.")
            return
        in_scope = (self.scope.contains(host)
                    and all(self.scope.contains_ip(ip) for ip in ips))
        if not in_scope:
            messagebox.showerror(
                "Out of scope",
                f"'{host}' is not in the authorized scope.\n"
                f"Resolved: {', '.join(ips)}\n"
                f"Add it in 'Manage Scope…' only if you have written permission.")
            return
        ports = self._selected_ports()
        if not ports:
            return
        try:
            self.rate_limit = max(0.1, float(self.rate_var.get()))
        except ValueError:
            self.rate_limit = DEFAULT_RATE
            self.rate_var.set(str(DEFAULT_RATE))
        try:
            self.workers = max(1, min(64, int(self.workers_var.get())))
        except ValueError:
            self.workers = MAX_WORKERS
            self.workers_var.set(str(self.workers))
        self._last_target = host
        self.stop_event.clear()
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self._expected_ticks = len(ports)
        self._done_ticks = 0
        self._start_mono = time.monotonic()
        self.progress.config(mode="determinate",
                             maximum=max(self._expected_ticks, 1), value=0)
        self.status_var.set(f"Running against {host} ...")
        self.phase_var.set("Phase: DNS")
        self.eta_var.set("")
        self._all_findings = []
        self._seen_keys.clear()
        self.output.config(state=NORMAL)
        self.output.delete("1.0", END)
        self.output.config(state=DISABLED)
        self.report = None
        engine = ScanEngine(
            host, ports, self.scope, self.queue, self.stop_event,
            rate_limit=self.rate_limit, workers=self.workers,
            enable_http=self.enable_http.get(),
            enable_tls=self.enable_tls.get(),
            enable_ciphers=self.enable_ciphers.get(),
            enable_web_discovery=self.enable_web_disc.get(),
            enable_subdomains=self.enable_subdomains.get(),
            enable_tls_versions=self.enable_tls_versions.get(),
            enable_path_probe=self.enable_path_probe.get(),
            enable_udp=self.enable_udp.get(),
            enable_service_detect=self.enable_service_detect.get(),
            enable_whois=self.enable_whois.get(),
            enable_ct=self.enable_ct.get(),
            enable_secret_scan=self.enable_secret_scan.get(),
            config=self.cfg,
        )
        self.worker_thread = threading.Thread(target=engine.run, daemon=True)
        self.worker_thread.start()

    def stop_check(self) -> None:
        if not (self.worker_thread and self.worker_thread.is_alive()):
            return
        self.stop_event.set()
        self.status_var.set("Stopping ...")

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "finding":
                    self._append_finding(payload)
                elif kind == "done":
                    self.report = payload
                    self._on_scan_done(payload)
                elif kind == "progress":
                    self._done_ticks += 1
                    if self._expected_ticks:
                        self.progress["value"] = min(
                            self._done_ticks, self._expected_ticks)
                    self._update_eta()
                elif kind == "phase":
                    self.phase_var.set(f"Phase: {payload}")
        except queue.Empty:
            pass
        try:
            self._after_id = self.root.after(80, self._drain_queue)
        except Exception:
            self._after_id = None

    def _update_eta(self) -> None:
        if not self._expected_ticks or not self._done_ticks:
            return
        elapsed = time.monotonic() - self._start_mono
        rate = self._done_ticks / max(elapsed, 0.01)
        remaining = (self._expected_ticks - self._done_ticks) / max(rate, 0.01)
        if remaining > 0:
            self.eta_var.set(f"ETA {remaining:.0f}s")

    def _on_scan_done(self, report: ScanReport) -> None:
        from tkinter import NORMAL, DISABLED
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.progress["value"] = self.progress["maximum"]
        self.phase_var.set("Phase: Done")
        self.eta_var.set("")
        counts: dict[str, int] = {}
        for f in report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        append_audit({
            "ts": now_iso(), "target": report.target,
            "started": report.started, "finished": report.finished,
            "duration_s": report.duration_s, "open_ports": report.open_ports,
            "counts": counts, "aborted": report.aborted,
            "risk_score": report.risk_score,
        })
        append_history({
            "ts": now_iso(), "target": report.target,
            "duration_s": report.duration_s,
            "open_ports": report.open_ports,
            "technologies": report.technologies,
            "waf": report.waf,
            "counts": counts, "risk_score": report.risk_score,
        })
        if report.aborted:
            self.status_var.set(
                f"Aborted: {report.aborted_reason} "
                f"({len(report.findings)} finding(s))")
        else:
            summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            self.status_var.set(
                f"Done in {report.duration_s:.2f}s | "
                f"Risk: {report.risk_score}/100 | "
                f"{len(report.findings)} finding(s). {summary}")

    def _severity_visible(self, sev: str) -> bool:
        return {
            "info": self.show_info.get(),
            "low": self.show_low.get(),
            "medium": self.show_med.get(),
            "high": self.show_high.get(),
            "critical": self.show_crit.get(),
        }.get(sev, True)

    def _matches_filter(self, f: Finding) -> bool:
        needle = self.filter_var.get().strip().lower()
        if needle and needle not in f.pretty().lower():
            return False
        cat = self.category_var.get()
        if cat != "All" and f.category.upper() != cat.upper():
            return False
        return True

    def _append_finding(self, f: Finding) -> None:
        k = f.key()
        if k in self._seen_keys:
            return
        self._seen_keys.add(k)
        self._all_findings.append(f)
        self._render_finding(f)

    def _render_finding(self, f: Finding) -> None:
        from tkinter import END, NORMAL, DISABLED
        if not self._severity_visible(f.severity):
            return
        if not self._matches_filter(f):
            return
        self.output.config(state=NORMAL)
        self.output.insert(END, f.pretty() + "\n", f.severity)
        self.output.see(END)
        self.output.config(state=DISABLED)

    def _reapply_filter(self) -> None:
        from tkinter import END, NORMAL, DISABLED
        self.output.config(state=NORMAL)
        self.output.delete("1.0", END)
        self.output.config(state=DISABLED)
        ordered = sorted(
            self._all_findings,
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.ts),
        )
        for f in ordered:
            self._render_finding(f)

    def clear_output(self) -> None:
        from tkinter import END, NORMAL, DISABLED
        self._all_findings = []
        self._seen_keys.clear()
        self.output.config(state=NORMAL)
        self.output.delete("1.0", END)
        self.output.config(state=DISABLED)
        self.status_var.set("Cleared.")

    def save(self, fmt: str) -> None:
        from tkinter import filedialog, messagebox
        if not self._all_findings:
            messagebox.showinfo("No results", "There are no results to save.")
            return
        ext = {"txt": ".txt", "json": ".json", "csv": ".csv",
               "html": ".html", "md": ".md",
               "sarif": ".sarif", "junit": ".xml"}[fmt]
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"),
                       ("All files", "*.*")],
            title="Save assessment results")
        if not path:
            return
        try:
            ordered = sorted(
                self._all_findings,
                key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.ts))
            if self.cfg.redact:
                ordered = [f.redacted() for f in ordered]
            if fmt == "txt":
                self._save_txt(path, ordered)
            elif fmt == "json":
                self._save_json(path, ordered)
            elif fmt == "csv":
                self._save_csv(path, ordered)
            elif fmt == "html":
                self._save_html(path, ordered)
            elif fmt == "md":
                self._save_md(path, ordered)
            elif fmt == "sarif":
                self._save_sarif(path, ordered)
            elif fmt == "junit":
                self._save_junit(path, ordered)
            messagebox.showinfo("Saved", f"Results saved to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Save failed", f"Could not save file:\n{exc}")

    def _save_txt(self, path: str, ordered: list[Finding]) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{APP_NAME} v{APP_VERSION}\n")
            fh.write(f"Generated: {now_iso()}\n")
            fh.write(f"Host: {platform.node()}  "
                     f"OS: {platform.system()} {platform.release()}\n")
            if self.report:
                fh.write(f"Target: {self.report.target}\n")
                fh.write(f"Resolved: {', '.join(self.report.resolved_ips)}\n")
                fh.write(f"Open TCP ports: "
                         f"{', '.join(map(str, self.report.open_ports))}\n")
                fh.write(f"Open UDP ports: "
                         f"{', '.join(map(str, self.report.open_udp_ports))}\n")
                fh.write(f"Risk score: {self.report.risk_score}/100\n")
                fh.write(f"Duration: {self.report.duration_s}s\n")
            fh.write("-" * 70 + "\n")
            for f in ordered:
                fh.write(f.pretty() + "\n")
                if f.cve:
                    fh.write(f"    {f.cve} (CVSS {f.cvss})\n")
                if f.mitre:
                    fh.write(f"    MITRE: {', '.join(f.mitre)}\n")
                if f.owasp:
                    fh.write(f"    OWASP: {', '.join(f.owasp)}\n")
                if f.evidence:
                    fh.write(f"    evidence: {f.evidence[:300]!r}\n")
                if f.refs:
                    fh.write(f"    refs: {', '.join(f.refs)}\n")

    def _save_json(self, path: str, ordered: list[Finding]) -> None:
        payload = {
            "app": APP_NAME, "version": APP_VERSION,
            "generated": now_iso(), "host": platform.node(),
            "report": self.report.to_dict() if self.report else None,
            "findings": [asdict(f) for f in ordered],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    def _save_csv(self, path: str, ordered: list[Finding]) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp", "target", "port", "service", "category",
                        "severity", "score", "cve", "cvss", "message",
                        "mitre", "owasp", "refs"])
            for f in ordered:
                w.writerow([f.ts, f.target, f.port, f.service, f.category,
                            f.severity, f.score, f.cve, f.cvss, f.message,
                            ";".join(f.mitre), ";".join(f.owasp),
                            ";".join(f.refs)])

    def _save_md(self, path: str, ordered: list[Finding]) -> None:
        lines = [f"# {APP_NAME} v{APP_VERSION}", "",
                 f"Generated: {now_iso()}"]
        if self.report:
            r = self.report
            lines += [
                "", "## Executive summary", "",
                f"- **Target:** {r.target}",
                f"- **Risk score:** {r.risk_score}/100",
                f"- **Resolved IPs:** {', '.join(r.resolved_ips)}",
                f"- **Reverse DNS:** {r.reverse_dns}",
                f"- **Open TCP ports:** {', '.join(map(str, r.open_ports))}",
                f"- **Open UDP ports:** {', '.join(map(str, r.open_udp_ports))}",
                f"- **Duration:** {r.duration_s}s",
                f"- **Technologies:** {', '.join(r.technologies) or '-'}",
                f"- **WAF/CDN:** {', '.join(r.waf) or '-'}",
            ]
            if r.whois:
                lines += ["", "### WHOIS"]
                for k, v in r.whois.items():
                    lines.append(f"- **{k}:** {v}")
            if r.subdomains:
                lines += ["", "### Subdomains"]
                for s in r.subdomains:
                    lines.append(f"- {s}")
            if r.ct_logs:
                lines += ["", "### Certificate transparency"]
                for s in r.ct_logs[:50]:
                    lines.append(f"- {s}")
            if r.tls_certs:
                lines += ["", "### TLS certificates"]
                for port, info in r.tls_certs.items():
                    lines.append(f"- **{port}:** "
                                 f"{info.get('subject_cn','')} "
                                 f"({info.get('issuer_cn','')}) "
                                 f"expires {info.get('not_after','')}")
            if r.phase_times:
                lines += ["", "### Phase timings"]
                for k, v in r.phase_times.items():
                    lines.append(f"- {k}: {v}s")
        counts: dict[str, int] = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines += ["", "## Severity summary", "",
                  "| Severity | Count |", "|---|---|"]
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {sev} | {counts.get(sev, 0)} |")
        lines += ["", "## Findings", ""]
        for f in ordered:
            loc = f":{f.port}" if f.port else ""
            lines.append(f"### [{f.severity.upper()}] {f.category}{loc}")
            lines.append(f"- **Time:** {f.ts}")
            lines.append(f"- **Message:** {f.message}")
            if f.service:
                lines.append(f"- **Service:** {f.service}")
            if f.cve:
                lines.append(f"- **CVE:** {f.cve} (CVSS {f.cvss})")
            if f.mitre:
                lines.append(f"- **MITRE ATT&CK:** {', '.join(f.mitre)}")
            if f.owasp:
                lines.append(f"- **OWASP:** {', '.join(f.owasp)}")
            if f.refs:
                lines.append(f"- **Refs:** {', '.join(f.refs)}")
            if f.remediation:
                lines.append(f"- **Remediation:** {f.remediation}")
            if f.evidence:
                lines.append("")
                lines.append("```")
                lines.append(f.evidence[:1000])
                lines.append("```")
            lines.append("")
        Path(path).write_text("\n".join(lines), encoding="utf-8")

    def _save_html(self, path: str, ordered: list[Finding]) -> None:
        counts: dict[str, int] = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        bar_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            n = counts.get(sev, 0)
            if not n:
                continue
            color = SEVERITY_COLORS.get(sev, "#888")
            bar_parts.append(
                f"<div style='flex:{n};background:{color};height:14px;' "
                f"title='{sev}: {n}'></div>")
        bar = ("<div style='display:flex;width:100%;border:1px solid #ccc;"
               "margin:8px 0;'>" + "".join(bar_parts) + "</div>")
        rows = []
        for f in ordered:
            refs_html = ""
            if f.refs:
                refs_html = "<br>".join(
                    f"<a href='{esc(r)}'>{esc(r)}</a>" for r in f.refs if r)
            evidence_html = ""
            if f.evidence:
                evidence_html = (
                    f"<details><summary>evidence</summary>"
                    f"<pre>{esc(f.evidence[:2000])}</pre></details>")
            tags = []
            if f.cve:
                tags.append(f"<span class='cve'>{esc(f.cve)}</span>")
            for m in f.mitre:
                tags.append(f"<span class='mitre'>{esc(m)}</span>")
            for o in f.owasp:
                tags.append(f"<span class='owasp'>{esc(o)}</span>")
            rows.append(
                f"<tr style='color:{SEVERITY_COLORS.get(f.severity,'#000')}'>"
                f"<td>{esc(f.ts)}</td>"
                f"<td>{esc(f.target)}</td>"
                f"<td>{f.port or ''}</td>"
                f"<td>{esc(f.service)}</td>"
                f"<td>{esc(f.category)}</td>"
                f"<td><b>{esc(f.severity.upper())}</b></td>"
                f"<td>{esc(f.message)} {''.join(tags)}{refs_html}"
                f"{evidence_html}</td>"
                f"</tr>")
        rpt = self.report
        meta = ""
        if rpt:
            meta = (
                f"<p>"
                f"<b>Target:</b> {esc(rpt.target)}<br>"
                f"<b>Risk score:</b> {rpt.risk_score}/100<br>"
                f"<b>Resolved IPs:</b> {esc(', '.join(rpt.resolved_ips))}<br>"
                f"<b>Reverse DNS:</b> {esc(rpt.reverse_dns)}<br>"
                f"<b>Open TCP:</b> {esc(', '.join(map(str, rpt.open_ports)))}<br>"
                f"<b>Open UDP:</b> {esc(', '.join(map(str, rpt.open_udp_ports)))}<br>"
                f"<b>Technologies:</b> {esc(', '.join(rpt.technologies))}<br>"
                f"<b>WAF/CDN:</b> {esc(', '.join(rpt.waf))}<br>"
                f"<b>Started:</b> {esc(rpt.started)}<br>"
                f"<b>Finished:</b> {esc(rpt.finished)}<br>"
                f"<b>Duration:</b> {rpt.duration_s}s"
                f"</p>")
        doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{esc(APP_NAME)} report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 24px;
        color: #222; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left;
          font-size: 13px; vertical-align: top; word-break: break-word; }}
th {{ background: #eee; position: sticky; top: 0; cursor: pointer; }}
pre {{ background: #f6f6f6; padding: 6px; overflow-x: auto;
       white-space: pre-wrap; }}
details {{ margin-top: 4px; }}
.cve {{ background:#fee; border:1px solid #c66; padding:1px 4px;
        border-radius:3px; font-size:11px; margin-left:4px; }}
.mitre {{ background:#eef; border:1px solid #66c; padding:1px 4px;
          border-radius:3px; font-size:11px; margin-left:4px; }}
.owasp {{ background:#efe; border:1px solid #6c6; padding:1px 4px;
          border-radius:3px; font-size:11px; margin-left:4px; }}
@media print {{ body {{ margin: 0; }} table {{ page-break-inside: auto; }}
tr {{ page-break-inside: avoid; }} }}
</style>
<script>
function sortTable(n) {{
  var table = document.querySelector("table");
  var rows = Array.from(table.tBodies[0].rows);
  var dir = table.getAttribute("data-sort-" + n) === "asc" ? "desc" : "asc";
  table.setAttribute("data-sort-" + n, dir);
  rows.sort(function(a, b) {{
    var x = a.cells[n].innerText.toLowerCase();
    var y = b.cells[n].innerText.toLowerCase();
    if (x < y) return dir === "asc" ? -1 : 1;
    if (x > y) return dir === "asc" ? 1 : -1;
    return 0;
  }});
  rows.forEach(function(r) {{ table.tBodies[0].appendChild(r); }});
}}
</script>
</head><body>
<h1>{esc(APP_NAME)} v{esc(APP_VERSION)}</h1>
<p>Generated: {esc(now_iso())}</p>
{meta}
{bar}
<table>
<thead><tr>
<th onclick="sortTable(0)">Timestamp</th>
<th onclick="sortTable(1)">Target</th>
<th onclick="sortTable(2)">Port</th>
<th onclick="sortTable(3)">Service</th>
<th onclick="sortTable(4)">Category</th>
<th onclick="sortTable(5)">Severity</th>
<th>Message</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody></table>
</body></html>"""
        Path(path).write_text(doc, encoding="utf-8")

    def _save_sarif(self, path: str, ordered: list[Finding]) -> None:
        rules: dict[str, dict] = {}
        results = []
        for f in ordered:
            rule_id = f"{f.category}-{hashlib.sha1(f.message.encode()).hexdigest()[:8]}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": f.message[:120]},
                    "fullDescription": {"text": f.message},
                    "helpUri": f.refs[0] if f.refs else "",
                    "properties": {
                        "severity": f.severity,
                        "cve": f.cve,
                        "cvss": f.cvss,
                        "mitre": f.mitre,
                        "owasp": f.owasp,
                    },
                }
            level = {"critical": "error", "high": "error",
                     "medium": "warning", "low": "note",
                     "info": "note"}.get(f.severity, "note")
            loc_uri = f"tcp://{f.target}:{f.port}" if f.port else f"host://{f.target}"
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc_uri}
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": hashlib.sha1(
                        (f.message + str(f.port)).encode()
                    ).hexdigest()[:16],
                },
                "properties": {
                    "port": f.port,
                    "service": f.service,
                    "evidence": f.evidence[:1000],
                },
            })
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": APP_NAME,
                        "version": APP_VERSION,
                        "informationUri": APP_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }
        Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    def _save_junit(self, path: str, ordered: list[Finding]) -> None:
        suite = ET.Element("testsuite", {
            "name": f"{APP_NAME}:{self.report.target if self.report else ''}",
            "tests": str(len(ordered)),
            "failures": str(sum(1 for f in ordered
                                if f.severity in ("high", "critical"))),
            "errors": "0",
            "time": f"{self.report.duration_s if self.report else 0}",
        })
        for f in ordered:
            tc = ET.SubElement(suite, "testcase", {
                "name": f"{f.category}:{f.port or 0}:{f.message[:80]}",
                "classname": f.category,
                "time": "0",
            })
            if f.severity in ("high", "critical"):
                fail = ET.SubElement(tc, "failure", {
                    "message": f.message,
                    "type": f.severity,
                })
                fail.text = (f"{f.message}\n\n"
                             f"Evidence:\n{f.evidence}\n\n"
                             f"Refs: {', '.join(f.refs)}")
            elif f.severity == "medium":
                ET.SubElement(tc, "system-out").text = f.message
        tree = ET.ElementTree(suite)
        try:
            ET.indent(tree, space="  ")
        except AttributeError:
            pass
        tree.write(path, encoding="utf-8", xml_declaration=True)

    def diff_json(self) -> None:
        from tkinter import filedialog, messagebox
        old_path = filedialog.askopenfilename(
            title="Select OLD JSON report",
            filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not old_path:
            return
        new_path = filedialog.askopenfilename(
            title="Select NEW JSON report",
            filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not new_path:
            return
        try:
            old = json.loads(Path(old_path).read_text(encoding="utf-8"))
            new = json.loads(Path(new_path).read_text(encoding="utf-8"))
        except Exception as e:
            messagebox.showerror("Diff failed", str(e))
            return
        lines = diff_reports(old, new)
        messagebox.showinfo("Report diff", "\n".join(lines)[:4000] or "No output")

    def _on_close(self) -> None:
        from tkinter import messagebox
        if self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("Quit",
                                       "A scan is running. Stop and quit?"):
                return
            self.stop_event.set()
            self.worker_thread.join(timeout=1.5)
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        self.cfg.scope = self.scope
        self.cfg.rate_limit = self.rate_limit
        self.cfg.workers = self.workers
        self.cfg.last_target = self._last_target
        self.cfg.save()
        self._save_profiles()
        try:
            self.root.destroy()
        except Exception:
            pass

def run_cli(args: argparse.Namespace) -> int:
    host = args.target
    ok, err = validate_target(host)
    if not ok:
        print(f"error: invalid target: {err}", file=sys.stderr)
        return 2
    cfg = Config.load()
    if args.rate is not None:
        cfg.rate_limit = args.rate
    if args.workers is not None:
        cfg.workers = args.workers
    if args.connect_timeout is not None:
        cfg.connect_timeout = args.connect_timeout
    if args.banner_timeout is not None:
        cfg.banner_timeout = args.banner_timeout
    if args.http_timeout is not None:
        cfg.http_timeout = args.http_timeout
    if args.tls_timeout is not None:
        cfg.tls_timeout = args.tls_timeout
    if args.udp_timeout is not None:
        cfg.udp_timeout = args.udp_timeout
    if args.user_agent:
        cfg.user_agent = args.user_agent
    if args.header:
        for h in args.header:
            if ":" in h:
                k, _, v = h.partition(":")
                cfg.custom_headers[k.strip()] = v.strip()
    if args.proxy:
        cfg.proxy = args.proxy
    if args.redact:
        cfg.redact = True
    if args.log_file:
        cfg.log_file = args.log_file
    scope = cfg.scope
    for net in (args.allow_network or []):
        ok, err = scope.add_network(net)
        if not ok:
            print(f"error: {err}", file=sys.stderr)
            return 2
    for h in (args.allow_host or []):
        if not scope.add_host(h):
            print(f"error: invalid host '{h}'", file=sys.stderr)
            return 2
    template = TEMPLATES.get(args.template or "standard", TEMPLATES["standard"])
    if args.ports:
        if args.ports in PORT_PROFILES:
            ports = list(PORT_PROFILES[args.ports])
        else:
            ok, ports = parse_custom_ports(args.ports)
            if not ok:
                print(f"error: {ports}", file=sys.stderr)
                return 2
    else:
        ports = list(PORT_PROFILES.get(template["profile"],
                                       PORT_PROFILES["Top 20 (safe default)"]))
    if args.exclude_ports:
        ok, excluded = parse_custom_ports(args.exclude_ports)
        if ok:
            ports = [p for p in ports if p not in set(excluded)]
    snap_hosts, snap_nets = scope.snapshot()
    ips = resolve_host(host, prefer_ipv6=args.ipv6)
    if not ips:
        print(f"error: could not resolve '{host}'", file=sys.stderr)
        return 3
    out_of_scope = _ip_scope_check(ips, snap_hosts, snap_nets)
    if out_of_scope:
        print(f"error: target '{host}' resolves to out-of-scope IP(s): "
              f"{', '.join(out_of_scope)}", file=sys.stderr)
        return 4
    q: "queue.Queue[tuple]" = queue.Queue()
    stop = threading.Event()

    def _sig_handler(signum, frame):
        stop.set()
        print("\n# stopping...", file=sys.stderr)
    try:
        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)
    except (ValueError, OSError):
        pass
    engine = ScanEngine(
        host, ports, scope, q, stop,
        rate_limit=cfg.rate_limit, workers=cfg.workers,
        enable_http=not args.no_http and template["http"],
        enable_tls=not args.no_tls and template["tls"],
        enable_ciphers=args.weak_ciphers or template["ciphers"],
        enable_web_discovery=not args.no_web_discovery and template["web"],
        enable_subdomains=not args.no_subdomains and template["subdomains"],
        enable_tls_versions=not args.no_tls_versions and template["tls_versions"],
        enable_path_probe=not args.no_path_probe and template["paths"],
        enable_udp=not args.no_udp and template["udp"],
        enable_service_detect=not args.no_service_detect and template["service_detect"],
        enable_whois=not args.no_whois,
        enable_ct=not args.no_ct,
        enable_secret_scan=not args.no_secret_scan,
        config=cfg,
    )
    t = threading.Thread(target=engine.run, daemon=True)
    t.start()
    findings: list[Finding] = []
    report: Optional[ScanReport] = None
    printed_header = False
    threshold = SEVERITY_ORDER.get((args.severity_threshold or "info").lower(), 0)
    while True:
        try:
            kind, payload = q.get(timeout=0.2)
        except queue.Empty:
            if not t.is_alive() and report is not None:
                break
            continue
        if kind == "finding":
            findings.append(payload)
            if not args.quiet:
                if SEVERITY_ORDER.get(payload.severity, 0) >= threshold:
                    if not printed_header:
                        print(f"# {APP_NAME} v{APP_VERSION} -> {host}")
                        printed_header = True
                    print(payload.pretty(), flush=True)
        elif kind == "done":
            report = payload
            break
    t.join(timeout=1.0)
    if report is None:
        report = engine.report
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if not args.no_audit:
        append_audit({
            "ts": now_iso(), "target": host,
            "started": report.started, "finished": report.finished,
            "duration_s": report.duration_s, "open_ports": report.open_ports,
            "counts": counts, "aborted": report.aborted, "cli": True,
            "risk_score": report.risk_score,
        })
    if cfg.log_file:
        append_log(Path(cfg.log_file), {
            "ts": now_iso(), "target": host,
            "counts": counts, "risk_score": report.risk_score,
        })

    ordered = sorted(findings,
                     key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.ts))
    if cfg.redact:
        ordered_saved = [f.redacted() for f in ordered]
    else:
        ordered_saved = ordered
    if args.json_out:
        payload = {
            "app": APP_NAME, "version": APP_VERSION,
            "generated": now_iso(), "host": platform.node(),
            "report": report.to_dict(),
            "findings": [asdict(f) for f in ordered_saved],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2,
                                                  default=str),
                                       encoding="utf-8")
        if not args.quiet:
            print(f"# JSON written to {args.json_out}")
    if args.csv_out:
        with open(args.csv_out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp", "target", "port", "service", "category",
                        "severity", "score", "cve", "cvss", "message",
                        "mitre", "owasp", "refs"])
            for f in ordered_saved:
                w.writerow([f.ts, f.target, f.port, f.service, f.category,
                            f.severity, f.score, f.cve, f.cvss, f.message,
                            ";".join(f.mitre), ";".join(f.owasp),
                            ";".join(f.refs)])
        if not args.quiet:
            print(f"# CSV written to {args.csv_out}")
    if args.sarif_out:
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": APP_NAME, "version": APP_VERSION,
                        "informationUri": APP_URL,
                        "rules": [{"id": f"{f.category}-{i}",
                                   "name": f.category,
                                   "shortDescription": {"text": f.message}}
                                  for i, f in enumerate(ordered_saved)],
                    }
                },
                "results": [{
                    "ruleId": f"{f.category}-{i}",
                    "level": {"critical": "error", "high": "error",
                              "medium": "warning", "low": "note",
                              "info": "note"}.get(f.severity, "note"),
                    "message": {"text": f.message},
                } for i, f in enumerate(ordered_saved)],
            }],
        }
        Path(args.sarif_out).write_text(json.dumps(sarif, indent=2),
                                        encoding="utf-8")
        if not args.quiet:
            print(f"# SARIF written to {args.sarif_out}")
    if args.junit_out:
        suite = ET.Element("testsuite", {
            "name": f"{APP_NAME}:{host}",
            "tests": str(len(ordered_saved)),
            "failures": str(sum(1 for f in ordered_saved
                                if f.severity in ("high", "critical"))),
            "errors": "0",
            "time": f"{report.duration_s}",
        })
        for f in ordered_saved:
            tc = ET.SubElement(suite, "testcase", {
                "name": f"{f.category}:{f.port or 0}:{f.message[:80]}",
                "classname": f.category, "time": "0",
            })
            if f.severity in ("high", "critical"):
                el = ET.SubElement(tc, "failure", {
                    "message": f.message, "type": f.severity})
                el.text = f.evidence
        tree = ET.ElementTree(suite)
        try:
            ET.indent(tree, space="  ")
        except AttributeError:
            pass
        tree.write(args.junit_out, encoding="utf-8", xml_declaration=True)
        if not args.quiet:
            print(f"# JUnit written to {args.junit_out}")
    if args.md_out:
        lines = [f"# {APP_NAME} v{APP_VERSION}", "",
                 f"Generated: {now_iso()}", "",
                 f"- **Target:** {report.target}",
                 f"- **Risk score:** {report.risk_score}/100",
                 f"- **Open TCP ports:** {', '.join(map(str, report.open_ports))}",
                 f"- **Open UDP ports:** {', '.join(map(str, report.open_udp_ports))}",
                 "", "## Findings", ""]
        for f in ordered_saved:
            lines.append(f"- [{f.severity.upper()}] {f.category}"
                         f"{':'+str(f.port) if f.port else ''} {f.message}")
        Path(args.md_out).write_text("\n".join(lines), encoding="utf-8")
        if not args.quiet:
            print(f"# Markdown written to {args.md_out}")
    if args.webhook:
        try:
            payload = json.dumps({
                "target": report.target,
                "risk_score": report.risk_score,
                "counts": counts,
                "open_ports": report.open_ports,
                "aborted": report.aborted,
            }).encode("utf-8")
            req = urllib.request.Request(
                args.webhook, data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": USER_AGENT})
            urllib.request.urlopen(req, timeout=10)
            if not args.quiet:
                print(f"# Webhook delivered to {args.webhook}")
        except Exception as e:
            print(f"# Webhook failed: {e}", file=sys.stderr)
    if report.aborted:
        return 5
    fail_on = (args.fail_on or "high").lower()
    fail_threshold = SEVERITY_ORDER.get(fail_on, 3)
    if any(SEVERITY_ORDER.get(f.severity, 0) >= fail_threshold
           for f in findings):
        return 6
    return 0
  
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safeassess",
        description=f"{APP_NAME} v{APP_VERSION} — authorized-use-only "
                    f"network/HTTP/TLS/service assessment.",
    )
    p.add_argument("--target", "-t", help="Hostname or IP to scan.")
    p.add_argument("--target-file",
                   help="File with one target per line; scans sequentially.")
    p.add_argument("--ports", "-p",
                   help="Port profile name or custom list "
                        "(e.g. '80,443,8000-8010').")
    p.add_argument("--exclude-ports",
                   help="Ports to exclude from the scan (custom list).")
    p.add_argument("--template", choices=list(TEMPLATES.keys()),
                   help="Scan template (quick, standard, deep, web, compliance).")
    p.add_argument("--allow-host", action="append", default=[],
                   help="Add a host to the authorized scope (repeatable).")
    p.add_argument("--allow-network", action="append", default=[],
                   help="Add a CIDR to the authorized scope (repeatable).")
    p.add_argument("--rate", type=float, default=None,
                   help=f"Probes per second (default {DEFAULT_RATE}).")
    p.add_argument("--workers", type=int, default=None,
                   help=f"Worker threads (default {MAX_WORKERS}).")
    p.add_argument("--connect-timeout", type=float, default=None)
    p.add_argument("--banner-timeout", type=float, default=None)
    p.add_argument("--http-timeout", type=float, default=None)
    p.add_argument("--tls-timeout", type=float, default=None)
    p.add_argument("--udp-timeout", type=float, default=None)
    p.add_argument("--user-agent", default=None)
    p.add_argument("--header", action="append", default=[],
                   help="Add a custom HTTP header 'Name: value' (repeatable).")
    p.add_argument("--proxy", default=None,
                   help="HTTP proxy URL for HTTP probing (best-effort).")
    p.add_argument("--json-out", help="Write JSON results to this path.")
    p.add_argument("--csv-out", help="Write CSV results to this path.")
    p.add_argument("--sarif-out", help="Write SARIF 2.1.0 to this path.")
    p.add_argument("--junit-out", help="Write JUnit XML to this path.")
    p.add_argument("--md-out", help="Write Markdown report to this path.")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP probing.")
    p.add_argument("--no-tls", action="store_true", help="Skip TLS probing.")
    p.add_argument("--no-web-discovery", action="store_true",
                   help="Skip robots.txt/sitemap.xml discovery.")
    p.add_argument("--no-subdomains", action="store_true",
                   help="Skip subdomain enumeration.")
    p.add_argument("--no-tls-versions", action="store_true",
                   help="Skip TLS protocol version matrix.")
    p.add_argument("--no-path-probe", action="store_true",
                   help="Skip curated path probing.")
    p.add_argument("--no-udp", action="store_true", help="Skip UDP probing.")
    p.add_argument("--no-service-detect", action="store_true",
                   help="Skip service detection.")
    p.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookup.")
    p.add_argument("--no-ct", action="store_true",
                   help="Skip certificate transparency lookup.")
    p.add_argument("--no-secret-scan", action="store_true",
                   help="Skip secret scanning in HTTP bodies.")
    p.add_argument("--no-audit", action="store_true",
                   help="Do not write to the audit log.")
    p.add_argument("--weak-ciphers", action="store_true",
                   help="Enable weak-cipher enumeration (slow).")
    p.add_argument("--ipv6", action="store_true",
                   help="Prefer IPv6 addresses.")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress per-finding output (still writes files).")
    p.add_argument("--severity-threshold", default="info",
                   choices=["info", "low", "medium", "high", "critical"],
                   help="Only print findings at or above this severity.")
    p.add_argument("--fail-on", default="high",
                   choices=["info", "low", "medium", "high", "critical"],
                   help="Return non-zero if any finding is at or above this "
                        "severity (default: high).")
    p.add_argument("--redact", action="store_true",
                   help="Redact IPs/hostnames in saved reports.")
    p.add_argument("--log-file", default=None,
                   help="Append JSONL log entries to this file.")
    p.add_argument("--webhook", default=None,
                   help="POST scan summary JSON to this URL on completion.")
    p.add_argument("--schedule", default=None,
                   help="Repeat scan on an interval in seconds (e.g. '300').")
    p.add_argument("--resume", action="store_true",
                   help="Resume a previously interrupted scan.")
    p.add_argument("--list-profiles", action="store_true",
                   help="List built-in port profiles and exit.")
    p.add_argument("--list-templates", action="store_true",
                   help="List scan templates and exit.")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                   help="Diff two JSON reports and exit.")
    p.add_argument("--version", action="store_true",
                   help="Print version and exit.")
    return p

def _run_one(args: argparse.Namespace) -> int:
    return run_cli(args)

def main(argv: Optional[list[str]] = None) -> int:
    if sys.version_info < REQUIRES_PY:
        sys.stderr.write(
            f"This tool requires Python {REQUIRES_PY[0]}.{REQUIRES_PY[1]} or newer.\n")
        return 1
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    if args.list_profiles:
        for name, ports in PORT_PROFILES.items():
            if name == "Custom":
                continue
            print(f"{name}: {', '.join(map(str, ports))}")
        return 0
    if args.list_templates:
        for name, t in TEMPLATES.items():
            print(f"{name}: profile={t['profile']}")
        return 0
    if args.diff:
        try:
            old = json.loads(Path(args.diff[0]).read_text(encoding="utf-8"))
            new = json.loads(Path(args.diff[1]).read_text(encoding="utf-8"))
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        for line in diff_reports(old, new):
            print(line)
        return 0
    if args.target_file:
        lines = [l.strip() for l in Path(args.target_file).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        worst = 0
        for line in lines:
            ns = argparse.Namespace(**vars(args))
            ns.target = line
            ns.target_file = None
            rc = _run_one(ns)
            worst = max(worst, rc)
        return worst
    if args.target:
        if args.schedule:
            try:
                interval = float(args.schedule)
            except ValueError:
                print("error: --schedule must be a number of seconds",
                      file=sys.stderr)
                return 2
            print(f"# scheduled scan every {interval}s (Ctrl-C to stop)")
            try:
                while True:
                    _run_one(args)
                    time.sleep(interval)
            except KeyboardInterrupt:
                print("# scheduler stopped")
                return 0
        return _run_one(args)
    try:
        from tkinter import Tk
    except ImportError as exc:
        sys.stderr.write(f"error: tkinter not available ({exc}). "
                         f"Use --target for CLI mode.\n")
        return 1
    root = Tk()
    App(root, Config.load())
    root.mainloop()
    return 0

if __name__ == "__main__":
    sys.exit(main())
