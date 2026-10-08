<p align="center"> <em>a single-file, scope-locked security assessment tool for HTTP, TLS, DNS, services and curated web paths — my cybersecurity exam project</em> </p><p align="center"> <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blueviolet?style=for-the-badge&logo=python"> <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge"> <img alt="Authorized" src="https://img.shields.io/badge/authorized%20use%20only-%E2%9A%A0%20scope--locked-red?style=for-the-badge"> <img alt="Status" src="https://img.shields.io/badge/exam%20project-%E2%9C%94%20submitted-success?style=for-the-badge"> </p>

# hi
#### this is my cybersecurity exam project and it's called SafeAssess
#### it's a single-file Python tool that does non-destructive network, HTTP, TLS and service assessment — but with something i'm actually really proud of: a scope lock that refuses to touch anything you haven't explicitly authorized. no scanning random IPs, no accidental nmap -A on the neighbour's router, no lawsuits.
#### my professor kept saying "if a tool makes it easy to do something illegal, that's a design flaw." so i built SafeAssess to make it hard to do the wrong thing and easy to do the right thing.
#### read this first: SafeAssess is for authorized security testing only. only scan systems you own or have explicit written permission to test. the tool enforces this — out-of-scope targets get refused, and any resolved IP outside your allowlist aborts the scan.

# what it actually does
## scope-locked by default
- default allowlist = 127.0.0.1, localhost, ::1 only
- add hosts and CIDRs in the Scope Manager (GUI) or --allow-host / --allow-network (CLI)
- every scan resolves the target and refuses if any resolved IP falls outside the allowlist
- re-checked mid-scan — CDN flips during the run are caught
- subdomains enumerated but their out-of-scope IPs are marked, not scanned
## discovery & enumeration
- TCP port scan with configurable profiles (Top 20/Top 100/Web/Mail/Databases/Windows-AD/Containers/MQ/Custom)
- Banner grabbing on 25+ service ports, with service-specific requests (Redis PING, Memcached version, MongoDB isMaster)
- UDP probe with real service payloads (DNS, NTP, SNMP, SSDP, mDNS)
- Service identification from banners
- Subdomain enumeration from a ~180-word list + numeric/suffix variants
- DNS records (A/AAAA, plus reverse DNS)
- WHOIS for common TLDs
- Certificate Transparency log lookup via crt.sh
## HTTP & TLS auditing
- Full HTTP probe with redirect chain, headers, body, TTFB, and per-method checks (HEAD, OPTIONS, PUT, DELETE, TRACE)
- HTTP security header audit — HSTS (with max-age parsing), CSP (unsafe-inline/eval, wildcards, missing object-src/base-uri/frame-ancestors, nonce/hash detection), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP
- Cookie audit — Secure/HttpOnly/SameSite, __Host- and __Secure- prefix rules, SameSite=None-without-Secure, duplicate names
- CORS misconfigurations — null origin, wildcard + credentials, reflected origins
- Information-leak headers — Server, X-Powered-By, X-AspNet-*, X-Debug-Token, X-Backend-Server, X-Forwarded-For, etc.
- Dangerous methods — PUT/DELETE/TRACE returning 200/204, plus Allow-header analysis
- HTTP/3 advertisement via Alt-Svc
- Host-header reflection — X-Forwarded-Host presence
- TLS deep inspection — protocol, cipher, verification, self-signed detection, CN/SAN matching (with wildcard support), expiry days, chain length
- Public key info — RSA / EC / DSA key type and size, weak-key detection, signature algorithm
- Weak cipher enumeration — RC4, 3DES, DES, NULL, EXPORT, aNULL, ADH, AECDH, MD5
- TLS version matrix — tests whether TLS 1.0 / 1.1 / 1.2 / 1.3 are each supported
## vulnerability detection
- CVE banner matching — Heartbleed-era OpenSSL, vsftpd 2.3.4 backdoor, ProFTPD 1.3.x RCEs, Apache 2.4.49/2.4.50 path traversal, Exim 4.80–4.94 RCEs, SambaCry, IIS 6.0, EOL PHP/MySQL/Tomcat/Jetty/lighttpd, and more
- Curated path probing — .git/HEAD, .env, .htaccess, actuator/*, swagger.json, graphql, phpinfo.php, robots.txt, sitemap.xml, security.txt, backup.zip, .DS_Store and ~50 more — with baseline 404 comparison to reduce false positives
- Secret scanning in HTTP bodies — API keys, AWS creds, GitHub tokens, Stripe keys, Slack tokens, Google API keys, JWTs, DB connection strings, private key blocks
- Technology fingerprinting — WordPress, Drupal, Joomla, Django, Laravel, Rails, Express, Next.js, React, Vue, Angular, jQuery, Bootstrap, Cloudflare, Akamai, Fastly, S3, nginx, Apache, IIS, GraphQL, Swagger, OpenAPI
- WAF/CDN detection — Cloudflare, Akamai, AWS, F5, Imperva, Sucuri and more via headers
- JS endpoint extraction from response bodies
- Favicon hashing (mmh3 if available, else SHA-256) for tech-stack pivoting
## reporting
- TXT, JSON, CSV, Markdown, HTML, SARIF 2.1.0, JUnit XML
- HTML report with severity bar, click-to-sort table, <details> evidence, CVE/MITRE/OWASP badges, print-friendly CSS
- SARIF with rules, fingerprints and level mapping (integrates with GitHub code scanning)
- JUnit XML for CI systems (Jenkins, GitLab CI, CircleCI)
- Diff two JSON reports — new/closed ports, new/gone findings, new/gone technologies and WAFs
## framework mappings
#### every finding is tagged with:
- MITRE ATT&CK technique IDs (T1046 discovery, T1595 active scanning, T1190 exploit public-facing app, T1552 credentials, etc.)
- OWASP Top 10 2021 category codes where applicable (A01, A02, A03, A05)
## CLI + GUI
- Tkinter GUI with target/template/rate/workers top bar, per-module toggles, severity filters, category filter, live search, progress bar with ETA, phase display, keyboard shortcuts
- Full headless CLI with templates, custom ports, per-module toggles, timeouts, custom headers, proxy, redaction, log file, webhook, scheduler, --fail-on exit codes
# installation
#### you'll need Python 3.9+.
#### optional but recommended:
```
pip install mmh3 cryptography
```
- mmh3 → Shodan-compatible favicon hashes
- cryptography → full X.509 key type and signature algorithm parsing (RSA/EC/DSA sizes)
## run it
```
# GUI (default when no --target given)
python main.py

# quick CLI sanity scan against localhost
python main.py --target 127.0.0.1 --template quick

# full CLI help
python main.py --help
```
