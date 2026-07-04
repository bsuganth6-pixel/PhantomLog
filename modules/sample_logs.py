"""
PhantomLog — Sample Log Generator
═══════════════════════════════════════════════════════════════
Generates realistic synthetic log files with deliberately injected
attack patterns at KNOWN counts. Dual purpose:

  1. Lets a user try PhantomLog immediately without needing their
     own log files ("Load Sample Attack Log" button).
  2. Lets the test suite verify detection RECALL precisely — since
     we know exactly how many brute-force attempts, SQLi probes,
     etc. were injected, we can assert the detector finds exactly
     that many, with zero false positives on the normal traffic
     mixed in alongside them.

Fully offline, deterministic given a fixed random seed.
"""

import random
import datetime

NORMAL_IPS = ["198.51.100.{}".format(i) for i in range(10, 40)]
NORMAL_PATHS = ["/", "/index.html", "/about", "/products", "/contact",
                "/blog/post-1", "/images/logo.png", "/css/style.css",
                "/api/status", "/favicon.ico", "/products/item-42"]
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
NORMAL_USERS = ["alice", "bob", "carol", "dave", "deploy"]

ATTACKER_IP_BRUTEFORCE = "203.0.113.66"
ATTACKER_IP_SQLI = "203.0.113.77"
ATTACKER_IP_XSS = "203.0.113.88"
ATTACKER_IP_TRAVERSAL = "203.0.113.99"
ATTACKER_IP_ENUM = "203.0.113.111"
ATTACKER_IP_SCANNER = "203.0.113.122"
ATTACKER_IP_WEBBRUTE = "203.0.113.133"
ATTACKER_IP_COMPROMISED = "203.0.113.144"  # brute force that SUCCEEDS at the end


def _fmt_apache_time(dt: datetime.datetime) -> str:
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    return f"{dt.day:02d}/{months[dt.month-1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def _fmt_syslog_time(dt: datetime.datetime) -> str:
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    return f"{months[dt.month-1]} {dt.day:2d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"


def generate_sample_access_log(seed: int = 42) -> dict:
    """
    Returns {"text": str, "injected": {...known counts...}}
    Injected attack counts are returned so tests can assert exact recall.
    """
    rng = random.Random(seed)
    start = datetime.datetime(2026, 7, 1, 8, 0, 0, tzinfo=datetime.timezone.utc)
    lines = []
    t = start

    def emit(ip, method, path, status, size, ua, referer="-"):
        nonlocal t
        line = (f'{ip} - - [{_fmt_apache_time(t)}] "{method} {path} HTTP/1.1" '
                f'{status} {size} "{referer}" "{ua}"')
        lines.append(line)
        t += datetime.timedelta(seconds=rng.randint(1, 8))

    # ── Normal traffic: 80 legitimate requests interspersed ──
    for _ in range(80):
        emit(rng.choice(NORMAL_IPS), "GET", rng.choice(NORMAL_PATHS), 200,
             rng.randint(300, 15000), rng.choice(NORMAL_USER_AGENTS))

    # ── SQLi probe burst: 6 distinct SQL injection payloads ──
    sqli_payloads = [
        "/products?id=1' OR '1'='1",
        "/search?q=test' UNION SELECT username,password FROM users--",
        "/item?id=1; DROP TABLE users;--",
        "/login?user=admin'--",
        "/product?id=1 UNION SELECT NULL,NULL,NULL--",
        "/api/item?id=1' AND 1=1 AND 'a'='a",
    ]
    for payload in sqli_payloads:
        path, _, query = payload.partition("?")
        emit(ATTACKER_IP_SQLI, "GET", payload, 200, 512, "sqlmap/1.7.2#stable (http://sqlmap.org)")
    sqli_count = len(sqli_payloads)

    # ── XSS probe burst: 5 distinct XSS payloads ──
    xss_payloads = [
        "/search?q=<script>alert(1)</script>",
        "/comment?text=<img src=x onerror=alert(document.cookie)>",
        "/profile?name=javascript:alert('xss')",
        "/search?q=<svg onload=alert(1)>",
        "/page?ref=%22%3E%3Cscript%3Edocument.location=%27http://evil.com%27%3C/script%3E",
    ]
    for payload in xss_payloads:
        emit(ATTACKER_IP_XSS, "GET", payload, 200, 400, NORMAL_USER_AGENTS[0])
    xss_count = len(xss_payloads)

    # ── Path traversal burst: 4 distinct traversal payloads ──
    traversal_payloads = [
        "/download?file=../../../../etc/passwd",
        "/image?path=..%2f..%2f..%2fetc%2fshadow",
        "/view?doc=....//....//boot.ini",
        "/get?f=../../../../../windows/win.ini",
    ]
    for payload in traversal_payloads:
        emit(ATTACKER_IP_TRAVERSAL, "GET", payload, 404, 200, "curl/8.4.0")
    traversal_count = len(traversal_payloads)

    # ── Directory enumeration burst: 20 different 404s from one IP fast ──
    enum_paths = [f"/{rng.choice(['admin','backup','old','test','tmp','wp-content','uploads','private'])}"
                 f"{rng.choice(['','2','_bak','.old','_v2'])}/{rng.choice(['config','db','index','data'])}.php"
                 for _ in range(20)]
    for path in enum_paths:
        emit(ATTACKER_IP_ENUM, "GET", path, 404, 150, "Gobuster/3.6")
    enum_count = len(enum_paths)

    # ── Known scanner user-agent + sensitive-path probes: 5 requests ──
    scanner_paths = ["/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/", "/xmlrpc.php"]
    for path in scanner_paths:
        emit(ATTACKER_IP_SCANNER, "GET", path, 404, 180, "Nikto/2.5.0")
    scanner_count = len(scanner_paths)

    # ── Web login brute force: 12 failed POST /login (401) ──
    webbrute_count = 12
    for _ in range(webbrute_count):
        emit(ATTACKER_IP_WEBBRUTE, "POST", "/login", 401, 90, "python-requests/2.31.0")

    # ── More normal traffic mixed in after attacks ──
    for _ in range(40):
        emit(rng.choice(NORMAL_IPS), "GET", rng.choice(NORMAL_PATHS), 200,
             rng.randint(300, 15000), rng.choice(NORMAL_USER_AGENTS))

    return {
        "text": "\n".join(lines) + "\n",
        "injected": {
            "sqli_attempts": sqli_count,
            "xss_attempts": xss_count,
            "traversal_attempts": traversal_count,
            "enumeration_requests": enum_count,
            "scanner_requests": scanner_count,
            "web_bruteforce_attempts": webbrute_count,
            "attacker_ips": {
                "sqli": ATTACKER_IP_SQLI, "xss": ATTACKER_IP_XSS,
                "traversal": ATTACKER_IP_TRAVERSAL, "enum": ATTACKER_IP_ENUM,
                "scanner": ATTACKER_IP_SCANNER, "webbrute": ATTACKER_IP_WEBBRUTE,
            },
            "total_lines": len(lines),
        },
    }


def generate_sample_auth_log(seed: int = 43) -> dict:
    """SSH auth.log with a brute-force attack, including one that SUCCEEDS at the end."""
    rng = random.Random(seed)
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    lines = []
    t = start
    pid_counter = [10000]

    def emit(ip, message):
        nonlocal t
        pid_counter[0] += 1
        line = f"{_fmt_syslog_time(t)} webserver01 sshd[{pid_counter[0]}]: {message}"
        lines.append(line)
        t += datetime.timedelta(seconds=rng.randint(1, 6))

    # ── Normal legitimate logins scattered throughout: 15 ──
    for _ in range(15):
        emit(rng.choice(NORMAL_IPS), f"Accepted password for {rng.choice(NORMAL_USERS)} "
                                    f"from {rng.choice(NORMAL_IPS)} port {rng.randint(30000,60000)} ssh2")

    # ── Brute force attack #1: 18 failed passwords, never succeeds (blocked/gave up) ──
    bruteforce_1_count = 18
    usernames_tried = ["root", "admin", "test", "user", "oracle", "postgres", "ftpuser", "guest"]
    for _ in range(bruteforce_1_count):
        user = rng.choice(usernames_tried)
        invalid = "invalid user " if user not in ("root",) else ""
        emit(ATTACKER_IP_BRUTEFORCE,
             f"Failed password for {invalid}{user} from {ATTACKER_IP_BRUTEFORCE} port {rng.randint(30000,60000)} ssh2")

    # ── Brute force attack #2: 22 failed passwords, THEN a successful login — compromise! ──
    bruteforce_2_fail_count = 22
    for _ in range(bruteforce_2_fail_count):
        user = rng.choice(usernames_tried + ["admin"])
        emit(ATTACKER_IP_COMPROMISED,
             f"Failed password for {user} from {ATTACKER_IP_COMPROMISED} port {rng.randint(30000,60000)} ssh2")
    # the successful breach:
    emit(ATTACKER_IP_COMPROMISED, f"Accepted password for admin from {ATTACKER_IP_COMPROMISED} port {rng.randint(30000,60000)} ssh2")

    # ── More normal traffic ──
    for _ in range(10):
        emit(rng.choice(NORMAL_IPS), f"Accepted password for {rng.choice(NORMAL_USERS)} "
                                    f"from {rng.choice(NORMAL_IPS)} port {rng.randint(30000,60000)} ssh2")

    return {
        "text": "\n".join(lines) + "\n",
        "injected": {
            "bruteforce_ip_no_success": ATTACKER_IP_BRUTEFORCE,
            "bruteforce_ip_no_success_failures": bruteforce_1_count,
            "bruteforce_ip_compromised": ATTACKER_IP_COMPROMISED,
            "bruteforce_ip_compromised_failures": bruteforce_2_fail_count,
            "total_lines": len(lines),
        },
    }
