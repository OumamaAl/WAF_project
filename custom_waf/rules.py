import re

RULES = [
    # ── SQLi ──────────────────────────────────────────────────────────────
    {"id": "SQLi-01", "category": "SQLi",
     "pattern": re.compile(r"(\bUNION\b.{0,20}\bSELECT\b|\bSELECT\b.{0,30}\bFROM\b)", re.I),
     "desc": "UNION SELECT / SELECT FROM"},

    {"id": "SQLi-02", "category": "SQLi",
     "pattern": re.compile(r"'\s*OR\s*'?\d+'?\s*=\s*'?\d+|--[\s#]|;\s*--", re.I),
     "desc": "OR 1=1 / commentaires SQL"},

    {"id": "SQLi-03", "category": "SQLi",
     "pattern": re.compile(r"\b(DROP|INSERT|DELETE|UPDATE|TRUNCATE)\b\s+\b(TABLE|INTO|FROM)\b", re.I),
     "desc": "DDL/DML injection"},

    {"id": "SQLi-04", "category": "SQLi",
     "pattern": re.compile(r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|pg_sleep)", re.I),
     "desc": "Time-based blind SQLi"},

    {"id": "SQLi-05", "category": "SQLi",
     "pattern": re.compile(r"(INFORMATION_SCHEMA|sysobjects|xp_cmdshell|load_file\s*\()", re.I),
     "desc": "SQLi enumeration / fonctions systeme"},

    {"id": "SQLi-06", "category": "SQLi",
     "pattern": re.compile(r"(CHAR\s*\(|CONCAT\s*\(|GROUP_CONCAT|HEX\s*\(|ASCII\s*\()", re.I),
     "desc": "SQLi fonctions d'encodage/obfuscation"},

    # ── XSS ───────────────────────────────────────────────────────────────
    {"id": "XSS-01", "category": "XSS",
     "pattern": re.compile(r"<\s*script[\s>/]", re.I),
     "desc": "XSS balise script"},

    {"id": "XSS-02", "category": "XSS",
     "pattern": re.compile(r"on(load|click|mouseover|error|focus|keyup|submit|input|change)\s*=", re.I),
     "desc": "XSS event handler"},

    {"id": "XSS-03", "category": "XSS",
     "pattern": re.compile(r"javascript\s*:", re.I),
     "desc": "XSS javascript: URI"},

    {"id": "XSS-04", "category": "XSS",
     "pattern": re.compile(r"<\s*(iframe|object|embed|svg|img)[^>]{0,50}src\s*=", re.I),
     "desc": "XSS via balise media"},

    {"id": "XSS-05", "category": "XSS",
     "pattern": re.compile(r"(alert|confirm|prompt)\s*\(", re.I),
     "desc": "XSS appel JS alert/confirm/prompt"},

    {"id": "XSS-06", "category": "XSS",
     "pattern": re.compile(r"(document\.(cookie|write|location)|window\.location)", re.I),
     "desc": "XSS acces DOM sensible"},

    # ── LFI / Path Traversal ──────────────────────────────────────────────
    {"id": "LFI-01", "category": "LFI",
     "pattern": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|\.\.%2f)", re.I),
     "desc": "Path traversal ../"},

    {"id": "LFI-02", "category": "LFI",
     "pattern": re.compile(r"(etc/passwd|etc/shadow|etc/hosts|proc/self|win32|windows/system32)", re.I),
     "desc": "LFI acces fichiers sensibles systeme"},

    # ── Command Injection ──────────────────────────────────────────────────
    {"id": "CMDi-01", "category": "CMDi",
     "pattern": re.compile(r"(;\s*|&&\s*|\|\|\s*|\|\s*)(ls|cat|id|whoami|wget|curl|bash|sh|nc|python|perl|ruby)\b", re.I),
     "desc": "Command injection operateurs shell"},

    {"id": "CMDi-02", "category": "CMDi",
     "pattern": re.compile(r"`[^`]{1,80}`|\$\([^)]{1,80}\)", re.I),
     "desc": "Command substitution backtick ou $()"},

    {"id": "CMDi-03", "category": "CMDi",
     "pattern": re.compile(r"\b(chmod|chown|passwd|useradd|userdel|crontab|systemctl)\b", re.I),
     "desc": "Command injection commandes systeme critiques"},

    # ── SSRF ──────────────────────────────────────────────────────────────
    {"id": "SSRF-01", "category": "SSRF",
     "pattern": re.compile(r"(http|ftp|file|gopher|dict)://\s*(localhost|127\.0\.0\.\d+|0\.0\.0\.0|169\.254|::1)", re.I),
     "desc": "SSRF vers loopback ou metadata"},

    {"id": "SSRF-02", "category": "SSRF",
     "pattern": re.compile(r"169\.254\.169\.254", re.I),
     "desc": "SSRF AWS/GCP metadata endpoint"},

    # ── Scanner / Recon ────────────────────────────────────────────────────
    {"id": "SCAN-01", "category": "Scanner",
     "pattern": re.compile(r"(nikto|sqlmap|nmap|masscan|zgrab|nuclei|burpsuite|acunetix)", re.I),
     "desc": "User-Agent scanner connu"},
]