#!/usr/bin/env python3
"""
Custom WAF — Phase 3
Reverse proxy HTTP avec inspection SQLi, XSS, LFI, CMDi, SSRF, Scanner
"""

import http.server
import urllib.request
import urllib.error
import urllib.parse
import json
import logging
import os
from datetime import datetime, timezone
from rules import RULES

# ══════════════════════════════════════════════════════════════════
#  Configuration
# ══════════════════════════════════════════════════════════════════
WAF_HOST   = "0.0.0.0"
WAF_PORT   = 8090
TARGET     = "http://dvwa:80"
LOG_FILE   = "/var/log/waf/waf.log"
LOG_STATS  = "/var/log/waf/stats.json"

os.makedirs("/var/log/waf", exist_ok=True)

# ══════════════════════════════════════════════════════════════════
#  Logging
# ══════════════════════════════════════════════════════════════════
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

# Compteurs en mémoire pour les stats Phase 4
_stats = {"total": 0, "blocked": 0, "passed": 0, "by_category": {}}


def _write_stats():
    with open(LOG_STATS, "w") as f:
        json.dump(_stats, f, indent=2)


def log_block(ip, method, path, zone, rule_id, rule_desc, rule_cat, payload):
    entry = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "attacker_ip":  ip,
        "method":       method,
        "path":         path,
        "zone":         zone,           # URI | Headers | Body
        "rule_id":      rule_id,
        "rule_category": rule_cat,
        "rule_desc":    rule_desc,
        "payload":      payload[:400],
        "action":       "BLOCKED"
    }
    logging.info(json.dumps(entry, ensure_ascii=False))

    # Stats
    _stats["blocked"] += 1
    _stats["by_category"][rule_cat] = _stats["by_category"].get(rule_cat, 0) + 1
    _write_stats()

    print(
        f"[BLOCK] {entry['timestamp']} | {ip} | {rule_id} | "
        f"zone={zone} | {payload[:60]!r}"
    )


def log_pass(ip, method, path):
    _stats["passed"] += 1
    _write_stats()
    print(f"[PASS]  {datetime.now(timezone.utc).isoformat()} | {ip} | {method} {path}")


# ══════════════════════════════════════════════════════════════════
#  Page 403 personnalisée
# ══════════════════════════════════════════════════════════════════
BLOCK_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>403 — Accès Refusé</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d0d1a;
      color: #ddd;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: #13132a;
      border: 1px solid #c0392b;
      border-radius: 14px;
      padding: 52px 60px;
      text-align: center;
      max-width: 500px;
      width: 90%;
    }
    .shield { font-size: 72px; margin-bottom: 20px; }
    h1 { color: #e74c3c; font-size: 30px; margin-bottom: 6px; }
    .sub { color: #888; font-size: 13px; margin-bottom: 28px; letter-spacing: 1px; }
    p { font-size: 14px; color: #aaa; line-height: 1.7; margin-bottom: 24px; }
    .rule-box {
      background: rgba(231,76,60,0.08);
      border: 1px solid #c0392b;
      border-radius: 8px;
      padding: 10px 20px;
      font-size: 12px;
      color: #e74c3c;
      letter-spacing: 1px;
      display: inline-block;
      margin-bottom: 20px;
    }
    .footer { font-size: 11px; color: #555; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="shield">&#x1F6E1;</div>
    <h1>403 &mdash; Accès Refusé</h1>
    <p class="sub">CUSTOM WAF &bull; REQUEST BLOCKED</p>
    <p>
      Cette requête a été identifiée comme potentiellement malveillante
      et bloquée par le pare-feu applicatif custom.
    </p>
    <div class="rule-box">MALICIOUS PAYLOAD DETECTED</div>
    <p class="footer">
      Si vous pensez qu'il s'agit d'une erreur, contactez l'administrateur.<br>
      Incident enregistré dans les logs.
    </p>
  </div>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════
#  Moteur d'inspection
# ══════════════════════════════════════════════════════════════════
def decode_payload(text: str) -> str:
    """Décode URL-encoding et HTML-entities pour éviter les bypasses."""
    try:
        decoded = urllib.parse.unquote_plus(text)
        decoded = urllib.parse.unquote(decoded)   # double-encoding
        return decoded
    except Exception:
        return text


def inspect_value(text: str):
    """
    Retourne (rule_id, rule_desc, rule_category, matched_payload) ou None.
    Inspecte le texte brut + décodé.
    """
    targets = [text, decode_payload(text)]
    for content in targets:
        for rule in RULES:
            m = rule["pattern"].search(content)
            if m:
                return rule["id"], rule["desc"], rule["category"], m.group(0)
    return None


def check_request(method: str, path: str, headers, body: str):
    """
    Inspecte URI, headers et body.
    Retourne (zone, rule_id, rule_desc, category, payload) ou None.
    """
    zones = {
        "URI":     path,
        "Body":    body or "",
        "Headers": " ".join(f"{k}:{v}" for k, v in headers.items()
                            if k.lower() in ("user-agent","x-forwarded-for",
                                             "cookie", "x-custom-header")),
    }
    for zone, content in zones.items():
        result = inspect_value(content)
        if result:
            rule_id, rule_desc, rule_cat, payload = result
            return zone, rule_id, rule_desc, rule_cat, payload
    return None


# ══════════════════════════════════════════════════════════════════
#  Handler HTTP
# ══════════════════════════════════════════════════════════════════
class WAFHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass   # désactive le log Apache par défaut

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return ""
        raw = self.rfile.read(min(length, 1_048_576))  # max 1 Mo
        return raw.decode("utf-8", errors="replace")

    def _send_403(self, rule_id: str):
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-WAF-Block", rule_id)
        self.send_header("X-WAF-Engine", "CustomWAF/1.0")
        self.end_headers()
        self.wfile.write(BLOCK_PAGE.encode())

    def _forward(self, body: str):
        """Transfère la requête propre vers DVWA et renvoie la réponse."""
        url = TARGET + self.path

        # Copier les headers utiles
        fwd = {k: v for k, v in self.headers.items()
               if k.lower() not in ("host", "connection", "transfer-encoding")}
        fwd["Host"] = "dvwa"
        fwd["X-Forwarded-For"] = self.client_address[0]
        fwd["X-Forwarded-By"]  = "CustomWAF/1.0"

        data = body.encode() if body else None
        req  = urllib.request.Request(url, data=data, headers=fwd, method=self.command)

        try:
            resp = urllib.request.urlopen(req, timeout=15)
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.read())

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())

        except Exception as ex:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"<h1>502 Bad Gateway</h1><p>{ex}</p>".encode())

    def _handle(self):
        client_ip = self.client_address[0]
        _stats["total"] += 1

        body = self._read_body() if self.command in ("POST", "PUT", "PATCH") else ""

        # ── Inspection ────────────────────────────────────
        result = check_request(self.command, self.path, self.headers, body)
        if result:
            zone, rule_id, rule_desc, rule_cat, payload = result
            log_block(client_ip, self.command, self.path,
                      zone, rule_id, rule_desc, rule_cat, payload)
            self._send_403(rule_id)
            return

        # ── Requête propre → DVWA ────────────────────────
        log_pass(client_ip, self.command, self.path)
        self._forward(body)

    do_GET     = _handle
    do_POST    = _handle
    do_PUT     = _handle
    do_DELETE  = _handle
    do_HEAD    = _handle
    do_OPTIONS = _handle


# ══════════════════════════════════════════════════════════════════
#  Démarrage
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"[WAF] Démarrage — écoute sur {WAF_HOST}:{WAF_PORT}")
    print(f"[WAF] Cible backend : {TARGET}")
    print(f"[WAF] Règles chargées : {len(RULES)}")
    print(f"[WAF] Logs : {LOG_FILE}")
    print("-" * 55)

    server = http.server.HTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[WAF] Arrêt propre.")
        server.server_close()
