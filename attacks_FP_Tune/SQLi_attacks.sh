#!/bin/bash
URL="http://waf:8080/test"

attack() {
    local payload="$1"
    local name="$2"
    echo -n "[ATTACK] $name → "
    curl -s -o /dev/null -w "%{http_code}\n" -X POST "$URL" --data "html=$payload"
}

echo "=== REAL SQLi ATTACKS - Testing Detection Strength ==="

# === Classic & Basic SQLi ===
attack "1' OR '1'='1"                              "Classic tautology 1"
attack "1' OR '1'='1' --"                          "Classic with comment"
attack "' OR '1'='1"                               "Auth bypass"
attack "admin' --"                                 "Login bypass"
attack "' UNION SELECT NULL--"                     "Basic UNION"

# === UNION-based ===
attack "' UNION SELECT username,password FROM users--"   "Data exfiltration"
attack "' UNION ALL SELECT NULL,NULL--"                   "UNION ALL"
attack "1 UNION SELECT database(),user()--"               "DB info"
attack "' UNION SELECT @@version--"                       "Version"

# === Error-based / Blind ===
attack "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--" "Error-based"
attack "1' AND SLEEP(5)--"                                "Time-based blind"
attack "1' AND BENCHMARK(5000000,MD5(1))--"               "Benchmark DoS"

# === Advanced / Obfuscated ===
attack "1' UNION/*comment*/SELECT/*comment*/user()"       "Inline comment"
attack "1' UNION/*!50000SELECT*/version()--"              "MySQL comment"
attack "0'XOR(if(now()=sysdate(),sleep(5),0))OR'0"        "Advanced blind"
attack "1' AND '1'=(SELECT '1' FROM dual)"                "Subquery"

# === Stacked Queries ===
attack "1'; DROP TABLE users-- "                          "Stacked DROP"
attack "1'; EXEC xp_cmdshell('whoami')--"                 "MSSQL command"
attack "1; SHUTDOWN--"                                    "Shutdown"

# === Encoded / Evasion ===
attack "%31%27%20OR%20%271%27%3D%271"                     "URL encoded"
attack "1%27%20UNION%20SELECT%20NULL%2CNULL--"           "Encoded UNION"
attack "<script>alert(1)</script>' OR '1'='1"             "XSS + SQLi mix"

# === More realistic in form context ===
attack "username=admin'--&password=anything"              "Login form bypass"
attack "id=1 UNION SELECT credit_card FROM users--"       "ID parameter injection"
attack "search=') UNION SELECT NULL,table_name FROM information_schema.tables--" "Search field"

echo "=== End of Real SQLi Attack Tests ==="