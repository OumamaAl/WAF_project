#!/bin/bash
URL="http://waf:8080/test"
echo "=== Testing Real XSS Attacks - Checking if 941180 / 941370 weakening created bypasses ==="

# Helper
attack() {
    local payload="$1"
    local name="$2"
    echo -n "[ATTACK] $name → "
    curl -s -o /dev/null -w "%{http_code}\n" -X POST "$URL" --data "html=$payload"
}

echo "=== 1. Classic & Strong XSS (should still be blocked) ==="
attack "<script>alert(1)</script>"                    "Classic script tag"
attack "<img src=x onerror=alert(1)>"                 "onerror img"
attack "<svg/onload=alert(1)>"                        "SVG onload"

attack "<body onload=alert(1)>"                       "body onload"

echo "=== 2. Tests specifically targeting 941180 / 941370 areas ==="
attack "document.cookie='stolen=123'"                 "Real document.cookie assignment"  
attack "document.write('<script>alert(1)</script>')"  "Real document.write"
attack "window.location='javascript:alert(1)'"        "Real window.location"
attack "window['location']='javascript:alert(1)'"     "Bracket notation location"
attack "document['cookie']='evil=1'"                  "Bracket + cookie"
attack "self['alert'](1)"                             "self bracket alert"
attack "top.location.href='evil.com'"                 "top.location"

echo "=== 3. Obfuscated / Evasion attempts (should still catch) ==="
attack "%3Cscript%3Ealert(1)%3C/script%3E"            "URL encoded script"
attack "jaVasCript:alert(1)"                          "Mixed case javascript:"
attack "&#106;avascript:alert(1)"                     "HTML entity javascript" 
attack "<img src=\"x\" onerror=\"alert(1)\">"         "Quoted onerror"
attack "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>"  "CDATA bypass"

echo "=== 4. More dangerous payloads ==="
attack "<iframe src=javascript:alert(1)></iframe>"    "iframe javascript"
attack "onerror=alert(1)>"                            "Loose onerror"
attack "<details open ontoggle=alert(1)>"             "ontoggle"
attack "<math><mi><![CDATA[</mi><script>alert(1)</script>]]></math>"   "MathML"

echo "=== End of attack tests ==="

URL="http://waf:8080/test"



echo -e "\n=== REAL ATTACK TESTS ==="
curl -s -o /dev/null -w "%{http_code} - Classic script\n" -X POST "$URL" --data "html=<script>alert(1)</script>"
curl -s -o /dev/null -w "%{http_code} - onerror\n" -X POST "$URL" --data "html=<img src=x onerror=alert(1)>"
curl -s -o /dev/null -w "%{http_code} - javascript: protocol\n" -X POST "$URL" --data "html=javascript:alert(1)"
curl -s -o /dev/null -w "%{http_code} - document.cookie real\n" -X POST "$URL" --data "html=document.cookie='stolen'"
curl -s -o /dev/null -w "%{http_code} - window.location real\n" -X POST "$URL" --data "html=window.location='evil.com'"
curl -s -o /dev/null -w "%{http_code} - Bracket notation\n" -X POST "$URL" --data "html=window['location']='javascript:alert(1)'"

