#!/bin/bash
echo "=== Expanded False Positive Test Suite (~100+ tests) ==="

URL="http://waf:8080/test"


test_fp_post() {
    local data="$1"
    local comment="$2"

    echo -n "[FP][POST] $comment → "

    curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "$URL" \
    --data "txtName=test&mtxMessage=$data&btnSign=Sign+Guestbook"
}

echo "=== 1. Event Handler (941120) ==="
for prefix in "on" "ON" "On" "oN"; do
    test_fp "${prefix}top=team"                    "ontop"
    test_fp "${prefix}call=meeting"                "oncall"
    test_fp "${prefix}board=welcome"               "onboard"
    test_fp "${prefix}track=progress"              "ontrack"
    test_fp "${prefix}piece=anime"                 "onepiece"
    test_fp "${prefix}load=ready"                  "onload"
    test_fp "${prefix}error=alert"                 "onerror"
    test_fp "${prefix}click=submit"                "onclick"
    test_fp "${prefix}focus=login"                 "onfocus"
    test_fp "${prefix}hover=menu"                  "onhover"
    test_fp "${prefix}change=value"                "onchange"
    test_fp "${prefix}submit=form"                 "onsubmit"
    test_fp "${prefix}blur=input"                  "onblur"
    test_fp "${prefix}keydown=search"              "onkeydown"
    test_fp "${prefix}mouseover=effect"            "onmouseover"
done

echo "=== 2. Javascript URI & Obfuscated (941140 + 941210) ==="
test_fp "javascript: basics"                       "javascript:"
test_fp "learn javascript: step by step"           "javascript tutorial"
test_fp "javascript: arrays and objects"           "javascript keyword"
test_fp "JavaScript: best practices"               "Capital JS"
test_fp "jaVasCript:alert(1) but tutorial"         "obfuscated case"
test_fp "JAVASCRIPT: DOM manipulation"             "upper case"
test_fp "javascript : with space"                  "space after"
test_fp "data:text/html,<h1>hello</h1>"            "data: URI"
test_fp "vbscript:deprecated old code"             "vbscript"
test_fp "VBScript: old language example"           "VBScript capital"
test_fp "jAvAsCrIpT: document.write"               "mixed case js"
test_fp "\\x6Aavascript: test"                     "hex js"
test_fp "ja%76ascript: tutorial"                   "url encoded"
test_fp "vb%73cript: old"                          "vbscript encoded"
test_fp "JavaScript tutorial for beginners"        "javascript word"
test_fp "modern javascript es6 features"           "modern js"
test_fp "javascript framework comparison"          "js framework"
test_fp "using javascript in html"                 "js in html"

echo "=== 3. Node-Validator Blacklist (941180) ==="
test_fp "document.cookie explained"                "document.cookie"
test_fp "how document.cookie works"                "document.cookie 2"
test_fp "window.location tutorial"                 "window.location"
test_fp "document.write example"                   "document.write"
test_fp "using document.cookie in frontend"        "document.cookie 3"
test_fp "window.location.href redirect"            "window.location 2"
test_fp "document.write dynamic content"           "document.write 2"

echo "=== 4. JS Globals (941370) ==="
test_fp "document['title'] example"                "document['']"
test_fp "document['cookie'] tutorial"              "document cookie array"
test_fp "window['location'] guide"                 "window['']"
test_fp "self['alert'] test"                       "self[]"
test_fp "top['location'] = home"                   "top[]"
test_fp "this['value'] binding"                    "this[]"
test_fp "document['getElementById'] usage"         "document[] method"
test_fp "window['addEventListener'] example"       "window[] event"
test_fp "self['location'] = url"                   "self location"

echo "=== 5. Meta / IE Filters (941260 + 921130 + 941160) ==="
test_fp "<meta charset=UTF-8>"                     "meta charset"
test_fp "<meta http-equiv='content-type'>"         "meta http-equiv"
test_fp "<META charset='utf-8'>"                   "META upper"
test_fp "<meta name='description' content='test'>" "meta tag"
test_fp "<meta charset='ISO-8859-1'>"              "meta iso"
test_fp "<META http-equiv='refresh' content='5'>"  "meta refresh"
test_fp "<meta name='viewport' content='width=device-width'>" "meta viewport"

echo "=== 6. More Obfuscated / Edge Cases for 941210 ==="
test_fp "jAvAsCrIpT: document.write"               "mixed case 2"
test_fp "\\x6Aavascript: test"                     "hex js 2"
test_fp "ja%76ascript: tutorial"                   "url encoded 2"
test_fp "vb%73cript: old"                          "vbscript encoded 2"
test_fp "JavaScript: advanced techniques"          "advanced js"


echo "=== 7. International / Encoding (941310) ==="
test_fp "য়/া বাংলা"                               "Bengali"

echo "=== 8. SQLi Crossover Words (942xxx) ==="
test_fp "because 'UNION workers deserve better'"   "UNION word"

echo "=== FP TESTS ==="
curl -s -o /dev/null -w "%{http_code} - javascript tutorial\n" -X POST "$URL" --data "html=msg=learn javascript: step by step"
curl -s -o /dev/null -w "%{http_code} - ontop word\n" -X POST "$URL" --data "html=msg=ontop=our team"
curl -s -o /dev/null -w "%{http_code} - document.cookie word\n" -X POST "$URL" --data "html=msg=document.cookie explained"
curl -s -o /dev/null -w "%{http_code} - window location word\n" -X POST "$URL" --data "html=msg=window location tutorial"


echo "=== Total FP tests completed ==="