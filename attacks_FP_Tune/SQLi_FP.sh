URL="http://waf:8080/test"

fp() {
    echo -n "[FP] $2 → "
    curl -s -o /dev/null -w "%{http_code}\n" -X POST "$URL" --data "html=msg=$1"
}

echo "=== Additional Realistic SQLi False Positives ==="

# 942190 - UNION related (very common in legal, business, politics)
fp "The European Union passed new regulations last year" "EU politics"
fp "Labor Union members are planning a strike" "Labor Union"
fp "Union of South American Nations was dissolved" "International Union"
fp "They formed a union between the two companies" "Business merger"
fp "UNION ALL is not the same as UNION in SQL" "SQL tutorial mention"

# 942360 - SQL Keywords in educational / documentation context
fp "You should always use parameterized queries instead of SELECT *" "SQL best practice"
fp "The INSERT statement adds new records to the table" "INSERT explanation"
fp "Never use DROP TABLE in production code" "DROP warning"
fp "UPDATE your application to the latest version" "UPDATE software"
fp "DELETE old log entries after 30 days" "DELETE logs"
fp "ALTER TABLE users ADD COLUMN email_verified" "ALTER TABLE"
fp "TRUNCATE TABLE is faster than DELETE" "TRUNCATE"

# 942100 / 942130 - Libinjection + Tautologies
fp "If the username equals the password then access is granted" "equals logic"
fp "Make sure old password is not equal to new password" "password validation"
fp "1 + 1 equals 2 is always true" "basic math"
fp "The result must be equal to or greater than zero" "comparison"
fp "User role should be the same as expected role" "role comparison"

# 942110 / 942430 - Quotes, special characters, code snippets
fp "In SQL you write: SELECT * FROM users WHERE id = '5'" "SQL code example"
fp "Escape single quotes like this: O''Reilly" "Name with quote"
fp "The command is: grep -E 'pattern' file.txt" "Linux command"
fp "The command format is: cp -r source/ destination/" "Linux command"
fp "JSON example: {\"name\": \"John\", \"age\": 30}" "JSON in text"
fp "Avoid using ' OR '1'='1' in your queries" "Warning about injection"

# More natural language & tutorial content
fp "How to benchmark your database performance" "Benchmark performance"
fp "The sleep function can be used for testing delays" "Sleep function"
fp "Information_schema is very useful for database introspection" "information_schema"
fp "The information_schema provides metadata about the database" "information_schema"
fp "Please select your country from the dropdown list" "Select country"
fp "Insert your card details in the secure form" "Insert card details"
fp "Update your billing information before the due date" "Update billing"
fp "Delete your account permanently from the system" "Delete account"

# Technical / developer content
fp "Common SQL antipattern: SELECT * FROM large_table" "SELECT * antipattern"
fp "Using UNION in views can improve performance" "UNION in views"
fp "Avoid SELECT COUNT(*) on huge tables" "COUNT performance"
fp "The HAVING clause filters groups after aggregation" "HAVING clause"
fp "Stored procedures can contain multiple SELECT statements" "Stored procedures"

# Edge cases with operators
fp "Price must be greater than or equal to 0" "greater than or equal"
fp "Status = 'active' AND role = 'admin'" "AND in condition"
fp "id != 0 and username is not null" "!= and is not null"


fp "MY msg would be:because 'UNION workers deserve better conditions'"   "UNION"
fp "the blog has the insert into table function explained  :FP:"   "insert into table"

fp "Status = 'active' OR role = 'admin'" "OR condition"

fp "id != 1 and email is not null" "!= and is not null"



URL="http://waf:8080/test"

fp() {
    echo -n "[FP] $2 → "
    curl -s -o /dev/null -w "%{http_code}\n" -X POST "$URL" --data "html=msg=$1"
}

echo "=== New False Positives Categories ==="

# === Punctuation & Special Characters (Apostrophes, Dashes, etc.) ===
fp "O'Connor is a common Irish surname"                    "Apostrophe in name"
fp "Mr. O'Reilly from marketing department"                "O'Reilly"
fp "The drop-off point is at the main gate"                "drop-off"
fp "Well-known author: J.K. Rowling"                       "J.K. Rowling"
fp "Follow-up email sent to client"                        "Follow-up"
fp "Mother-in-law relationship explained"                  "Mother-in-law"
fp "Real-time data processing tutorial"                    "Real-time"
fp "High-quality product with built-in features"           "built-in"

# === URL Encoding / Path Structure Looking Payloads ===
fp "The resource path is /api/v1/users?include=profile"    "URL path"
fp "Encoded example: %2Fadmin%2Fpanel%2Flogin"             "URL encoded path"
fp "Query parameter: id=123&name=test%20user"              "Query params"
fp "Redirect URL: https://example.com/return?token=abc123" "Redirect URL"
fp "File path: /var/www/html/uploads/file.pdf"             "File system path"
fp "API endpoint: /users/123/delete?soft=true"             "API path with delete"

# === Previous good ones + some new safe ones ===
fp "The European Union passed new regulations"             "EU politics"
fp "Labor Union members are planning a strike"             "Labor Union"
fp "Please select your preferred option"                   "select option"
fp "Insert your shipping address here"                     "Insert address"
fp "Update your profile picture"                           "Update profile"
fp "Delete old conversations"                              "Delete conversations"
fp "If the result equals zero then success"                "equals zero"
fp "The total must be greater than zero"                   "greater than zero"

echo "=== End of expanded FP list ==="

