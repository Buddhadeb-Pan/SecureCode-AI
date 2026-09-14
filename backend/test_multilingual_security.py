"""
Comprehensive Multilingual Security Analyzer Test Suite.
Tests both vulnerable snippets and safe snippets across all 15 supported languages
to verify accurate detection and false-positive resistance.
"""

from security_rules import scan_security


def run_test(name: str, code: str, language: str, expect_vuln: bool, expected_type: str = None):
    findings = scan_security(code, language)
    has_vuln = len(findings) > 0

    if expect_vuln:
        assert has_vuln, f"[{language}] Expected vulnerability for '{name}', but found none."
        if expected_type:
            types = [f.get("type") for f in findings]
            assert any(expected_type.lower() in t.lower() for t in types), \
                f"[{language}] Expected '{expected_type}' in findings, got: {types}"
        print(f"  [PASS] {language} - {name} (Vulnerable: Found {len(findings)} issue)")
    else:
        assert not has_vuln, f"[{language}] Expected safe code for '{name}', but got false positive: {[f.get('type') for f in findings]}"
        print(f"  [PASS] {language} - {name} (Safe: Zero false positives)")


def test_all_languages():
    print("\n--- 1. PYTHON ---")
    # Vulnerable SQLi
    py_vuln_sql = "username = input()\nquery = 'SELECT * FROM users WHERE name = ' + username\ncursor.execute(query)"
    run_test("SQL Injection", py_vuln_sql, "Python", True, "SQL Injection")
    # Safe SQLi
    py_safe_sql = "username = input()\ncursor.execute('SELECT * FROM users WHERE name = %s', (username,))"
    run_test("Safe Parameterized SQL", py_safe_sql, "Python", False)
    # Vulnerable Command Injection
    py_vuln_cmd = "import os\ncmd = input()\nos.system('echo ' + cmd)"
    run_test("Command Injection", py_vuln_cmd, "Python", True, "Command Injection")
    # Safe Command Execution
    py_safe_cmd = "import subprocess\nsubprocess.run(['echo', 'hello'], shell=False)"
    run_test("Safe Subprocess List", py_safe_cmd, "Python", False)
    # Insecure Deserialization
    py_pickle = "import pickle\npickle.loads(user_data)"
    run_test("Pickle Deserialization", py_pickle, "Python", True, "Insecure Deserialization")

    print("\n--- 2. JAVASCRIPT / TYPESCRIPT ---")
    # Vulnerable DOM XSS
    js_vuln_xss = "const name = req.query.name;\ndocument.write('<h1>' + name + '</h1>');"
    run_test("DOM XSS", js_vuln_xss, "JavaScript", True, "Cross-Site Scripting (XSS)")
    # Safe DOM operation
    js_safe_dom = "element.textContent = 'Hello world';"
    run_test("Safe textContent", js_safe_dom, "JavaScript", False)
    # Vulnerable Path Traversal
    js_vuln_path = "const file = req.query.f;\nconst data = fs.readFileSync('./uploads/' + file);"
    run_test("Path Traversal", js_vuln_path, "JavaScript", True, "Path Traversal")
    # Safe fs read
    js_safe_path = "const data = fs.readFileSync('/var/log/app.log', 'utf8');"
    run_test("Static fs read", js_safe_path, "JavaScript", False)

    print("\n--- 3. JAVA ---")
    # Vulnerable Java SQLi
    java_vuln_sql = "String query = \"SELECT * FROM users WHERE id = \" + reqId;\nstmt.executeQuery(query);"
    run_test("Statement SQLi", java_vuln_sql, "Java", True, "SQL Injection")
    # Safe PreparedStatement
    java_safe_sql = "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setString(1, reqId);"
    run_test("PreparedStatement", java_safe_sql, "Java", False)
    # Deserialization
    java_deser = "ObjectInputStream ois = new ObjectInputStream(stream);\nois.readObject();"
    run_test("ObjectInputStream Deserialization", java_deser, "Java", True, "Insecure Deserialization")

    print("\n--- 4. C / C++ ---")
    # Buffer overflow gets
    c_gets = "int main() {\n  char buf[10];\n  gets(buf);\n}"
    run_test("Unbounded gets", c_gets, "C", True, "Buffer Overflow")
    # Safe fgets
    c_safe = "int main() {\n  char buf[10];\n  fgets(buf, sizeof(buf), stdin);\n}"
    run_test("Bounded fgets", c_safe, "C", False)
    # Format string
    c_fmt = "void log_msg(char *user) {\n  printf(user);\n}"
    run_test("Format String", c_fmt, "C", True, "Format String")

    print("\n--- 5. C# ---")
    # SQLi
    cs_sql = "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = '\" + userName + \"'\", conn);"
    run_test("SqlCommand Concatenation", cs_sql, "C#", True, "SQL Injection")
    # Safe C#
    cs_safe = "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = @name\", conn);\ncmd.Parameters.AddWithValue(\"@name\", userName);"
    run_test("Parameterized SqlCommand", cs_safe, "C#", False)

    print("\n--- 6. PHP ---")
    # XSS in echo
    php_xss = "<?php\necho $_GET['username'];\n?>"
    run_test("Reflected XSS", php_xss, "PHP", True, "Cross-Site Scripting (XSS)")
    # Safe escaped echo
    php_safe = "<?php\necho htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8');\n?>"
    run_test("Escaped htmlspecialchars", php_safe, "PHP", False)

    print("\n--- 7. GO ---")
    # SQLi
    go_sql = "db.Query(fmt.Sprintf(\"SELECT * FROM accounts WHERE id = '%s'\", id))"
    run_test("fmt.Sprintf SQLi", go_sql, "Go", True, "SQL Injection")
    # Safe Go
    go_safe = "db.Query(\"SELECT * FROM accounts WHERE id = ?\", id)"
    run_test("Parameterized Go Query", go_safe, "Go", False)

    print("\n--- 8. RUBY ---")
    # ActiveRecord interpolation
    rb_sql = "User.where(\"username = '#{params[:name]}'\")"
    run_test("ActiveRecord String Interpolation", rb_sql, "Ruby", True, "SQL Injection")
    # Safe Ruby
    rb_safe = "User.where(\"username = ?\", params[:name])"
    run_test("Parameterized ActiveRecord", rb_safe, "Ruby", False)

    print("\n--- 9. RUST ---")
    # Command sh -c
    rs_cmd = "Command::new(\"sh\").arg(\"-c\").arg(format!(\"echo {}\", input));"
    run_test("Shell Command Injection", rs_cmd, "Rust", True, "Command Injection")
    # Safe Rust
    rs_safe = "Command::new(\"ls\").arg(\"-la\").status().unwrap();"
    run_test("Safe Discrete Command", rs_safe, "Rust", False)

    print("\n--- 10. KOTLIN ---")
    # SQLi template
    kt_sql = "db.rawQuery(\"SELECT * FROM users WHERE name = '$username'\", null)"
    run_test("Kotlin String Template SQL", kt_sql, "Kotlin", True, "SQL Injection")
    # Safe Kotlin
    kt_safe = "db.rawQuery(\"SELECT * FROM users WHERE name = ?\", arrayOf(username))"
    run_test("Parameterized Kotlin Query", kt_safe, "Kotlin", False)

    print("\n--- 11. SWIFT ---")
    # Weak crypto
    swift_md5 = "CC_MD5(data.bytes, CC_LONG(data.length), &digest)"
    run_test("CommonCrypto MD5", swift_md5, "Swift", True, "Weak Cryptography")

    print("\n--- 12. SQL ---")
    # Dynamic EXEC
    sql_exec = "DECLARE @q NVARCHAR(MAX) = 'SELECT * FROM users WHERE name = ' + @name;\nEXEC(@q);"
    run_test("Dynamic SQL EXEC Concatenation", sql_exec, "SQL", True, "SQL Injection")
    # Safe SQL procedure
    sql_safe = "SELECT id, name FROM users WHERE id = @userId;"
    run_test("Standard Parameterized SQL", sql_safe, "SQL", False)

    print("\n--- 13. HTML ---")
    # Insecure form
    html_form = "<form action=\"http://example.com/login\" method=\"POST\">\n<input type=\"password\" name=\"pwd\"/>\n</form>"
    run_test("Plaintext HTTP Form Action", html_form, "HTML", True, "Insecure HTML Form")
    # Safe form
    html_safe = "<form action=\"https://example.com/login\" method=\"POST\">\n<input type=\"password\" name=\"pwd\"/>\n</form>"
    run_test("HTTPS Form Action", html_safe, "HTML", False)

    print("\n==========================================")
    print("ALL 15-LANGUAGE ANALYZER TESTS PASSED!")
    print("==========================================\n")


if __name__ == "__main__":
    test_all_languages()
