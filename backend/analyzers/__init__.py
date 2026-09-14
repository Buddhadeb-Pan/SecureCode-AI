"""
Modular Security Analyzers package for SecureCode AI.
Exports language-specific analyzers across all 15 supported languages.
"""

from analyzers.python_security_analyzer import analyze_python
from analyzers.javascript_security_analyzer import analyze_javascript
from analyzers.java_security_analyzer import analyze_java
from analyzers.c_cpp_security_analyzer import analyze_c_cpp
from analyzers.csharp_security_analyzer import analyze_csharp
from analyzers.php_security_analyzer import analyze_php
from analyzers.go_security_analyzer import analyze_go
from analyzers.ruby_security_analyzer import analyze_ruby
from analyzers.rust_security_analyzer import analyze_rust
from analyzers.kotlin_security_analyzer import analyze_kotlin
from analyzers.swift_security_analyzer import analyze_swift
from analyzers.sql_security_analyzer import analyze_sql
from analyzers.html_security_analyzer import analyze_html

__all__ = [
    "analyze_python",
    "analyze_javascript",
    "analyze_java",
    "analyze_c_cpp",
    "analyze_csharp",
    "analyze_php",
    "analyze_go",
    "analyze_ruby",
    "analyze_rust",
    "analyze_kotlin",
    "analyze_swift",
    "analyze_sql",
    "analyze_html",
]
