import re
from pathlib import Path
from tree_sitter_language_pack import get_parser

# =========================================================
# 1. FILE EXTENSION DETECTION
# =========================================================

EXTENSION_MAP = {
    ".py": "Python",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".cs": "C#",
    ".php": "PHP",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".swift": "Swift",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
}


# =========================================================
# 2. LANGUAGE KEYWORDS / PATTERNS
# Each pattern has a weight.
# Stronger language-specific patterns get a higher weight.
# =========================================================

PATTERN_RULES = {
    "Python": [
        (r"\bdef\s+\w+\s*\(", 5),
        (r"\bimport\s+\w+", 3),
        (r"\bfrom\s+\w+\s+import\b", 5),
        (r"\bprint\s*\(", 2),
        (r"\belif\b", 4),
        (r"if\s+__name__\s*==\s*[\"']__main__[\"']", 8),
    ],

    "C": [
        (r"#include\s*<stdio\.h>", 6),
        (r"\bprintf\s*\(", 4),
        (r"\bscanf\s*\(", 4),
        (r"\bmalloc\s*\(", 3),
        (r"\bfree\s*\(", 3),
    ],

    "C++": [
        (r"#include\s*<iostream>", 7),
        (r"\bstd::", 7),
        (r"\bcout\s*<<", 6),
        (r"\bcin\s*>>", 6),
        (r"\busing\s+namespace\s+std\b", 7),
        (r"\bvector\s*<", 4),
    ],

    "Java": [
        (r"\bpublic\s+class\s+\w+", 6),
        (r"\bpublic\s+static\s+void\s+main\s*\(", 8),
        (r"\bSystem\.out\.println\s*\(", 7),
        (r"\bimport\s+java\.", 6),
        (r"\bextends\s+\w+", 2),
    ],

    "JavaScript": [
        (r"\bconst\s+\w+\s*=", 3),
        (r"\blet\s+\w+\s*=", 3),
        (r"\bconsole\.log\s*\(", 6),
        (r"\bfunction\s+\w+\s*\(", 4),
        (r"=>", 2),
        (r"\brequire\s*\(", 4),
    ],

    "TypeScript": [
        (r"\binterface\s+\w+", 7),
        (r"\btype\s+\w+\s*=", 6),
        (r"\b(?:let|const|var)\s+\w+\s*:\s*\w+", 7),
        (r"\)\s*:\s*(?:string|number|boolean|void)\b", 7),
        (r"\bas\s+(?:string|number|boolean)\b", 5),
    ],

    "C#": [
        (r"\busing\s+System\b", 7),
        (r"\bConsole\.WriteLine\s*\(", 7),
        (r"\bnamespace\s+\w+", 5),
        (r"\bstatic\s+void\s+Main\s*\(", 7),
        (r"\bList<\w+>", 3),
    ],

    "PHP": [
        (r"<\?php", 10),
        (r"\$\w+\s*=", 4),
        (r"\becho\b", 4),
        (r"\bfunction\s+\w+\s*\(", 2),
        (r"\$_(?:GET|POST|SERVER|SESSION|COOKIE)", 8),
    ],

    "Go": [
        (r"\bpackage\s+main\b", 8),
        (r'\bimport\s+"fmt"', 7),
        (r"\bfmt\.Print(?:ln|f)?\s*\(", 7),
        (r"\bfunc\s+main\s*\(", 7),
        (r"\bgo\s+\w+\s*\(", 4),
    ],

    "Rust": [
        (r"\bfn\s+main\s*\(", 7),
        (r"\bprintln!\s*\(", 7),
        (r"\blet\s+mut\s+\w+", 6),
        (r"\buse\s+std::", 7),
        (r"\bimpl\s+\w+", 4),
    ],

    "Ruby": [
        (r"\bdef\s+\w+", 3),
        (r"\bputs\b", 5),
        (r"\brequire\s+[\"']", 4),
        (r"\bend\b", 2),
        (r"\battr_(?:reader|writer|accessor)\b", 7),
    ],

    "Kotlin": [
        (r"\bfun\s+main\s*\(", 8),
        (r"\bprintln\s*\(", 3),
        (r"\bval\s+\w+", 5),
        (r"\bvar\s+\w+\s*:", 5),
        (r"\bdata\s+class\s+\w+", 7),
    ],

    "Swift": [
        (r"\bimport\s+Foundation\b", 7),
        (r"\bfunc\s+\w+\s*\(", 4),
        (r"\bvar\s+\w+\s*:", 4),
        (r"\blet\s+\w+\s*:", 4),
        (r"\bguard\s+let\b", 7),
    ],

    "SQL": [
        (r"\bSELECT\b.+\bFROM\b", 7),
        (r"\bINSERT\s+INTO\b", 7),
        (r"\bUPDATE\b.+\bSET\b", 7),
        (r"\bDELETE\s+FROM\b", 7),
        (r"\bCREATE\s+TABLE\b", 7),
        (r"\bJOIN\b", 3),
    ],

    "HTML": [
        (r"<!DOCTYPE\s+html", 10),
        (r"<html\b", 8),
        (r"<head\b", 5),
        (r"<body\b", 5),
        (r"</[a-zA-Z][^>]*>", 3),
    ],
}


def detect_extension(file_name: str):
    """
    Detect language using file extension.
    Returns language name or None.
    """

    if not file_name:
        return None

    extension = Path(file_name).suffix.lower()

    return EXTENSION_MAP.get(extension)


def detect_pattern_candidates(code: str):
    """
    Check language-specific keywords and patterns.
    Returns candidate languages sorted by score.
    """

    scores = {}
    matched_patterns = {}

    for language, rules in PATTERN_RULES.items():

        score = 0
        matches = []

        for pattern, weight in rules:

            if re.search(
                pattern,
                code,
                flags=re.IGNORECASE | re.MULTILINE | re.DOTALL
            ):
                score += weight
                matches.append(pattern)

        if score > 0:
            scores[language] = score
            matched_patterns[language] = matches

    candidates = []

    for language, score in sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        candidates.append({
            "language": language,
            "pattern_score": score,
            "matched_patterns": matched_patterns[language]
        })

    return candidates


def get_language_candidates(code: str, file_name: str = ""):
    """
    Step 3B result.

    Combines:
    - file extension hint
    - keyword / pattern candidates

    Parser validation will be added in Step 3C.
    """

    extension_language = detect_extension(file_name)
    pattern_candidates = detect_pattern_candidates(code)

    return {
        "extension_hint": extension_language,
        "pattern_candidates": pattern_candidates[:3]
    }
# =========================================================
# 3. PARSER VALIDATION
# =========================================================

PARSER_LANGUAGE_MAP = {
    "Python": "python",
    "C": "c",
    "C++": "cpp",
    "Java": "java",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "C#": "csharp",
    "PHP": "php",
    "Go": "go",
    "Rust": "rust",
    "Ruby": "ruby",
    "Kotlin": "kotlin",
    "Swift": "swift",
    "SQL": "sql",
    "HTML": "html",
}


def count_parser_errors(node):
    """
    Count ERROR and missing nodes inside the syntax tree.
    """

    error_count = 0

    if node.type == "ERROR" or node.is_missing:
        error_count += 1

    for child in node.children:
        error_count += count_parser_errors(child)

    return error_count


def validate_with_parser(code: str, language: str):
    """
    Parse code using the selected language parser.
    Returns parser validation information.
    """

    parser_name = PARSER_LANGUAGE_MAP.get(language)

    if not parser_name:
        return {
            "language": language,
            "parser_available": False,
            "parser_passed": False,
            "error_count": None,
        }

    try:
        parser = get_parser(parser_name)

        tree = parser.parse(code.encode("utf-8"))
        root = tree.root_node

        error_count = count_parser_errors(root)

        return {
            "language": language,
            "parser_available": True,
            "parser_passed": error_count == 0,
            "error_count": error_count,
        }

    except Exception as error:
        return {
            "language": language,
            "parser_available": False,
            "parser_passed": False,
            "error_count": None,
            "error": str(error),
        }


def validate_candidates(code: str, candidates):
    """
    Validate pattern-selected candidate languages
    using their Tree-sitter parsers.
    """

    results = []

    for candidate in candidates:
        language = candidate["language"]

        parser_result = validate_with_parser(code, language)

        results.append({
            **candidate,
            **parser_result,
        })

    return results

# =========================================================
# 4. FINAL LANGUAGE DECISION
# Confidence + conflict handling
# =========================================================

SUPPORTED_LANGUAGES = set(PARSER_LANGUAGE_MAP.keys())


def detect_language(code: str, file_name: str = "", frontend_hint: str = ""):
    """
    Final language detection using:
    1. File extension
    2. Keyword / pattern scoring
    3. Parser validation
    4. Frontend hint (low priority)
    5. Conflict / ambiguity handling

    Alternative candidates are checked internally only.
    Frontend receives only the final detected language.
    """

    # -------------------------------------------------
    # 0. EMPTY CODE CHECK
    # -------------------------------------------------

    if not code or not code.strip():
        return {
            "language": "Unknown",
            "confidence": 0,
            "status": "empty_code",
            "parser_passed": False,
        }

    # -------------------------------------------------
    # 1. EXTENSION + PATTERN CHECK
    # -------------------------------------------------

    extension_language = detect_extension(file_name)
    pattern_candidates = detect_pattern_candidates(code)

    # Take top 3 pattern candidates
    candidates = pattern_candidates[:3]

    candidate_names = {
        candidate["language"]
        for candidate in candidates
    }

    # -------------------------------------------------
    # 2. ADD EXTENSION LANGUAGE
    # -------------------------------------------------

    if (
        extension_language
        and extension_language in SUPPORTED_LANGUAGES
        and extension_language not in candidate_names
    ):
        candidates.append({
            "language": extension_language,
            "pattern_score": 0,
            "matched_patterns": [],
        })

    candidate_names = {
        candidate["language"]
        for candidate in candidates
    }

    # -------------------------------------------------
    # 3. ADD FRONTEND HINT
    # Very low priority
    # -------------------------------------------------

    if (
        frontend_hint
        and frontend_hint in SUPPORTED_LANGUAGES
        and frontend_hint not in candidate_names
    ):
        candidates.append({
            "language": frontend_hint,
            "pattern_score": 0,
            "matched_patterns": [],
        })

    # No candidate found
    if not candidates:
        return {
            "language": "Unknown",
            "confidence": 0,
            "status": "insufficient_evidence",
            "parser_passed": False,
        }

    # -------------------------------------------------
    # 4. CHECK EVERY CANDIDATE WITH PARSER
    # -------------------------------------------------

    final_results = []

    for candidate in candidates:

        language = candidate["language"]
        pattern_score = candidate["pattern_score"]

        parser_result = validate_with_parser(
            code,
            language
        )

        score = 0

        # ---------------------------------------------
        # Pattern / keyword score
        # Maximum = 45
        # ---------------------------------------------

        pattern_points = min(
            pattern_score * 3,
            45
        )

        score += pattern_points

        # ---------------------------------------------
        # Extension score
        # ---------------------------------------------

        extension_match = (
            language == extension_language
        )

        if extension_match:
            score += 25

        # ---------------------------------------------
        # Frontend hint score
        # Very small importance
        # ---------------------------------------------

        frontend_match = (
            language == frontend_hint
        )

        if frontend_match:
            score += 5

        # ---------------------------------------------
        # Parser result
        # ---------------------------------------------

        parser_available = parser_result[
            "parser_available"
        ]

        parser_passed = parser_result[
            "parser_passed"
        ]

        parser_errors = parser_result[
            "error_count"
        ]

        # Parser passed = strong evidence
        if parser_passed:
            score += 35

        # Parser failed
        elif parser_available:

            if parser_errors is None:
                score -= 15

            elif parser_errors <= 1:
                score -= 8

            elif parser_errors <= 3:
                score -= 15

            else:
                score -= 25

        # Keep score between 0 and 100
        score = max(
            0,
            min(score, 100)
        )

        final_results.append({
            "language": language,
            "score": score,
            "pattern_score": pattern_score,
            "extension_match": extension_match,
            "frontend_hint_match": frontend_match,
            "parser_available": parser_available,
            "parser_passed": parser_passed,
            "parser_errors": parser_errors,
        })

    # -------------------------------------------------
    # 5. SORT RESULTS
    # -------------------------------------------------

    final_results.sort(
        key=lambda item: (
            item["score"],
            item["parser_passed"],
            item["pattern_score"],
        ),
        reverse=True,
    )

    best = final_results[0]

    second = (
        final_results[1]
        if len(final_results) > 1
        else None
    )

    # -------------------------------------------------
    # 6. VERY SHORT / GENERIC CODE PROTECTION
    #
    # Example:
    # print("hello")
    # x = 10
    #
    # Don't blindly declare a language.
    # -------------------------------------------------

    if (
        not extension_language
        and best["pattern_score"] < 4
    ):
        return {
            "language": "Unknown",
            "confidence": best["score"],
            "status": "insufficient_evidence",
            "parser_passed": best["parser_passed"],
        }

    # -------------------------------------------------
    # 7. PARSER FAILED + WEAK PATTERN
    # -------------------------------------------------

    if (
        best["parser_available"]
        and not best["parser_passed"]
        and best["pattern_score"] < 8
    ):
        return {
            "language": "Unknown",
            "confidence": best["score"],
            "status": "parser_not_confirmed",
            "parser_passed": False,
        }

    # -------------------------------------------------
    # 8. INTERNAL ALTERNATIVE / CONFLICT CHECK
    #
    # Alternative language is NOT sent to frontend.
    # -------------------------------------------------

    if second:

        score_difference = (
            best["score"]
            - second["score"]
        )

        both_parsers_passed = (
            best["parser_passed"]
            and second["parser_passed"]
        )

        # Too close = ambiguous
        if (
            score_difference < 10
            and both_parsers_passed
        ):
            return {
                "language": "Unknown",
                "confidence": best["score"],
                "status": "ambiguous",
                "parser_passed": True,
            }

    # -------------------------------------------------
    # 9. LOW CONFIDENCE CHECK
    # -------------------------------------------------

    if best["score"] < 40:
        return {
            "language": "Unknown",
            "confidence": best["score"],
            "status": "low_confidence",
            "parser_passed": best["parser_passed"],
        }

    # -------------------------------------------------
    # 10. FINAL CONFIRMATION
    # -------------------------------------------------

    strong_pattern = (
        best["pattern_score"] >= 4
    )

    extension_and_parser = (
        best["extension_match"]
        and best["parser_passed"]
    )

    pattern_and_parser = (
        strong_pattern
        and best["parser_passed"]
    )

    very_strong_pattern = (
        best["pattern_score"] >= 10
    )

    if not (
        extension_and_parser
        or pattern_and_parser
        or very_strong_pattern
    ):
        return {
            "language": "Unknown",
            "confidence": best["score"],
            "status": "insufficient_evidence",
            "parser_passed": best["parser_passed"],
        }

    # -------------------------------------------------
    # FINAL LANGUAGE
    # -------------------------------------------------

    return {
        "language": best["language"],
        "confidence": best["score"],
        "status": "confirmed",
        "parser_passed": best["parser_passed"],
    }