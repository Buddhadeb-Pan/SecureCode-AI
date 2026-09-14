import ast
import math
import re
from collections import Counter


class PythonHardcodedSecretAnalyzer(ast.NodeVisitor):

    def __init__(self, code):
        self.code = code
        self.findings = []


    # ==================================================
    # HELPERS
    # ==================================================

    def get_code(self, node):
        return ast.get_source_segment(
            self.code,
            node
        ) or ""


    def get_name(self, node):

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            return node.attr

        return ""


    def get_full_name(self, node):

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):

            parent = self.get_full_name(
                node.value
            )

            if parent:
                return f"{parent}.{node.attr}"

            return node.attr

        return ""


    # ==================================================
    # SENSITIVE IDENTIFIER
    # ==================================================

    def is_sensitive_name(self, name):

        normalized = name.lower()

        keywords = {
            "password",
            "passwd",
            "pwd",
            "api_key",
            "apikey",
            "secret",
            "client_secret",
            "access_token",
            "auth_token",
            "admin_token",
            "jwt_secret",
            "token",
            "private_key",
            "aws_secret_access_key",
            "aws_access_key_id",
        }

        return any(
            keyword in normalized
            for keyword in keywords
        )


    # ==================================================
    # SAFE SECRET SOURCES
    # ==================================================

    def is_safe_external_source(self, node):

        # os.getenv("API_KEY")
        # os.environ.get("API_KEY")

        if isinstance(node, ast.Call):

            name = self.get_full_name(
                node.func
            )

            if name in {
                "os.getenv",
                "os.environ.get",
                "getenv",
            }:
                return True


        # os.environ["API_KEY"]

        if isinstance(node, ast.Subscript):

            name = self.get_full_name(
                node.value
            )

            if name == "os.environ":
                return True


        return False


    # ==================================================
    # LITERAL VALUE
    # ==================================================

    def get_string_literal(self, node):

        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
        ):
            return node.value

        return None


    # ==================================================
    # ENTROPY
    # ==================================================

    def calculate_entropy(self, value):

        if not value:
            return 0.0

        counts = Counter(value)
        length = len(value)

        entropy = 0.0

        for count in counts.values():

            probability = count / length

            entropy -= (
                probability
                * math.log2(probability)
            )

        return round(
            entropy,
            2
        )


    # ==================================================
    # KNOWN SECRET FORMATS
    # ==================================================

    def detect_secret_format(self, value):

        # AWS Access Key
        if re.fullmatch(
            r"AKIA[0-9A-Z]{16}",
            value
        ):
            return "AWS Access Key"


        # GitHub tokens
        if value.startswith(
            (
                "ghp_",
                "gho_",
                "ghu_",
                "ghs_",
                "github_pat_",
            )
        ):
            return "GitHub Token"


        # API keys similar to sk-...
        if (
            value.startswith("sk-")
            and len(value) >= 20
        ):
            return "API Secret Key"


        # JWT-like
        if (
            value.count(".") == 2
            and len(value) >= 30
        ):
            return "JWT-like Token"


        # Private keys
        _begin_key = "BEGIN "
        if (_begin_key + "PRIVATE KEY") in value:
            return "Private Key"

        if (_begin_key + "RSA PRIVATE KEY") in value:
            return "RSA Private Key"


        return None


    # ==================================================
    # PLACEHOLDER CHECK
    # ==================================================

    def is_placeholder(self, value):

        normalized = value.strip().lower()

        placeholders = {
            "password",
            "password123",
            "changeme",
            "change_me",
            "your_password",
            "your_api_key",
            "your_secret",
            "example",
            "example_key",
            "test",
            "dummy",
            "placeholder",
        }

        return normalized in placeholders


    # ==================================================
    # FINDING CREATION
    # ==================================================

    def analyze_assignment(
        self,
        variable_name,
        value_node,
        assignment_node
    ):

        # Environment variable etc.
        # → NOT hardcoded

        if self.is_safe_external_source(
            value_node
        ):
            return


        value = self.get_string_literal(
            value_node
        )

        # Only direct string literal
        if value is None:
            return


        if len(value.strip()) < 4:
            return


        sensitive_name = (
            self.is_sensitive_name(
                variable_name
            )
        )

        secret_format = (
            self.detect_secret_format(
                value
            )
        )


        # Need at least identifier evidence
        # OR known secret format

        if (
            not sensitive_name
            and not secret_format
        ):
            return


        entropy = (
            self.calculate_entropy(
                value
            )
        )

        placeholder = (
            self.is_placeholder(
                value
            )
        )


        if secret_format:
            confidence = 99

        elif placeholder:
            confidence = 75

        elif entropy >= 3.5:
            confidence = 97

        else:
            confidence = 90


        line = getattr(
            assignment_node,
            "lineno",
            0
        )


        evidence = {
            "role": "secret_declaration",
            "line": line,
            "start_line": line,
            "end_line": getattr(
                assignment_node,
                "end_lineno",
                line
            ),
            "code": self.get_code(
                assignment_node
            ),
            "description":
                "Sensitive literal value is stored directly in source code.",
        }


        finding = {
            "type":
                "Hardcoded Secret",

            # Temporary severity.
            # Later severity engine changes this.
            "severity":
                "HIGH",

            "primary_line":
                line,

            "description":
                (
                    "A sensitive credential appears "
                    "to be stored directly in source code."
                ),

            "variable":
                variable_name,

            "secret_format":
                secret_format,

            "entropy":
                entropy,

            "placeholder":
                placeholder,

            "confidence":
                confidence,

            "source":
                evidence,

            "evidence": [
                evidence
            ],

            "sink":
                None,

            "affected_lines": [
                line
            ],

            "location": {
                "start_line":
                    line,

                "end_line":
                    getattr(
                        assignment_node,
                        "end_lineno",
                        line
                    ),
            },

            "evidence_level":
                "hardcoded_secret_confirmed",

            "analysis_method":
                (
                    "AST + Sensitive Identifier Analysis "
                    "+ Secret Format Detection "
                    "+ Entropy Heuristics"
                ),
        }

        self.findings.append(
            finding
        )


    # ==================================================
    # AST ASSIGNMENTS
    # ==================================================

    def visit_Assign(self, node):

        for target in node.targets:

            variable_name = (
                self.get_name(target)
            )

            if variable_name:

                self.analyze_assignment(
                    variable_name,
                    node.value,
                    node
                )

        self.generic_visit(node)


    def visit_AnnAssign(self, node):

        if node.value is not None:

            variable_name = (
                self.get_name(
                    node.target
                )
            )

            if variable_name:

                self.analyze_assignment(
                    variable_name,
                    node.value,
                    node
                )

        self.generic_visit(node)


# ==================================================
# PUBLIC FUNCTION
# ==================================================

def analyze_python_hardcoded_secrets(code):

    try:
        tree = ast.parse(code)

    except SyntaxError as error:

        return {
            "status": "parser_error",
            "error": str(error),
            "findings": [],
        }


    analyzer = (
        PythonHardcodedSecretAnalyzer(
            code
        )
    )

    analyzer.visit(tree)


    for index, finding in enumerate(
        analyzer.findings,
        start=1
    ):
        finding["id"] = index


    return {
        "status": "success",
        "findings": analyzer.findings,
    }