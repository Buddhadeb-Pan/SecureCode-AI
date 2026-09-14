import ast


class PythonXSSAnalyzer(ast.NodeVisitor):

    def __init__(self, code):
        self.code = code
        self.lines = code.splitlines()

        self.tainted = set()
        self.sanitized = set()
        self.flow = {}
        self.findings = []


    # ==================================================
    # HELPERS
    # ==================================================

    def get_full_name(self, node):

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = self.get_full_name(node.value)

            if parent:
                return f"{parent}.{node.attr}"

            return node.attr

        return ""


    def get_code(self, node):

        segment = ast.get_source_segment(
            self.code,
            node
        )

        if segment:
            return segment

        line = getattr(
            node,
            "lineno",
            0
        )

        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]

        return ""


    def create_evidence(
        self,
        node,
        role,
        description
    ):

        start_line = getattr(
            node,
            "lineno",
            0
        )

        end_line = getattr(
            node,
            "end_lineno",
            start_line
        )

        return {
            "role": role,
            "line": start_line,
            "start_line": start_line,
            "end_line": end_line,
            "code": self.get_code(node),
            "description": description,
        }


    # ==================================================
    # SOURCES
    # ==================================================

    def is_source_call(self, node):

        if not isinstance(node, ast.Call):
            return False

        name = self.get_full_name(
            node.func
        )

        return name in {
            "input",
            "request.args.get",
            "request.form.get",
            "request.values.get",
            "request.cookies.get",
            "request.json.get",
            "request.get_json",
        }


    def is_request_subscript(self, node):

        if not isinstance(
            node,
            ast.Subscript
        ):
            return False

        name = self.get_full_name(
            node.value
        )

        return name in {
            "request.args",
            "request.form",
            "request.values",
            "request.cookies",
            "request.json",
        }


    # ==================================================
    # SANITIZERS
    # ==================================================

    def is_sanitizer_call(self, node):

        if not isinstance(node, ast.Call):
            return False

        name = self.get_full_name(
            node.func
        )

        return name in {
            "html.escape",
            "markupsafe.escape",
            "bleach.clean",
            "escape",
        }


    # ==================================================
    # TAINT
    # ==================================================

    def expression_is_tainted(self, node):

        if node is None:
            return False

        if self.is_source_call(node):
            return True

        if self.is_request_subscript(node):
            return True


        if isinstance(node, ast.Name):

            if node.id in self.sanitized:
                return False

            return node.id in self.tainted


        if isinstance(node, ast.BinOp):

            return (
                self.expression_is_tainted(
                    node.left
                )
                or
                self.expression_is_tainted(
                    node.right
                )
            )


        if isinstance(
            node,
            ast.JoinedStr
        ):

            for value in node.values:

                if isinstance(
                    value,
                    ast.FormattedValue
                ):

                    if self.expression_is_tainted(
                        value.value
                    ):
                        return True

            return False


        if isinstance(node, ast.Call):

            if self.is_sanitizer_call(node):
                return False

            if isinstance(
                node.func,
                ast.Attribute
            ):

                if self.expression_is_tainted(
                    node.func.value
                ):
                    return True

            for arg in node.args:

                if self.expression_is_tainted(
                    arg
                ):
                    return True

            for keyword in node.keywords:

                if self.expression_is_tainted(
                    keyword.value
                ):
                    return True

            return False


        if isinstance(
            node,
            ast.Subscript
        ):

            if self.is_request_subscript(node):
                return True

            return self.expression_is_tainted(
                node.value
            )


        if isinstance(
            node,
            (
                ast.List,
                ast.Tuple,
                ast.Set,
            )
        ):

            return any(
                self.expression_is_tainted(item)
                for item in node.elts
            )


        if isinstance(node, ast.Dict):

            return any(
                self.expression_is_tainted(value)
                for value in node.values
                if value is not None
            )


        return False


    # ==================================================
    # FLOW
    # ==================================================

    def collect_parent_flow(self, node):

        evidence = []

        for child in ast.walk(node):

            if isinstance(
                child,
                ast.Name
            ):

                if child.id in self.flow:

                    for item in self.flow[
                        child.id
                    ]:

                        if item not in evidence:
                            evidence.append(item)

        return evidence


    def mark_assignment(
        self,
        variable_name,
        value,
        node
    ):

        if self.is_sanitizer_call(value):

            self.sanitized.add(
                variable_name
            )

            self.tainted.discard(
                variable_name
            )

            self.flow.pop(
                variable_name,
                None
            )

            return


        if not self.expression_is_tainted(
            value
        ):

            self.tainted.discard(
                variable_name
            )

            self.sanitized.discard(
                variable_name
            )

            self.flow.pop(
                variable_name,
                None
            )

            return


        self.tainted.add(
            variable_name
        )

        previous_flow = (
            self.collect_parent_flow(
                value
            )
        )


        if (
            self.is_source_call(value)
            or
            self.is_request_subscript(value)
        ):

            current = self.create_evidence(
                node,
                "source",
                "Untrusted user-controlled data enters the application."
            )

        else:

            current = self.create_evidence(
                node,
                "propagation",
                "Untrusted data is propagated into another value."
            )


        flow = list(
            previous_flow
        )

        if current not in flow:
            flow.append(current)

        self.flow[
            variable_name
        ] = flow


    def visit_Assign(self, node):

        for target in node.targets:

            if isinstance(
                target,
                ast.Name
            ):

                self.mark_assignment(
                    target.id,
                    node.value,
                    node
                )

        self.generic_visit(node)


    def visit_AnnAssign(self, node):

        if (
            isinstance(
                node.target,
                ast.Name
            )
            and node.value is not None
        ):

            self.mark_assignment(
                node.target.id,
                node.value,
                node
            )

        self.generic_visit(node)


    # ==================================================
    # XSS SINKS
    # ==================================================

    def is_xss_sink(self, node):

        if not isinstance(node, ast.Call):
            return False

        name = self.get_full_name(
            node.func
        )

        return name in {
            "render_template_string",
            "flask.render_template_string",

            "Markup",
            "markupsafe.Markup",

            "Response",
            "flask.Response",

            "make_response",
            "flask.make_response",
        }


    # ==================================================
    # FINDING
    # ==================================================

    def create_finding(
        self,
        sink_node,
        sink_argument
    ):

        evidence = []

        if isinstance(
            sink_argument,
            ast.Name
        ):

            evidence.extend(
                self.flow.get(
                    sink_argument.id,
                    []
                )
            )

        else:

            evidence.extend(
                self.collect_parent_flow(
                    sink_argument
                )
            )


        sink_evidence = (
            self.create_evidence(
                sink_node,
                "sink",
                "Untrusted data reaches an HTML rendering sink without confirmed output sanitization."
            )
        )

        evidence.append(
            sink_evidence
        )


        source = None

        for item in evidence:

            if item.get("role") == "source":
                source = item
                break


        affected_lines = set()

        for item in evidence:

            line = item.get(
                "line",
                0
            )

            if line:
                affected_lines.add(
                    line
                )


        finding = {
            "type":
                "Cross-Site Scripting (XSS)",

            "severity":
                "HIGH",

            "primary_line":
                getattr(
                    sink_node,
                    "lineno",
                    0
                ),

            "description":
                (
                    "User-controlled data reaches an HTML "
                    "rendering sink without confirmed sanitization."
                ),

            "source":
                source,

            "evidence":
                evidence,

            "sink":
                sink_evidence,

            "affected_lines":
                sorted(
                    affected_lines
                ),

            "location": {
                "start_line":
                    min(affected_lines)
                    if affected_lines
                    else getattr(
                        sink_node,
                        "lineno",
                        0
                    ),

                "end_line":
                    max(affected_lines)
                    if affected_lines
                    else getattr(
                        sink_node,
                        "end_lineno",
                        getattr(
                            sink_node,
                            "lineno",
                            0
                        )
                    ),
            },

            "evidence_level":
                "data_flow_confirmed",

            "analysis_method":
                (
                    "AST + Variable Tracking "
                    "+ Taint Analysis + Sanitization Check"
                ),
        }

        self.findings.append(
            finding
        )


    def visit_Call(self, node):

        if (
            self.is_xss_sink(node)
            and node.args
        ):

            argument = node.args[0]

            if self.expression_is_tainted(
                argument
            ):

                self.create_finding(
                    node,
                    argument
                )

        self.generic_visit(node)


# ==================================================
# PUBLIC FUNCTION
# ==================================================

def analyze_python_xss(code):

    try:

        tree = ast.parse(
            code
        )

    except SyntaxError as error:

        return {
            "status": "parser_error",
            "error": str(error),
            "findings": [],
        }


    analyzer = PythonXSSAnalyzer(
        code
    )

    analyzer.visit(
        tree
    )


    for index, finding in enumerate(
        analyzer.findings,
        start=1
    ):

        finding["id"] = index


    return {
        "status": "success",
        "findings": analyzer.findings,
    }