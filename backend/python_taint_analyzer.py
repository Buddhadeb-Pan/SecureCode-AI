import ast


SQL_KEYWORDS = (
    "select ",
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "create ",
    "alter ",
)


class PythonSQLTaintAnalyzer(ast.NodeVisitor):

    def __init__(self, code):
        self.code = code
        self.lines = code.splitlines()

        # কোন variable user-controlled
        self.tainted = set()

        # variable-এর complete flow/evidence
        self.flow = {}

        # কোন variable SQL query contain করে
        self.sql_variables = set()

        # final findings
        self.findings = []

    # --------------------------------------------------
    # Utility: exact source code বের করা
    # --------------------------------------------------

    def get_line(self, line_number):
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]

        return ""

    def get_code_range(self, start_line, end_line):
        if not start_line or not end_line:
            return ""

        return "\n".join(
            self.lines[start_line - 1:end_line]
        )

    # --------------------------------------------------
    # SOURCE detection
    # --------------------------------------------------

    def is_user_input_source(self, node):

        if not isinstance(node, ast.Call):
            return False

        # input()
        if isinstance(node.func, ast.Name):
            if node.func.id == "input":
                return True

        # request.args.get()
        # request.form.get()
        # request.values.get()
        # request.cookies.get()
        if isinstance(node.func, ast.Attribute):

            full_name = self.get_attribute_name(node.func)

            source_patterns = (
                "request.args.get",
                "request.form.get",
                "request.values.get",
                "request.cookies.get",
                "request.get_json",
            )

            if full_name in source_patterns:
                return True

        return False

    # --------------------------------------------------
    # Attribute নাম বের করা
    # --------------------------------------------------

    def get_attribute_name(self, node):

        parts = []

        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value

        if isinstance(node, ast.Name):
            parts.append(node.id)

        return ".".join(reversed(parts))

    # --------------------------------------------------
    # Expression tainted কিনা
    # --------------------------------------------------

    def expression_is_tainted(self, node):

        if node is None:
            return False

        # username
        if isinstance(node, ast.Name):
            return node.id in self.tainted

        # "text" + username
        if isinstance(node, ast.BinOp):
            return (
                self.expression_is_tainted(node.left)
                or
                self.expression_is_tainted(node.right)
            )

        # f"...{username}"
        if isinstance(node, ast.JoinedStr):

            for value in node.values:

                if isinstance(value, ast.FormattedValue):
                    if self.expression_is_tainted(value.value):
                        return True

            return False

        # function(arg)
        if isinstance(node, ast.Call):

            if self.is_user_input_source(node):
                return True

            for arg in node.args:
                if self.expression_is_tainted(arg):
                    return True

        # [username]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):

            return any(
                self.expression_is_tainted(item)
                for item in node.elts
            )

        return False

    # --------------------------------------------------
    # SQL আছে কিনা
    # --------------------------------------------------

    def expression_contains_sql(self, node):

        try:
            text = ast.get_source_segment(
                self.code,
                node
            ) or ""
        except Exception:
            text = ""

        text_lower = text.lower()

        return any(
            keyword in text_lower
            for keyword in SQL_KEYWORDS
        )

    # --------------------------------------------------
    # Variable name বের করা
    # --------------------------------------------------

    def get_target_names(self, target):

        names = []

        if isinstance(target, ast.Name):
            names.append(target.id)

        elif isinstance(target, (ast.Tuple, ast.List)):

            for element in target.elts:
                names.extend(
                    self.get_target_names(element)
                )

        return names

    # --------------------------------------------------
    # আগের variable-এর flow collect করা
    # --------------------------------------------------

    def collect_previous_flow(self, node):

        evidence = []

        class NameCollector(ast.NodeVisitor):

            def __init__(self):
                self.names = []

            def visit_Name(self, child):
                self.names.append(child.id)

        collector = NameCollector()
        collector.visit(node)

        already_added = set()

        for name in collector.names:

            if name not in self.flow:
                continue

            for item in self.flow[name]:

                key = (
                    item.get("role"),
                    item.get("line"),
                    item.get("start_line"),
                    item.get("end_line"),
                )

                if key not in already_added:
                    evidence.append(item.copy())
                    already_added.add(key)

        return evidence

    # --------------------------------------------------
    # ASSIGNMENT
    # username = input()
    # name = username
    # query = "... " + name
    # --------------------------------------------------

    def visit_Assign(self, node):

        target_names = []

        for target in node.targets:
            target_names.extend(
                self.get_target_names(target)
            )

        # ==============================================
        # SOURCE
        # ==============================================

        if self.is_user_input_source(node.value):

            for variable in target_names:

                self.tainted.add(variable)

                self.flow[variable] = [
                    {
                        "role": "source",
                        "line": node.lineno,
                        "start_line": node.lineno,
                        "end_line": getattr(
                            node,
                            "end_lineno",
                            node.lineno
                        ),
                        "code": self.get_code_range(
                            node.lineno,
                            getattr(
                                node,
                                "end_lineno",
                                node.lineno
                            )
                        )
                    }
                ]

        # ==============================================
        # PROPAGATION
        # ==============================================

        elif self.expression_is_tainted(node.value):

            previous_flow = self.collect_previous_flow(
                node.value
            )

            propagation = {
                "role": "propagation",
                "line": node.lineno,
                "start_line": node.lineno,
                "end_line": getattr(
                    node,
                    "end_lineno",
                    node.lineno
                ),
                "code": self.get_code_range(
                    node.lineno,
                    getattr(
                        node,
                        "end_lineno",
                        node.lineno
                    )
                )
            }

            for variable in target_names:

                self.tainted.add(variable)

                self.flow[variable] = (
                    previous_flow
                    +
                    [propagation]
                )

        # ==============================================
        # SQL variable mark
        # ==============================================

        if self.expression_contains_sql(node.value):

            for variable in target_names:
                self.sql_variables.add(variable)

        self.generic_visit(node)

    # --------------------------------------------------
    # SINK detection
    # cursor.execute(query)
    # db.execute(query)
    # --------------------------------------------------

    def visit_Call(self, node):

        sink_name = ""

        if isinstance(node.func, ast.Attribute):
            sink_name = node.func.attr

        elif isinstance(node.func, ast.Name):
            sink_name = node.func.id

        sql_sinks = (
            "execute",
            "executemany",
            "executescript",
        )

        if sink_name not in sql_sinks:
            self.generic_visit(node)
            return

        if not node.args:
            self.generic_visit(node)
            return

        query_argument = node.args[0]

        # ----------------------------------------------
        # Query tainted কিনা
        # ----------------------------------------------

        tainted = self.expression_is_tainted(
            query_argument
        )

        # ----------------------------------------------
        # Query SQL কিনা
        # ----------------------------------------------

        contains_sql = self.expression_contains_sql(
            query_argument
        )

        if isinstance(query_argument, ast.Name):

            if query_argument.id in self.sql_variables:
                contains_sql = True

        # SQL + tainted data দুটোই লাগবে
        if not tainted or not contains_sql:
            self.generic_visit(node)
            return

        evidence = self.collect_previous_flow(
            query_argument
        )

        # SINK evidence
        sink_evidence = {
            "role": "sink",
            "line": node.lineno,
            "start_line": node.lineno,
            "end_line": getattr(
                node,
                "end_lineno",
                node.lineno
            ),
            "code": self.get_code_range(
                node.lineno,
                getattr(
                    node,
                    "end_lineno",
                    node.lineno
                )
            )
        }

        evidence.append(sink_evidence)

        # ----------------------------------------------
        # Exact affected lines তৈরি
        # ----------------------------------------------

        affected_lines = set()

        for item in evidence:

            start_line = item.get(
                "start_line",
                item.get("line")
            )

            end_line = item.get(
                "end_line",
                start_line
            )

            if start_line and end_line:

                for number in range(
                    start_line,
                    end_line + 1
                ):
                    affected_lines.add(number)

        affected_lines = sorted(
            affected_lines
        )

        # ----------------------------------------------
        # Source বের করা
        # ----------------------------------------------

        source_evidence = next(
            (
                item
                for item in evidence
                if item["role"] == "source"
            ),
            None
        )

        # ----------------------------------------------
        # Final advanced finding
        # ----------------------------------------------

        finding = {
            "type": "SQL Injection",
            "severity": "HIGH",

            "primary_line": node.lineno,

            "source": source_evidence,

            "sink": sink_evidence,

            "evidence": evidence,

            "affected_lines": affected_lines,

            "location": {
                "start_line": (
                    min(affected_lines)
                    if affected_lines
                    else node.lineno
                ),
                "end_line": (
                    max(affected_lines)
                    if affected_lines
                    else node.lineno
                ),
            },

            "evidence_level":
                "data_flow_confirmed",

            "description":
                "User-controlled data reaches an SQL execution sink through an unsafe query construction path."
        }

        self.findings.append(finding)

        self.generic_visit(node)


# ======================================================
# MAIN FUNCTION
# ======================================================

def analyze_python_sql_injection(code):

    try:
        tree = ast.parse(code)

    except SyntaxError as error:

        return {
            "status": "parser_error",
            "error": str(error),
            "findings": []
        }

    analyzer = PythonSQLTaintAnalyzer(code)

    analyzer.visit(tree)

    # IDs add করা
    for index, finding in enumerate(
        analyzer.findings,
        start=1
    ):
        finding["id"] = index

    return {
        "status": "success",
        "findings": analyzer.findings
    }