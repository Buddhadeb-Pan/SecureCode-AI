import ast


class PythonCommandTaintAnalyzer(ast.NodeVisitor):

    def __init__(self, code):
        self.code = code
        self.lines = code.splitlines()

        # User-controlled variables
        self.tainted = set()

        # Properly sanitized variables
        self.sanitized = set()

        # Variable -> source/propagation evidence
        self.flow = {}

        # Final vulnerabilities
        self.findings = []


    # ==================================================
    # BASIC HELPERS
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

        line_number = getattr(
            node,
            "lineno",
            None
        )

        if (
            line_number
            and 1 <= line_number <= len(self.lines)
        ):
            return self.lines[line_number - 1]

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
    # SOURCE DETECTION
    # ==================================================

    def is_source_call(self, node):

        if not isinstance(node, ast.Call):
            return False

        name = self.get_full_name(
            node.func
        )

        sources = {
            "input",
            "request.args.get",
            "request.form.get",
            "request.values.get",
            "request.cookies.get",
            "request.get_json",
            "request.json.get",
        }

        return name in sources


    def is_source_subscript(self, node):

        if not isinstance(
            node,
            ast.Subscript
        ):
            return False

        name = self.get_full_name(
            node.value
        )

        return name == "sys.argv"


    # ==================================================
    # SANITIZER DETECTION
    # ==================================================

    def is_sanitizer_call(self, node):

        if not isinstance(node, ast.Call):
            return False

        name = self.get_full_name(
            node.func
        )

        # shlex.quote() is designed for shell escaping
        return name in {
            "shlex.quote",
        }


    # ==================================================
    # TAINT CHECK
    # ==================================================

    def expression_is_tainted(self, node):

        if node is None:
            return False


        # Direct user-controlled source
        if self.is_source_call(node):
            return True

        if self.is_source_subscript(node):
            return True


        # Variable
        if isinstance(node, ast.Name):

            if node.id in self.sanitized:
                return False

            return node.id in self.tainted


        # String concatenation
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


        # f-string
        if isinstance(node, ast.JoinedStr):

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


        # Function / method call
        if isinstance(node, ast.Call):

            # Proper sanitizer removes taint
            if self.is_sanitizer_call(node):
                return False


            # Example:
            # username.strip()
            # strip() does NOT make shell input safe
            if isinstance(
                node.func,
                ast.Attribute
            ):

                if self.expression_is_tainted(
                    node.func.value
                ):
                    return True


            for argument in node.args:

                if self.expression_is_tainted(
                    argument
                ):
                    return True


            for keyword in node.keywords:

                if self.expression_is_tainted(
                    keyword.value
                ):
                    return True

            return False


        # List / tuple / set
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


        # Dictionary
        if isinstance(node, ast.Dict):

            return any(
                self.expression_is_tainted(value)
                for value in node.values
                if value is not None
            )


        # Array/subscript access
        if isinstance(node, ast.Subscript):

            if self.is_source_subscript(node):
                return True

            return self.expression_is_tainted(
                node.value
            )


        return False


    # ==================================================
    # FLOW COLLECTION
    # ==================================================

    def collect_parent_flow(self, node):

        evidence = []

        for child in ast.walk(node):

            if isinstance(child, ast.Name):

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
        assignment_node
    ):

        # Example:
        # safe_name = shlex.quote(username)
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

            # Variable may have previously been tainted
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

        self.sanitized.discard(
            variable_name
        )


        previous_flow = (
            self.collect_parent_flow(value)
        )


        # Direct source assignment
        if (
            self.is_source_call(value)
            or
            self.is_source_subscript(value)
        ):

            current_evidence = (
                self.create_evidence(
                    assignment_node,
                    "source",
                    "User-controlled data enters the program."
                )
            )

        else:

            current_evidence = (
                self.create_evidence(
                    assignment_node,
                    "propagation",
                    "User-controlled data is propagated into another value."
                )
            )


        flow = list(
            previous_flow
        )

        if current_evidence not in flow:
            flow.append(
                current_evidence
            )

        self.flow[
            variable_name
        ] = flow


    # ==================================================
    # ASSIGNMENTS
    # ==================================================

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
    # COMMAND SINK DETECTION
    # ==================================================

    def has_shell_true(self, node):

        for keyword in node.keywords:

            if keyword.arg == "shell":

                if isinstance(
                    keyword.value,
                    ast.Constant
                ):

                    return (
                        keyword.value.value
                        is True
                    )

        return False


    def is_explicit_shell_command(
        self,
        argument
    ):

        if not isinstance(
            argument,
            (
                ast.List,
                ast.Tuple,
            )
        ):
            return False

        if len(argument.elts) < 2:
            return False


        first = argument.elts[0]
        second = argument.elts[1]


        if not (
            isinstance(
                first,
                ast.Constant
            )
            and
            isinstance(
                second,
                ast.Constant
            )
        ):
            return False


        shell_name = str(
            first.value
        ).lower()

        shell_flag = str(
            second.value
        ).lower()


        shells = {
            "sh",
            "bash",
            "zsh",
            "cmd",
            "cmd.exe",
            "powershell",
            "powershell.exe",
        }

        flags = {
            "-c",
            "/c",
            "-command",
        }


        return (
            shell_name in shells
            and
            shell_flag in flags
        )


    def is_command_sink(self, node):

        if not isinstance(node, ast.Call):
            return False

        name = self.get_full_name(
            node.func
        )


        # Always shell-based command execution
        if name in {
            "os.system",
            "os.popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }:

            return True


        # subprocess becomes dangerous
        # when shell=True
        subprocess_sinks = {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        }


        if name in subprocess_sinks:

            if self.has_shell_true(
                node
            ):
                return True


            if (
                node.args
                and
                self.is_explicit_shell_command(
                    node.args[0]
                )
            ):
                return True


        return False


    # ==================================================
    # COMMAND INJECTION ANALYSIS
    # ==================================================

    def visit_Call(self, node):

        if self.is_command_sink(node):

            if node.args:

                command_argument = (
                    node.args[0]
                )


                # Only confirmed when tainted input
                # reaches command execution
                if self.expression_is_tainted(
                    command_argument
                ):

                    evidence = []


                    # Variable passed directly
                    if isinstance(
                        command_argument,
                        ast.Name
                    ):

                        evidence.extend(
                            self.flow.get(
                                command_argument.id,
                                []
                            )
                        )

                    else:

                        evidence.extend(
                            self.collect_parent_flow(
                                command_argument
                            )
                        )


                    sink_evidence = (
                        self.create_evidence(
                            node,
                            "sink",
                            (
                                "User-controlled data "
                                "reaches a shell or operating-system "
                                "command execution sink."
                            )
                        )
                    )


                    # Prevent duplicate sink
                    if sink_evidence not in evidence:
                        evidence.append(
                            sink_evidence
                        )


                    source_evidence = None

                    for item in evidence:

                        if (
                            item.get("role")
                            == "source"
                        ):
                            source_evidence = item
                            break


                    affected_lines = set()

                    for item in evidence:

                        start = item.get(
                            "start_line",
                            item.get(
                                "line",
                                0
                            )
                        )

                        end = item.get(
                            "end_line",
                            start
                        )

                        if start:

                            for line in range(
                                start,
                                end + 1
                            ):

                                affected_lines.add(
                                    line
                                )


                    finding = {
                        "type":
                            "Command Injection",

                        "severity":
                            "CRITICAL",

                        "primary_line":
                            getattr(
                                node,
                                "lineno",
                                0
                            ),

                        "description":
                            (
                                "User-controlled data reaches "
                                "a command execution sink through "
                                "an unsafe command construction path."
                            ),

                        "source":
                            source_evidence,

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
                                (
                                    min(
                                        affected_lines
                                    )
                                    if affected_lines
                                    else getattr(
                                        node,
                                        "lineno",
                                        0
                                    )
                                ),

                            "end_line":
                                (
                                    max(
                                        affected_lines
                                    )
                                    if affected_lines
                                    else getattr(
                                        node,
                                        "end_lineno",
                                        getattr(
                                            node,
                                            "lineno",
                                            0
                                        )
                                    )
                                ),
                        },

                        "evidence_level":
                            "data_flow_confirmed",

                        "analysis_method":
                            (
                                "AST + Variable Tracking "
                                "+ Taint Analysis"
                            ),
                    }


                    self.findings.append(
                        finding
                    )


        self.generic_visit(node)


# ==================================================
# PUBLIC FUNCTION
# ==================================================

def analyze_python_command_injection(code):

    try:

        tree = ast.parse(code)

    except SyntaxError as error:

        return {
            "status":
                "parser_error",

            "error":
                str(error),

            "findings":
                [],
        }


    analyzer = PythonCommandTaintAnalyzer(
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
        "status":
            "success",

        "findings":
            analyzer.findings,
    }