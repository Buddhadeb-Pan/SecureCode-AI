import re


class CCppBufferOverflowAnalyzer:

    def __init__(self, code):
        self.code = code
        self.lines = code.split("\n")

        # buffer_name -> information
        self.buffers = {}

        self.findings = []


    # =====================================================
    # FIXED BUFFER DECLARATION
    # =====================================================

    def detect_buffers(self):

        pattern = re.compile(
            r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]"
        )

        for line_number, line in enumerate(
            self.lines,
            start=1
        ):

            match = pattern.search(line)

            if not match:
                continue

            name = match.group(1)
            size = int(match.group(2))

            self.buffers[name] = {
                "name": name,
                "size": size,
                "line": line_number,
                "code": line.strip(),
            }


    # =====================================================
    # CREATE FINDING
    # =====================================================

    def add_finding(
        self,
        buffer_name,
        sink_line,
        sink_code,
        sink_type,
        description,
        confidence,
        evidence_level="buffer_overflow_risk_confirmed",
    ):

        buffer_info = self.buffers.get(
            buffer_name
        )

        if not buffer_info:
            return

        declaration_line = buffer_info["line"]

        evidence = [
            {
                "role": "buffer_declaration",
                "line": declaration_line,
                "code": buffer_info["code"],
                "buffer": buffer_name,
                "buffer_size": buffer_info["size"],
            },
            {
                "role": "unsafe_write",
                "line": sink_line,
                "code": sink_code.strip(),
                "sink": sink_type,
            },
        ]

        affected_lines = sorted(
            {
                declaration_line,
                sink_line,
            }
        )

        self.findings.append(
            {
                "type": "Buffer Overflow Risk",

                # Temporary severity.
                # Later AI/context severity system will replace this.
                "severity": "HIGH",

                "primary_line": sink_line,

                "description": description,

                "buffer": buffer_name,

                "buffer_size": buffer_info["size"],

                "source": {
                    "role": "buffer_declaration",
                    "line": declaration_line,
                    "code": buffer_info["code"],
                },

                "evidence": evidence,

                "sink": {
                    "role": "unsafe_write",
                    "line": sink_line,
                    "code": sink_code.strip(),
                    "type": sink_type,
                },

                "affected_lines": affected_lines,

                "location": {
                    "start_line": declaration_line,
                    "end_line": sink_line,
                },

                "confidence": confidence,

                "evidence_level": evidence_level,

                "analysis_method": (
                    "C/C++ Buffer Tracking + "
                    "Unsafe Write Analysis + "
                    "Boundary Analysis"
                ),
            }
        )


    # =====================================================
    # gets(buffer)
    # =====================================================

    def check_gets(self):

        pattern = re.compile(
            r"\bgets\s*\(\s*(\w+)\s*\)"
        )

        for line_number, line in enumerate(
            self.lines,
            start=1
        ):

            match = pattern.search(line)

            if not match:
                continue

            buffer_name = match.group(1)

            if buffer_name not in self.buffers:
                continue

            self.add_finding(
                buffer_name=buffer_name,
                sink_line=line_number,
                sink_code=line,
                sink_type="gets",
                description=(
                    f"gets() writes unbounded input into "
                    f"fixed-size buffer '{buffer_name}'."
                ),
                confidence=99,
            )


    # =====================================================
    # scanf("%s", buffer)
    # =====================================================

    def check_scanf(self):

        pattern = re.compile(
            r"""scanf\s*\(
            \s*["']
            [^"']*%
            (\d*)s
            [^"']*
            ["']
            \s*,\s*
            &?(\w+)
            """,
            re.VERBOSE,
        )

        for line_number, line in enumerate(
            self.lines,
            start=1
        ):

            match = pattern.search(line)

            if not match:
                continue

            width_text = match.group(1)
            buffer_name = match.group(2)

            if buffer_name not in self.buffers:
                continue

            buffer_size = self.buffers[
                buffer_name
            ]["size"]

            # scanf("%s", buffer)
            if not width_text:

                self.add_finding(
                    buffer_name=buffer_name,
                    sink_line=line_number,
                    sink_code=line,
                    sink_type="scanf",
                    description=(
                        f"scanf() uses unbounded %s input "
                        f"for fixed-size buffer "
                        f"'{buffer_name}'."
                    ),
                    confidence=98,
                )

                continue

            width = int(width_text)

            # char x[10] → maximum safe width = 9
            if width >= buffer_size:

                self.add_finding(
                    buffer_name=buffer_name,
                    sink_line=line_number,
                    sink_code=line,
                    sink_type="scanf",
                    description=(
                        f"scanf() width {width} may exceed "
                        f"safe capacity of buffer "
                        f"'{buffer_name}' "
                        f"(size {buffer_size})."
                    ),
                    confidence=99,
                )


    # =====================================================
    # cin >> buffer
    # =====================================================

    def check_cin(self):

        pattern = re.compile(
            r"\b(?:std::)?cin\s*>>\s*(\w+)"
        )

        for line_number, line in enumerate(
            self.lines,
            start=1
        ):

            match = pattern.search(line)

            if not match:
                continue

            buffer_name = match.group(1)

            if buffer_name not in self.buffers:
                continue

            self.add_finding(
                buffer_name=buffer_name,
                sink_line=line_number,
                sink_code=line,
                sink_type="cin",
                description=(
                    f"Unbounded cin input is written into "
                    f"fixed-size character buffer "
                    f"'{buffer_name}'."
                ),
                confidence=96,
            )


    # =====================================================
    # strcpy / strcat / sprintf
    # =====================================================

    def check_unsafe_copy_functions(self):

        dangerous_functions = {
            "strcpy": 97,
            "strcat": 96,
            "sprintf": 96,
        }

        for function_name, confidence in (
            dangerous_functions.items()
        ):

            pattern = re.compile(
                rf"\b{function_name}"
                rf"\s*\(\s*(\w+)"
            )

            for line_number, line in enumerate(
                self.lines,
                start=1
            ):

                match = pattern.search(line)

                if not match:
                    continue

                buffer_name = match.group(1)

                if buffer_name not in self.buffers:
                    continue

                self.add_finding(
                    buffer_name=buffer_name,
                    sink_line=line_number,
                    sink_code=line,
                    sink_type=function_name,
                    description=(
                        f"{function_name}() may write data "
                        f"without respecting the capacity "
                        f"of fixed-size buffer "
                        f"'{buffer_name}'."
                    ),
                    confidence=confidence,
                )


    # =====================================================
    # memcpy(buffer, source, SIZE)
    # =====================================================

    def check_memcpy(self):

        pattern = re.compile(
            r"\bmemcpy\s*\("
            r"\s*(\w+)\s*,"
            r"\s*[^,]+,"
            r"\s*(\d+)\s*\)"
        )

        for line_number, line in enumerate(
            self.lines,
            start=1
        ):

            match = pattern.search(line)

            if not match:
                continue

            buffer_name = match.group(1)
            write_size = int(match.group(2))

            if buffer_name not in self.buffers:
                continue

            buffer_size = self.buffers[
                buffer_name
            ]["size"]

            if write_size > buffer_size:

                self.add_finding(
                    buffer_name=buffer_name,
                    sink_line=line_number,
                    sink_code=line,
                    sink_type="memcpy",
                    description=(
                        f"memcpy() attempts to write "
                        f"{write_size} bytes into "
                        f"'{buffer_name}', whose capacity "
                        f"is only {buffer_size} bytes."
                    ),
                    confidence=99,
                    evidence_level=(
                        "buffer_overflow_confirmed"
                    ),
                )


    # =====================================================
    # ANALYZE
    # =====================================================

    def analyze(self):

        self.detect_buffers()

        self.check_gets()

        self.check_scanf()

        self.check_cin()

        self.check_unsafe_copy_functions()

        self.check_memcpy()

        return {
            "status": "success",
            "language": "C/C++",
            "findings": self.findings,
        }


def analyze_c_cpp_buffer_overflow(code):

    try:

        analyzer = CCppBufferOverflowAnalyzer(
            code
        )

        return analyzer.analyze()

    except Exception as error:

        return {
            "status": "error",
            "message": str(error),
            "findings": [],
        }