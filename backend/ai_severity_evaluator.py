import json
import re

from ai_client import call_ai


VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
}


def extract_json(text):

    text = text.strip()

    text = re.sub(
        r"^```(?:json)?\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"\s*```$",
        "",
        text,
    )

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end > start:
        return json.loads(
            text[start:end + 1]
        )

    raise ValueError(
        "AI severity response is not valid JSON."
    )


def evaluate_severity_with_ai(
    code,
    language,
    findings,
):

    if not findings:
        return []


    compact_findings = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        compact_findings.append(
            {
                "id": index,
                "type": finding.get("type"),
                "line": finding.get(
                    "line",
                    finding.get(
                        "primary_line",
                        0
                    )
                ),
                "description": finding.get(
                    "description"
                ),
                "confidence": finding.get(
                    "confidence"
                ),
                "evidence_level": finding.get(
                    "evidence_level"
                ),
                "source": finding.get(
                    "source"
                ),
                "sink": finding.get(
                    "sink"
                ),
                "affected_lines": finding.get(
                    "affected_lines",
                    []
                ),
            }
        )


    system_prompt = """
You are a senior application-security risk analyst.

Evaluate the REAL severity of each supplied
security finding using the actual source-code
context and available evidence.

Do not assign severity only from the
vulnerability name.

Consider:

- attacker control
- source-to-sink data flow
- exploitability
- dangerous APIs
- sanitization
- authentication context
- authorization context
- memory corruption potential
- credential exposure
- impact
- evidence strength

Severity MUST be one of:

CRITICAL
HIGH
MEDIUM
LOW

Return ONLY valid JSON.
Do not use markdown.
"""


    user_prompt = f"""
LANGUAGE:
{language}

SOURCE CODE:
----- BEGIN CODE -----
{code}
----- END CODE -----

SECURITY FINDINGS:
{json.dumps(compact_findings, ensure_ascii=False)}

Return exactly:

{{
  "severity_results": [
    {{
      "id": 1,
      "severity": "HIGH",
      "confidence": 95,
      "exploitability": "HIGH",
      "reason": "Short context-aware reason"
    }}
  ]
}}
"""


    response = call_ai(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.1,
        max_tokens=700,
    )


    parsed = extract_json(response)

    results = parsed.get(
        "severity_results",
        []
    )


    normalized = []

    for item in results:

        severity = str(
            item.get(
                "severity",
                "MEDIUM"
            )
        ).upper()

        if severity not in VALID_SEVERITIES:
            severity = "MEDIUM"


        normalized.append(
            {
                "id": item.get("id"),
                "severity": severity,
                "severity_confidence":
                    item.get(
                        "confidence",
                        70
                    ),
                "exploitability":
                    item.get(
                        "exploitability",
                        "UNKNOWN"
                    ),
                "severity_reason":
                    item.get(
                        "reason",
                        ""
                    ),
            }
        )


    return normalized