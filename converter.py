#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

RULE_ID = "git-secrets.detected-secret"


def parse_git_secrets_output(text: str):
    """
    Parse git-secrets output of the form:

        path/to/file.py:12: SOME_SECRET="value"
        .github/workflows/git-secrets-sarif.yml:32: git secrets --add 'DB_PASSWORD'

    and convert each hit into a SARIF `result` object.
    """
    results = []

    # Match: path:line: message
    line_re = re.compile(
        r"^(?P<path>.+?):(?P<line>\d+):( ?(?P<snippet>.*))?$"
    )

    for raw_line in text.splitlines():
        line = raw_line.rstrip()

        # Skip empty lines and general tool messages
        if not line:
            continue
        if line.startswith("Error:") or line.startswith("Possible mitigations:"):
            continue

        m = line_re.match(line)
        if not m:
            # Not a "file:line: message" line, ignore
            continue

        path = m.group("path").strip()
        line_num = int(m.group("line"))
        snippet = (m.group("snippet") or "").strip()

        if snippet:
            message_text = snippet
        else:
            message_text = "Potential secret detected by git-secrets."

        result = {
            "ruleId": RULE_ID,
            "ruleIndex": 0,
            "level": "error",
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            # Use forward slashes so GitHub can resolve the file
                            "uri": path.replace("\\", "/")
                        },
                        "region": {"startLine": line_num},
                    }
                }
            ],
        }
        results.append(result)

    return results


def convert(input_path: str, output_path: str):
    # Read the git-secrets plain-text output
    input_text = Path(input_path).read_text(encoding="utf-8", errors="ignore")

    results = parse_git_secrets_output(input_text)

    sarif_log = {
        # schema URL GitHub recommends
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "git-secrets",
                        "version": "unknown",
                        "informationUri": "https://github.com/awslabs/git-secrets",
                        "rules": [
                            {
                                "id": RULE_ID,
                                "name": "Detected secret",
                                "shortDescription": {
                                    "text": "Potential secret detected by git-secrets"
                                },
                                "fullDescription": {
                                    "text": "git-secrets matched a configured secret pattern."
                                },
                                "properties": {
                                    "tags": ["security", "secret-detection"],
                                    "precision": "high",
                                    "security-severity": "9.0",
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }

    Path(output_path).write_text(
        json.dumps(sarif_log, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    # Allow local testing: python converter.py [input] [output]
    input_file = sys.argv[1] if len(sys.argv) > 1 else "git-secrets-output.txt"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "git-secrets-output.sarif"
    convert(input_file, output_file)
