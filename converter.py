import argparse
import json
import sys
from pathlib import Path

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert git-secrets output to SARIF 2.1.0"
    )
    parser.add_argument("--input", required=True, help="Path to git-secrets output file")
    parser.add_argument("--output", required=True, help="Path to SARIF file to write")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.is_file():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        return 1

    # Read git-secrets output
    raw_output = input_path.read_text(encoding="utf-8", errors="replace")

    # Parse into SARIF results
    results = parse_git_secrets_output(raw_output)

    sarif_log = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "git-secrets",
                        "version": "unknown",
                        "informationUri": "https://github.com/awslabs/git-secrets",
                        "rules": [
                            {
                                "id": "git-secrets.detected-secret",
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

    output_path.write_text(json.dumps(sarif_log, indent=2))
    return 0


def parse_git_secrets_output(text: str) -> list[dict]:
    """
    Parse git-secrets output into a list of SARIF result objects.

    Expected line format (typical):
        path/to/file:LINE: rest of the line that matched

    We split on the first two ':' characters so that extra colons in the
    message don't break parsing.
    """
    results: list[dict] = []

    for raw_line in text.splitlines():
        # Skip empty / whitespace-only lines
        line = raw_line.strip()
        if not line:
            continue

        # Expect "path:line:message"
        parts = line.split(":", maxsplit=2)
        if len(parts) < 3:
            # Not in the expected format – log and skip
            print(f"WARN: Skipping malformed line: {raw_line}", file=sys.stderr)
            continue

        path_str, line_str, message = parts

        # Try to interpret the line number
        try:
            line_num = int(line_str.strip())
        except ValueError:
            print(f"WARN: Invalid line number in line: {raw_line}", file=sys.stderr)
            continue

        message_text = message.strip() or "Potential secret detected by git-secrets"

        # Build one SARIF result
        result = {
            "ruleId": "git-secrets.detected-secret",
            "level": "error",  # treat all detected secrets as high severity
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            # Use the file path as-is; GitHub will treat this as relative to repo root
                            "uri": path_str.strip(),
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                # GitHub uses this to map to severity in the UI
                "security-severity": "9.0",
            },
        }

        results.append(result)

    return results


if __name__ == "__main__":
    raise SystemExit(main())
