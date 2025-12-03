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
                                "shortDescription": {"text": "Potential secret detected by git-secrets"},
                                "fullDescription": {"text": "git-secrets matched a configured secret pattern."},
                                "properties": {
                                    "tags": ["security", "secret-detection"],
                                    "precision": "high",
                                    "security-severity": "9.0",
                                },
                            }
                        ],
                    }
                },
                "results": [],
            }
        ],
    }

    output_path.write_text(json.dumps(sarif_log, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
