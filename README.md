# git-secrets SARIF converter

This GitHub Action converts [`git-secrets`](https://github.com/awslabs/git-secrets)
scan output into SARIF 2.1.0 so findings can appear in GitHub Code Scanning.

## Inputs

- `input-file` (required): Path to the git-secrets output text file.
- `output-file` (required): Path where the SARIF file will be written.

## Outputs

- `sarif-file`: Path to the generated SARIF file.
- `findings-count`: Number of findings parsed from the git-secrets output.

## Example

```yaml
- name: Convert git-secrets to SARIF
  uses: Jorshyy/git-secrets-sarif-action@v1
  with:
    input-file: git-secrets-output.txt
    output-file: results.sarif
