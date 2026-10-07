# Remote Access Intake Collector

`collect_host_intake.py` collects host metadata and one user-confirmed application use case for the remote-access requirements spreadsheet.

## Requirements

- Python 3.8 or newer
- Linux or macOS
- No Python packages or root privileges

The collector does **not** enumerate listening ports or guess which local services were used through Tailscale. It produces one row per run.

## Interactive use

```bash
python3 collect_host_intake.py --header --output host-intake.csv
```

The script asks for:

- Your name
- Directorate
- Division or facility
- Group or project
- Whether the host is Argonne managed
- Application used with Tailscale
- Access source location: `Outside ANL` or `Inside ANL`

`Date Submitted` is filled automatically with the local system date when the script runs. Hostname, validated FQDN, addresses, subnets, interfaces, OS, and OS version are collected automatically. Reverse-DNS `.arpa` artifacts are rejected as FQDNs.

The remaining fields—including application purpose, impact, protocol, port, transport, and URL path—remain blank for the respondent to complete when known.

## Noninteractive use

Every question has a corresponding option:

```bash
python3 collect_host_intake.py --header --output host-intake.csv \
  --submitted-by "Taylor Childers" \
  --directorate CELS \
  --division ALCF \
  --group-project "Agent project" \
  --argonne-managed Yes \
  --application "Hermes HTTP agent" \
  --access-source "Inside ANL"
```

If only some options are supplied, the script prompts for the missing answers.

## Review before submission

The output is an aid, not an authoritative inventory. Review the automatically collected host data and fill in the blank use-case fields before adding the row to the shared workbook.

The script is read-only and makes no network connections. It does not read application payloads, environment-variable values, credentials, configuration-file contents, process command lines, private keys, or user files.

Do not add passwords, tokens, private keys, or other secrets to the generated CSV.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile collect_host_intake.py tests/test_collect_host_intake.py
```
