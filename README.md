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
- Email address
- Directorate
- Division or facility
- Group or project
- Whether the host is Argonne managed
- Application or service used with Tailscale, with an example
- Application purpose or capability lost without Tailscale, with an example
- Impact of the Tailscale block, with an example
- Access source location: `Outside ANL`, `Inside ANL`, or `Mobile/Laptop`
- Protocol, such as HTTP, HTTPS, or SSH
- Port or port range, or `Unknown`
- Transport, such as TCP or UDP, or `Unknown`
- HTTP/HTTPS URL path, or `N/A`
- Additional notes, or `None`

`Date Submitted` is filled automatically with the local system date when the script runs. Hostname, validated FQDN, addresses, subnets, interfaces, OS, and OS version are collected automatically. Reverse-DNS `.arpa` artifacts are rejected as FQDNs.

All use-case fields are collected directly from the respondent. No application, protocol, or port is inferred from local listeners.

## Noninteractive use

Every question has a corresponding option:

```bash
python3 collect_host_intake.py --header --output host-intake.csv \
  --submitted-by "Taylor Childers" \
  --email "jchilders@anl.gov" \
  --directorate CELS \
  --division ALCF \
  --group-project "Agent project" \
  --argonne-managed Yes \
  --application "Hermes HTTP agent" \
  --purpose "Build and test software remotely" \
  --impact "Compute nodes can no longer reach the service" \
  --access-source "Mobile/Laptop" \
  --protocol HTTPS \
  --port 443 \
  --transport TCP \
  --url-path /api \
  --additional-notes "Access originated from ALCF compute nodes"
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
