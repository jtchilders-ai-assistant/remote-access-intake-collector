# Host Intake Collector

`collect_host_intake.py` collects non-sensitive host and listening-service metadata and emits rows matching `tailscale_alternative_requirements_intake.csv`.

## Requirements

- Python 3.8 or newer
- Linux or macOS
- No Python packages and no root privileges required

Listener discovery uses `ss` on Linux and `lsof` on macOS when available. If the applicable command is missing or process information is restricted, the script degrades to a host-only row and reports the limitation on stderr.

## Run

Print rows only for pasting beneath the existing Excel header:

```bash
python3 collect_host_intake.py
```

Create a standalone CSV with the header:

```bash
python3 collect_host_intake.py --header --output host-intake.csv
```

Collect host metadata without inspecting listening sockets:

```bash
python3 collect_host_intake.py --header --no-listeners --output host-intake.csv
```

The output contains one row per unique detected transport/port/process combination. Multiple IPv4/IPv6 bind addresses are collapsed. If no service can be detected, one host-only row is emitted.

## Review before submission

The output is an aid, not an authoritative inventory. In particular:

- A listening socket does **not** prove that the service was used through Tailscale.
- Application purpose, owner, impact, users, data sensitivity, security requirements, and the needed remote-access pattern require human input.
- Broad service categories are explicitly marked `Possible - inferred`.
- Process names may be unavailable to an unprivileged user.
- Local-only listeners are reported because they may still help identify applications, but they may not have been remotely accessible.

Open the generated file and complete or correct the blank fields before adding it to the shared workbook.

## Privacy and safety boundaries

The script is read-only, runs unprivileged, and makes no network connections. It does not read application payloads, environment-variable values, credentials, configuration-file contents, command-line arguments, private keys, or user files. It invokes only fixed, read-only metadata commands with a five-second timeout.

Do not add passwords, tokens, private keys, or other secrets to the generated CSV.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile collect_host_intake.py tests/test_collect_host_intake.py
```
