#!/usr/bin/env python3
"""Collect host metadata and one user-confirmed remote-access use case as CSV."""

import argparse
import csv
import io
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
from collections import namedtuple
from datetime import date
from pathlib import Path

HEADER = ["Record ID", "Submitted By", "Email Address", "Date Submitted", "Directorate", "Division or Facility", "Group or Project", "System Owner", "System Administrator", "Host Name or Asset ID", "FQDN", "IP Address", "Subnet or CIDR", "Network Zone or Location", "Physical or Virtual", "Operating System", "OS Version", "Argonne Managed Host", "Application or Service Name", "Application Purpose or Lost Capability", "Impact of Tailscale Block", "Access Source Location", "Protocol", "Port or Port Range", "Transport", "HTTP or HTTPS URL Path", "Additional Notes"]
CommandResult = namedtuple("CommandResult", "ok stdout stderr")


def blank_row():
    return {name: "" for name in HEADER}


def render_csv(rows, include_header=False):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    if include_header:
        writer.writerow(HEADER)
    for row in rows:
        writer.writerow([row.get(name, "") for name in HEADER])
    return output.getvalue()


def run_command(argv, timeout=5):
    try:
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, env={"PATH": os.environ.get("PATH", "")})
        return CommandResult(result.returncode == 0, result.stdout, result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(False, "", str(exc))


def _network_tuple(interface, address, prefix):
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if ip.is_loopback or ip.is_link_local:
            return None
        network = ipaddress.ip_network("{}/{}".format(ip, prefix), strict=False)
        return interface, str(ip), str(network)
    except ValueError:
        return None


def parse_ip_addr(text):
    result = []
    pattern = re.compile(r"^\d+:\s+([^\s:]+)(?:@\S+)?\s+inet(6)?\s+(\S+)/(\d+)")
    for line in text.splitlines():
        match = pattern.search(line.strip())
        if match:
            item = _network_tuple(match.group(1), match.group(3), int(match.group(4)))
            if item:
                result.append(item)
    return result


def parse_ifconfig(text):
    result = []
    interface = ""
    for line in text.splitlines():
        if line and not line[0].isspace() and ":" in line:
            interface = line.split(":", 1)[0]
            continue
        stripped = line.strip()
        v4 = re.match(r"inet\s+(\S+)\s+netmask\s+(0x[0-9a-fA-F]+|\S+)", stripped)
        if v4:
            mask = v4.group(2)
            try:
                prefix = bin(int(mask, 16)).count("1") if mask.startswith("0x") else ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
            except ValueError:
                continue
            item = _network_tuple(interface, v4.group(1), prefix)
            if item:
                result.append(item)
            continue
        v6 = re.match(r"inet6\s+(\S+)\s+prefixlen\s+(\d+)", stripped)
        if v6:
            item = _network_tuple(interface, v6.group(1), int(v6.group(2)))
            if item:
                result.append(item)
    return result


def _fallback_addresses():
    found = []
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            address = item[4][0]
            candidate = _network_tuple("unknown", address, 32 if ":" not in address else 128)
            if candidate and candidate not in found:
                found.append(candidate)
    except socket.gaierror:
        pass
    return found


def discover_addresses(system_name):
    if system_name == "Linux":
        result = run_command(["ip", "-o", "addr", "show"])
        parsed = parse_ip_addr(result.stdout) if result.ok else []
        if not parsed:
            fallback = run_command(["hostname", "-I"])
            for address in fallback.stdout.split() if fallback.ok else []:
                candidate = _network_tuple("unknown", address, 32 if ":" not in address else 128)
                if candidate:
                    parsed.append(candidate)
        return parsed or _fallback_addresses()
    if system_name == "Darwin":
        result = run_command(["ifconfig"])
        parsed = parse_ifconfig(result.stdout) if result.ok else []
        return parsed or _fallback_addresses()
    return _fallback_addresses()


def detect_virtualization(system_name):
    if system_name == "Linux":
        result = run_command(["systemd-detect-virt"])
        if result.ok and result.stdout.strip() and result.stdout.strip() != "none":
            return "Virtual (detected: {})".format(result.stdout.strip())
        if result.ok:
            return "Physical (reported)"
    if system_name == "Darwin":
        result = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
        if result.ok and "virtual" in result.stdout.lower():
            return "Virtual (detected)"
    return "Unknown"


def valid_fqdn(hostname, candidate):
    candidate = (candidate or "").strip().rstrip(".")
    if not candidate or candidate.lower().endswith(".arpa"):
        return hostname
    try:
        ipaddress.ip_address(candidate)
        return hostname
    except ValueError:
        return candidate


def discover_host():
    system_name = platform.system() or "Unknown"
    hostname = socket.gethostname()
    addresses = discover_addresses(system_name)
    return {"hostname": hostname, "fqdn": valid_fqdn(hostname, socket.getfqdn()), "ips": sorted({item[1] for item in addresses}), "cidrs": sorted({item[2] for item in addresses}), "interfaces": sorted({item[0] for item in addresses}), "os": system_name, "os_version": platform.platform(), "physical_virtual": detect_virtualization(system_name)}


def _read_prompt(prompt, input_fn, output):
    print(prompt, end="", file=output, flush=True)
    return input_fn("")


def _required(prompt, input_fn, output):
    while True:
        value = _read_prompt(prompt, input_fn, output).strip()
        if value:
            return value


def _choice(prompt, choices, input_fn, output):
    while True:
        value = _read_prompt(prompt, input_fn, output).strip()
        if value in choices:
            return choices[value]
        print("Please enter {}.".format(" or ".join(choices)), file=output)


def prompt_answers(input_fn=input, output=sys.stderr, existing=None):
    answers = dict(existing or {})
    for key, prompt in [("submitted_by", "Your name: "), ("email", "Email address: "), ("directorate", "Directorate: "), ("division", "Division or facility: "), ("group_project", "Group or project: ")]:
        if not answers.get(key):
            answers[key] = _required(prompt, input_fn, output)
    if not answers.get("argonne_managed"):
        answers["argonne_managed"] = _choice("Argonne-managed host? [1] Yes [2] No: ", {"1": "Yes", "2": "No"}, input_fn, output)
    if not answers.get("application"):
        answers["application"] = _required("Describe the application or service you used through Tailscale (example: Hermes HTTP agent): ", input_fn, output)
    for key, prompt in [
        ("purpose", "Describe its purpose or the capability lost without Tailscale (example: remotely build and test software): "),
        ("impact", "Describe the impact of the Tailscale block (example: compute nodes can no longer reach the service): "),
    ]:
        if not answers.get(key):
            answers[key] = _required(prompt, input_fn, output)
    if not answers.get("access_source"):
        answers["access_source"] = _choice("Access source location? [1] Outside ANL [2] Inside ANL [3] Mobile/Laptop: ", {"1": "Outside ANL", "2": "Inside ANL", "3": "Mobile/Laptop"}, input_fn, output)
    for key, prompt in [
        ("protocol", "Protocol used (example: HTTP, HTTPS, SSH): "),
        ("port", "Port or port range (example: 443 or 8000-8010; enter Unknown if unsure): "),
        ("transport", "Transport protocol (example: TCP or UDP; enter Unknown if unsure): "),
        ("url_path", "HTTP or HTTPS URL path (example: /api; enter N/A if not applicable): "),
        ("additional_notes", "Additional notes (example: access originated from ALCF compute nodes; enter None if there are no additional notes): "),
    ]:
        if not answers.get(key):
            answers[key] = _required(prompt, input_fn, output)
    return answers


def build_row(host, answers, today=None):
    today = today or date.today()
    row = blank_row()
    row.update({"Submitted By": answers["submitted_by"], "Email Address": answers["email"], "Date Submitted": today.isoformat(), "Directorate": answers["directorate"], "Division or Facility": answers["division"], "Group or Project": answers["group_project"], "Host Name or Asset ID": host.get("hostname", ""), "FQDN": host.get("fqdn", ""), "IP Address": "; ".join(host.get("ips", [])), "Subnet or CIDR": "; ".join(host.get("cidrs", [])), "Network Zone or Location": "Interfaces: " + "; ".join(host.get("interfaces", [])) if host.get("interfaces") else "", "Physical or Virtual": host.get("physical_virtual", ""), "Operating System": host.get("os", ""), "OS Version": host.get("os_version", ""), "Argonne Managed Host": answers["argonne_managed"], "Application or Service Name": answers["application"], "Application Purpose or Lost Capability": answers["purpose"], "Impact of Tailscale Block": answers["impact"], "Access Source Location": answers["access_source"], "Protocol": answers["protocol"], "Port or Port Range": answers["port"], "Transport": answers["transport"], "HTTP or HTTPS URL Path": answers["url_path"], "Additional Notes": answers["additional_notes"]})
    return row


def write_atomic(path, content):
    target = Path(path)
    fd, temporary = tempfile.mkstemp(prefix="." + target.name + ".", dir=str(target.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(target))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _normalize_choice(value, allowed, flag):
    if value is None:
        return None
    lookup = {item.lower(): item for item in allowed}
    normalized = lookup.get(value.lower())
    if normalized is None:
        raise ValueError("{} must be one of: {}".format(flag, ", ".join(allowed)))
    return normalized


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", action="store_true", help="include the 28-column header")
    parser.add_argument("--output", metavar="FILE", help="atomically write CSV to FILE")
    parser.add_argument("--submitted-by")
    parser.add_argument("--email")
    parser.add_argument("--directorate")
    parser.add_argument("--division")
    parser.add_argument("--group-project")
    parser.add_argument("--argonne-managed")
    parser.add_argument("--application")
    parser.add_argument("--purpose")
    parser.add_argument("--impact")
    parser.add_argument("--access-source")
    parser.add_argument("--protocol")
    parser.add_argument("--port")
    parser.add_argument("--transport")
    parser.add_argument("--url-path")
    parser.add_argument("--additional-notes")
    args = parser.parse_args(argv)
    try:
        existing = {"submitted_by": args.submitted_by, "email": args.email, "directorate": args.directorate, "division": args.division, "group_project": args.group_project, "argonne_managed": _normalize_choice(args.argonne_managed, ("Yes", "No"), "--argonne-managed"), "application": args.application, "purpose": args.purpose, "impact": args.impact, "access_source": _normalize_choice(args.access_source, ("Outside ANL", "Inside ANL", "Mobile/Laptop"), "--access-source"), "protocol": args.protocol, "port": args.port, "transport": args.transport, "url_path": args.url_path, "additional_notes": args.additional_notes}
        answers = prompt_answers(input_fn=input, output=sys.stderr, existing=existing)
        text = render_csv([build_row(discover_host(), answers)], include_header=args.header)
        if args.output:
            write_atomic(args.output, text)
        else:
            sys.stdout.write(text)
        return 0
    except (EOFError, KeyboardInterrupt):
        print("error: input cancelled", file=sys.stderr)
        return 1
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
