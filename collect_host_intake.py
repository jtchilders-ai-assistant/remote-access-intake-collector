#!/usr/bin/env python3
"""Collect non-sensitive host and listening-service metadata as intake CSV."""

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
from pathlib import Path

HEADER = "Record ID,Submission Status,Submitted By,Date Submitted,Directorate,Division or Facility,Group or Project,System Owner,System Administrator,Technical Contact,Host Name or Asset ID,FQDN,IP Address,Subnet or CIDR,Network Zone or Location,Physical or Virtual,Operating System,OS Version,Argonne Managed Host,EDR Installed,Original Block or Incident Reference,Application or Service Name,Application Purpose or Lost Capability,Application Owner,Application Criticality,Impact of Tailscale Block,Users Affected,User Population,External Collaborators or Institutions,Access Source Location,External Client Argonne Managed,Access Direction,Protocol,Port or Port Range,Transport,HTTP or HTTPS URL Path,Interactive or Machine to Machine,Authentication Method,Authorization or Group Requirements,MFA Required,Identity Provider,Data Sensitivity or Classification,Regulated or Export Controlled Data,Required Availability,Inbound File Transfer Needed,Outbound File Transfer Needed,SSH or Shell Needed,Desktop or GUI Needed,Database Access Needed,Agent or API Access Needed,Web Application Access Needed,Other Required Connectivity,Current Workaround,Workaround Limitations,Required Logging or Audit,Session Recording Required,Source IP Allowlisting Required,Fixed Client IP Required,DNS Requirements,Certificate or TLS Requirements,High Availability Required,Target Implementation Date,Preferred Open Source or On Premise Constraint,Must Not Route General Internet Traffic,Special Security Constraints,Additional Notes,Information Sensitivity Reminder".split(",")
REMINDER = "Do not enter passwords, private keys, tokens, credentials, or other secrets. Verify automatically collected and inferred values before submission."
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
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout,
                                check=False, env={"PATH": os.environ.get("PATH", "")})
        return CommandResult(result.returncode == 0, result.stdout, result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(False, "", str(exc))


def _split_endpoint(endpoint):
    endpoint = endpoint.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        address, port = endpoint[1:].rsplit("]:", 1)
    elif ":" in endpoint:
        address, port = endpoint.rsplit(":", 1)
    else:
        return endpoint, None
    try:
        return address, int(port)
    except ValueError:
        return address, None


def parse_ss(text):
    services = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        transport = parts[0].upper()
        if transport not in ("TCP", "UDP"):
            continue
        endpoint_index = 4 if transport == "TCP" else 4
        if len(parts) <= endpoint_index:
            continue
        address, port = _split_endpoint(parts[endpoint_index])
        if port is None:
            continue
        match = re.search(r'users:\(\("([^"\n]+)"', line)
        services.append({"transport": transport, "address": address,
                         "port": port, "process": match.group(1) if match else "unknown"})
    return services


def parse_lsof(text):
    services = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("COMMAND "):
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        match = re.search(r"\b(TCP|UDP)\s+(.+?)(?:\s+\(LISTEN\))?$", line)
        if not match:
            continue
        transport, endpoint = match.groups()
        if "->" in endpoint:
            continue
        address, port = _split_endpoint(endpoint)
        if port is None:
            continue
        services.append({"transport": transport, "address": address,
                         "port": port, "process": parts[0] or "unknown"})
    return services


def deduplicate_services(services):
    grouped = {}
    for service in services:
        key = (service["transport"].upper(), int(service["port"]), service.get("process") or "unknown")
        grouped.setdefault(key, set()).add(service.get("address") or "unknown")
    result = []
    for (transport, port, process), addresses in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
        result.append({"transport": transport, "port": port, "process": process,
                       "address": "; ".join(sorted(addresses))})
    return result


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


def discover_host():
    system_name = platform.system() or "Unknown"
    addresses = discover_addresses(system_name)
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "ips": sorted({item[1] for item in addresses}),
        "cidrs": sorted({item[2] for item in addresses}),
        "interfaces": sorted({item[0] for item in addresses}),
        "os": system_name,
        "os_version": platform.platform(),
        "physical_virtual": detect_virtualization(system_name),
    }


def discover_services(system_name):
    diagnostics = []
    if system_name == "Linux":
        result = run_command(["ss", "-H", "-lntup"])
        if result.ok:
            return deduplicate_services(parse_ss(result.stdout)), diagnostics
        diagnostics.append("ss unavailable or failed")
        result = run_command(["netstat", "-lntup"])
        if result.ok:
            return deduplicate_services(parse_ss(result.stdout)), diagnostics
        diagnostics.append("netstat fallback unavailable or failed")
    elif system_name == "Darwin":
        result = run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP"])
        if result.ok:
            return deduplicate_services(parse_lsof(result.stdout)), diagnostics
        diagnostics.append("lsof unavailable or failed")
        diagnostics.append("netstat fallback does not safely expose process/service ownership; omitted")
    else:
        diagnostics.append("listener discovery unsupported on {}".format(system_name))
    return [], diagnostics


def _classify(service):
    port = service["port"]
    process = service["process"].lower()
    values = {}
    if port == 22 or "sshd" in process:
        values["SSH or Shell Needed"] = "Possible - inferred"
    if port in {80, 443, 8000, 8080, 8443} or any(name in process for name in ("nginx", "httpd", "apache")):
        values["Web Application Access Needed"] = "Possible - inferred"
        values["HTTP or HTTPS URL Path"] = "Scheme inferred as HTTPS" if port in {443, 8443} else "Scheme inferred as HTTP"
    if port in {3306, 5432, 6379, 1433, 1521, 27017, 9200} or any(name in process for name in ("postgres", "mysql", "mariadb", "redis", "mongod")):
        values["Database Access Needed"] = "Possible - inferred"
    if port in {3389, 5900, 5901} or any(name in process for name in ("vnc", "screensharing")):
        values["Desktop or GUI Needed"] = "Possible - inferred"
    if any(name in process for name in ("agent", "ollama", "vllm")):
        values["Agent or API Access Needed"] = "Possible - inferred"
    return values


def build_rows(host, services, collection_notes=None):
    collection_notes = collection_notes or []
    source = services or [None]
    rows = []
    for service in source:
        row = blank_row()
        row.update({
            "Submission Status": "Needs owner review",
            "Host Name or Asset ID": host.get("hostname", ""),
            "FQDN": host.get("fqdn", ""),
            "IP Address": "; ".join(host.get("ips", [])),
            "Subnet or CIDR": "; ".join(host.get("cidrs", [])),
            "Network Zone or Location": "Interfaces: " + "; ".join(host.get("interfaces", [])) if host.get("interfaces") else "",
            "Physical or Virtual": host.get("physical_virtual", ""),
            "Operating System": host.get("os", ""),
            "OS Version": host.get("os_version", ""),
            "Information Sensitivity Reminder": REMINDER,
        })
        notes = ["Automatically collected; verify all values before submission."] + list(collection_notes)
        if service:
            row.update({
                "Application or Service Name": service.get("process", "unknown"),
                "Access Direction": "Inbound to host (listener detected)",
                "Protocol": service["transport"],
                "Port or Port Range": str(service["port"]),
                "Transport": service["transport"],
            })
            row.update(_classify(service))
            notes.append("Inferred from local listening socket bound to {}.".format(service.get("address", "unknown")))
            notes.append("Detection does not prove this service was accessed through Tailscale.")
        else:
            notes.append("No listening services collected; host-only row.")
        row["Additional Notes"] = " ".join(notes)
        rows.append(row)
    return rows


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", action="store_true", help="include the 67-column header")
    parser.add_argument("--output", metavar="FILE", help="atomically write CSV to FILE")
    parser.add_argument("--no-listeners", action="store_true", help="skip listener/process discovery")
    args = parser.parse_args(argv)
    try:
        host = discover_host()
        services, diagnostics = ([], ["Listener discovery disabled by --no-listeners."]) if args.no_listeners else discover_services(host["os"])
        for diagnostic in diagnostics:
            print("notice: " + diagnostic, file=sys.stderr)
        text = render_csv(build_rows(host, services, diagnostics), include_header=args.header)
        if args.output:
            write_atomic(args.output, text)
        else:
            sys.stdout.write(text)
        return 0
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
