import csv
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import collect_host_intake as c


EXPECTED_HEADER = "Record ID,Submission Status,Submitted By,Date Submitted,Directorate,Division or Facility,Group or Project,System Owner,System Administrator,Technical Contact,Host Name or Asset ID,FQDN,IP Address,Subnet or CIDR,Network Zone or Location,Physical or Virtual,Operating System,OS Version,Argonne Managed Host,EDR Installed,Original Block or Incident Reference,Application or Service Name,Application Purpose or Lost Capability,Application Owner,Application Criticality,Impact of Tailscale Block,Users Affected,User Population,External Collaborators or Institutions,Access Source Location,External Client Argonne Managed,Access Direction,Protocol,Port or Port Range,Transport,HTTP or HTTPS URL Path,Interactive or Machine to Machine,Authentication Method,Authorization or Group Requirements,MFA Required,Identity Provider,Data Sensitivity or Classification,Regulated or Export Controlled Data,Required Availability,Inbound File Transfer Needed,Outbound File Transfer Needed,SSH or Shell Needed,Desktop or GUI Needed,Database Access Needed,Agent or API Access Needed,Web Application Access Needed,Other Required Connectivity,Current Workaround,Workaround Limitations,Required Logging or Audit,Session Recording Required,Source IP Allowlisting Required,Fixed Client IP Required,DNS Requirements,Certificate or TLS Requirements,High Availability Required,Target Implementation Date,Preferred Open Source or On Premise Constraint,Must Not Route General Internet Traffic,Special Security Constraints,Additional Notes,Information Sensitivity Reminder"


class SchemaTests(unittest.TestCase):
    def test_exact_header_and_csv_quoting(self):
        self.assertEqual(c.HEADER, next(csv.reader([EXPECTED_HEADER])))
        row = c.blank_row()
        row["Additional Notes"] = "comma, newline\nquoted"
        text = c.render_csv([row], include_header=True)
        parsed = list(csv.reader(io.StringIO(text)))
        self.assertEqual(len(parsed), 2)
        self.assertTrue(all(len(item) == 67 for item in parsed))
        self.assertEqual(parsed[1][c.HEADER.index("Additional Notes")], "comma, newline\nquoted")

    def test_data_only_omits_header(self):
        parsed = list(csv.reader(io.StringIO(c.render_csv([c.blank_row()]))))
        self.assertEqual(len(parsed), 1)
        self.assertNotEqual(parsed[0], c.HEADER)


class ListenerTests(unittest.TestCase):
    SS = '''tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=5))
udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=3,fd=6))
'''
    LSOF = '''COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
Python 123 me 4u IPv4 0x0 0t0 TCP *:8000 (LISTEN)
Python 123 me 5u IPv6 0x0 0t0 TCP *:8000 (LISTEN)
mDNSResp 4 root 6u IPv4 0x0 0t0 UDP *:5353
Browser 5 me 7u IPv4 0x0 0t0 UDP 192.0.2.10:55555->198.51.100.8:443
'''

    def test_parse_ss_and_deduplicate(self):
        services = c.deduplicate_services(c.parse_ss(self.SS))
        self.assertEqual([(x["transport"], x["port"], x["process"]) for x in services],
                         [("TCP", 22, "sshd"), ("TCP", 5432, "postgres"), ("UDP", 5353, "avahi-daemon")])

    def test_parse_lsof_and_deduplicate(self):
        services = c.deduplicate_services(c.parse_lsof(self.LSOF))
        self.assertEqual([(x["transport"], x["port"], x["process"]) for x in services],
                         [("TCP", 8000, "Python"), ("UDP", 5353, "mDNSResp")])


class AddressTests(unittest.TestCase):
    def test_linux_addresses_exclude_loopback_and_link_local(self):
        text = "1: lo inet 127.0.0.1/8 scope host lo\n2: eth0 inet 10.2.3.4/24 brd 10.2.3.255 scope global eth0\n3: eth1 inet6 fe80::1/64 scope link\n3: eth1 inet6 2001:db8::2/64 scope global\n"
        self.assertEqual(c.parse_ip_addr(text), [("eth0", "10.2.3.4", "10.2.3.0/24"), ("eth1", "2001:db8::2", "2001:db8::/64")])

    def test_macos_ifconfig_addresses(self):
        text = "en0: flags=8863<UP>\n\tinet 192.0.2.4 netmask 0xffffff00 broadcast 192.0.2.255\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n\tinet6 2001:db8::4 prefixlen 64\n"
        self.assertEqual(c.parse_ifconfig(text), [("en0", "192.0.2.4", "192.0.2.0/24"), ("en0", "2001:db8::4", "2001:db8::/64")])

    def test_command_timeout_or_missing_is_nonfatal(self):
        result = c.run_command(["definitely-not-a-real-command-xyz"], timeout=0.01)
        self.assertFalse(result.ok)
        self.assertEqual(result.stdout, "")


class RowTests(unittest.TestCase):
    HOST = {"hostname": "node1", "fqdn": "node1.example", "ips": ["10.0.0.2"], "cidrs": ["10.0.0.0/24"], "interfaces": ["eth0"], "os": "Linux", "os_version": "TestOS 1", "physical_virtual": "Virtual (detected)"}

    def test_classifies_common_services_and_leaves_judgment_blank(self):
        services = [
            {"transport": "TCP", "address": "*", "port": 22, "process": "sshd"},
            {"transport": "TCP", "address": "*", "port": 443, "process": "nginx"},
            {"transport": "TCP", "address": "127.0.0.1", "port": 5432, "process": "postgres"},
            {"transport": "TCP", "address": "*", "port": 3389, "process": "unknown"},
            {"transport": "TCP", "address": "*", "port": 9999, "process": "customd"},
        ]
        rows = c.build_rows(self.HOST, services)
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["SSH or Shell Needed"], "Possible - inferred")
        self.assertEqual(rows[1]["Web Application Access Needed"], "Possible - inferred")
        self.assertEqual(rows[2]["Database Access Needed"], "Possible - inferred")
        self.assertEqual(rows[3]["Desktop or GUI Needed"], "Possible - inferred")
        self.assertEqual(rows[4]["Application or Service Name"], "customd")
        for row in rows:
            self.assertEqual(row["System Owner"], "")
            self.assertEqual(row["Impact of Tailscale Block"], "")
            self.assertIn("Automatically collected", row["Additional Notes"])

    def test_empty_services_yields_host_only_row(self):
        rows = c.build_rows(self.HOST, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Host Name or Asset ID"], "node1")
        self.assertEqual(rows[0]["Port or Port Range"], "")


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "collect_host_intake.py"), *args], text=True, capture_output=True, timeout=20)

    def test_header_no_listeners_stdout(self):
        result = self.run_cli("--header", "--no-listeners")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = list(csv.reader(io.StringIO(result.stdout)))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], c.HEADER)
        self.assertTrue(all(len(row) == 67 for row in rows))

    def test_atomic_output(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "result.csv"
            result = self.run_cli("--header", "--no-listeners", "--output", str(target))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            with target.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(len(row) == 67 for row in rows))

    def test_invalid_output_path_fails_without_csv_on_stdout(self):
        result = self.run_cli("--output", "/definitely/missing/path/result.csv", "--no-listeners")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("error:", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
