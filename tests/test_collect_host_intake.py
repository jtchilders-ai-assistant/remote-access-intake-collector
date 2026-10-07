import csv
import io
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import collect_host_intake as c

EXPECTED_HEADER = ["Record ID", "Submitted By", "Date Submitted", "Directorate", "Division or Facility", "Group or Project", "System Owner", "System Administrator", "Host Name or Asset ID", "FQDN", "IP Address", "Subnet or CIDR", "Network Zone or Location", "Physical or Virtual", "Operating System", "OS Version", "Argonne Managed Host", "Application or Service Name", "Application Purpose or Lost Capability", "Impact of Tailscale Block", "Access Source Location", "Protocol", "Port or Port Range", "Transport", "HTTP or HTTPS URL Path", "Additional Notes", "Information Sensitivity Reminder"]


class SchemaTests(unittest.TestCase):
    def test_exact_reduced_header(self):
        self.assertEqual(c.HEADER, EXPECTED_HEADER)
        self.assertEqual(len(c.HEADER), 27)
        for removed in ("Submission Status", "Technical Contact", "EDR Installed", "MFA Required"):
            self.assertNotIn(removed, c.HEADER)

    def test_csv_quoting_and_width(self):
        row = c.blank_row()
        row["Additional Notes"] = "comma, newline\nquoted"
        parsed = list(csv.reader(io.StringIO(c.render_csv([row], include_header=True))))
        self.assertEqual(parsed[0], EXPECTED_HEADER)
        self.assertTrue(all(len(item) == 27 for item in parsed))
        self.assertEqual(parsed[1][-2], "comma, newline\nquoted")


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

    def test_fqdn_rejects_reverse_dns_arpa_artifact(self):
        self.assertEqual(c.valid_fqdn("enterprise.local", "1.0.0.0.ip6.arpa"), "enterprise.local")

    def test_fqdn_accepts_normal_name(self):
        self.assertEqual(c.valid_fqdn("host", "host.example.org"), "host.example.org")


class IntakeTests(unittest.TestCase):
    HOST = {"hostname": "node1", "fqdn": "node1.example", "ips": ["10.0.0.2"], "cidrs": ["10.0.0.0/24"], "interfaces": ["eth0"], "os": "Linux", "os_version": "TestOS 1", "physical_virtual": "Virtual (detected)"}
    ANSWERS = {"submitted_by": "Taylor Childers", "directorate": "CELS", "division": "ALCF", "group_project": "Agent project", "argonne_managed": "Yes", "application": "Hermes HTTP agent", "access_source": "Inside ANL"}

    def test_builds_one_row_with_answers_and_current_date(self):
        row = c.build_row(self.HOST, self.ANSWERS, today=date(2026, 10, 7))
        self.assertEqual(row["Date Submitted"], "2026-10-07")
        self.assertEqual(row["Submitted By"], "Taylor Childers")
        self.assertEqual(row["Application or Service Name"], "Hermes HTTP agent")
        self.assertEqual(row["Access Source Location"], "Inside ANL")
        self.assertEqual(row["Host Name or Asset ID"], "node1")
        self.assertEqual(row["Protocol"], "")

    def test_prompt_retries_choice_and_collects_required_answers(self):
        answers = iter(["Taylor", "CELS", "ALCF", "Project", "maybe", "1", "Hermes", "3", "2"])
        output = io.StringIO()
        result = c.prompt_answers(input_fn=lambda _: next(answers), output=output)
        self.assertEqual(result["argonne_managed"], "Yes")
        self.assertEqual(result["access_source"], "Inside ANL")
        self.assertIn("Please enter 1 or 2", output.getvalue())


class CLITests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        return subprocess.run([sys.executable, str(ROOT / "collect_host_intake.py"), *args], input=input_text, text=True, capture_output=True, timeout=20)

    def test_noninteractive_flags_create_one_reduced_row(self):
        result = self.run_cli("--header", "--submitted-by", "Taylor", "--directorate", "CELS", "--division", "ALCF", "--group-project", "Agents", "--argonne-managed", "Yes", "--application", "Hermes", "--access-source", "Outside ANL")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = list(csv.reader(io.StringIO(result.stdout)))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(len(row) == 27 for row in rows))
        self.assertEqual(rows[1][EXPECTED_HEADER.index("Date Submitted")], date.today().isoformat())
        self.assertEqual(rows[1][EXPECTED_HEADER.index("Access Source Location")], "Outside ANL")

    def test_interactive_questions_create_one_row(self):
        result = self.run_cli("--header", input_text="Taylor\nCELS\nALCF\nAgents\n1\nHermes\n2\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = list(csv.reader(io.StringIO(result.stdout)))
        self.assertEqual(len(rows), 2)
        self.assertIn("Your name", result.stderr)
        self.assertEqual(rows[1][EXPECTED_HEADER.index("Argonne Managed Host")], "Yes")
        self.assertEqual(rows[1][EXPECTED_HEADER.index("Access Source Location")], "Inside ANL")

    def test_partial_flags_prompt_only_for_missing_fields(self):
        result = self.run_cli("--submitted-by", "Taylor", "--directorate", "CELS", input_text="ALCF\nAgents\n2\nHermes\n1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Your name", result.stderr)
        self.assertNotIn("Directorate", result.stderr)
        self.assertIn("Division or facility", result.stderr)

    def test_atomic_output(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "result.csv"
            result = self.run_cli("--header", "--output", str(target), "--submitted-by", "Taylor", "--directorate", "CELS", "--division", "ALCF", "--group-project", "Agents", "--argonne-managed", "Yes", "--application", "Hermes", "--access-source", "Inside ANL")
            self.assertEqual(result.returncode, 0, result.stderr)
            with target.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(len(row) == 27 for row in rows))


if __name__ == "__main__":
    unittest.main()
