"""Offline unit tests (standard library only):  python3 -m unittest discover -s tests -v"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["VAPT_HOME"] = tempfile.mkdtemp(prefix="vapt-test-")
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("vapt_app", ROOT / "vapt_app.py")
v = importlib.util.module_from_spec(spec)
sys.modules["vapt_app"] = v
spec.loader.exec_module(v)


def finding(target, title="Test finding", vec=None):
    return v.make_finding(target, "t", title, vec or v.V_LOW, "/", "d", "i", "r", "e", "Phase 3")


class Cvss(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(v.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(v.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(v.cvss31(v.V_INFO), 0.0)
        self.assertIsNone(v.cvss31("garbage"))

    def test_severity_bands(self):
        self.assertEqual([v.severity(x) for x in (0, 3.9, 6.9, 8.9, 9.0)],
                         ["Informational", "Low", "Medium", "High", "Critical"])


class Naming(unittest.TestCase):
    def test_slugs(self):
        self.assertEqual(v.target_slug("http://target.com"), "target.com")
        self.assertEqual(v.target_slug("https://target.com:443/path"), "target.com")
        self.assertEqual(v.target_slug("http://127.0.0.1:3000"), "127.0.0.1_3000")
        self.assertEqual(v.report_name("target.com"), "target.com_VAPT_Report")

    def test_scope_validation(self):
        self.assertFalse(v.check_scope("notaurl")[0])
        self.assertFalse(v.check_scope("ftp://127.0.0.1")[0])
        self.assertEqual(v.check_scope("http://127.0.0.1:3000"), (True, "lab/private target"))

    def test_wordlist_whitelist(self):
        self.assertIsNone(v.safe_wordlist("/etc/passwd"))
        self.assertIsNone(v.safe_wordlist("/usr/share/wordlists/../../etc/passwd"))


class PerTargetStorage(unittest.TestCase):
    def test_findings_are_separate_and_reports_named(self):
        v.merge_findings([finding("http://a.example", "A only")], "a.example")
        v.merge_findings([finding("http://b.example:8080", "B only")], "b.example_8080")
        self.assertEqual([f["title"] for f in v.load_findings("a.example")], ["A only"])
        self.assertEqual([f["title"] for f in v.load_findings("b.example_8080")], ["B only"])
        c = v.app.test_client()
        for ext in ("html", "json"):
            r = c.get(f"/report/a.example/{ext}")
            self.assertEqual(r.status_code, 200)
            self.assertIn("a.example_VAPT_Report." + ext, r.headers["Content-Disposition"])
        self.assertEqual(c.get("/report/missing/html").status_code, 404)
        self.assertEqual(c.get("/report/..%2F..%2Fetc/html").status_code, 404)
        data = json.loads(c.get("/report/a.example/json").data)
        self.assertEqual(data["report_name"], "a.example_VAPT_Report")
        self.assertIn("Shrayan Biswas", data["generated_by"])

    def test_reopen_after_remediation(self):
        f = finding("http://r.example", "Reopen me")
        v.merge_findings([f], "r.example")
        reg = v.load_findings("r.example")
        reg[0]["status"] = "Remediated"
        v.save_findings("r.example", reg)
        v.merge_findings([finding("http://r.example", "Reopen me")], "r.example")
        self.assertEqual(v.load_findings("r.example")[0]["status"], "Reopened")


class Branding(unittest.TestCase):
    def test_credit_and_grayscale(self):
        page = v.app.test_client().get("/").data.decode()
        self.assertIn("Shrayan Biswas", page)
        self.assertIn("linkedin.com/in/shrayan-biswas-a1259225a", page)
        for src in (page, v.build_report("a.example")):
            for m in re.finditer(r"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b", src):
                h = m.group(1)
                h = "".join(c * 2 for c in h) if len(h) == 3 else h
                self.assertTrue(h[0:2] == h[2:4] == h[4:6], f"non-gray color {m.group(0)}")


if __name__ == "__main__":
    unittest.main()
