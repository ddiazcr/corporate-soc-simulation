"""
Tests for rules/check_shadowing.py and for the parents of rule 100210.
No Wazuh install needed: a tiny fake ruleset stands in for the built-in rules.

Run from the repository root:
    python3 -m unittest discover -s rules/tests -v
"""
import os
import re
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
REGLAS = os.path.dirname(AQUI)
sys.path.insert(0, REGLAS)

import check_shadowing as cs  # noqa: E402

BUILTIN = """
<group name="windows,">
  <rule id="60106" level="3"><if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$|^4769$</field></rule>
  <rule id="92651" level="0"><if_sid>60106</if_sid>
    <field name="win.eventdata.ipAddress" type="pcre2">(?:[0-9]{1,3}\\.){3}[0-9]{1,3}</field></rule>
  <rule id="60194" level="0"><if_sid>60106</if_sid>
    <field name="win.system.eventID">^4624$</field></rule>
</group>
"""

NEGADO = """
<group name="windows,">
  <rule id="60106" level="3"><if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$|^4769$</field></rule>
  <rule id="91000" level="0"><if_sid>60106</if_sid>
    <field name="win.system.eventID" negate="yes">^4624$</field></rule>
  <rule id="91001" level="0"><if_sid>60106</if_sid>
    <field name="win.system.eventID" type="pcre2">^47\\d\\d$</field></rule>
  <rule id="91002" level="0"><if_sid>60106</if_sid>
    <field name="win.system.eventID">4624</field></rule>
  <rule id="91003" level="0"><if_sid>60106</if_sid>
    <field name="win.system.eventID">^4624$|
        |^4625$</field></rule>
  <rule id="91004" level="0"><if_sid>60106</if_sid>
    <field name="win.system.eventID">476</field></rule>
</group>
"""

LOCAL_VIEJA = """<rule id="100210" level="8"><if_sid>60106</if_sid>
  <field name="win.system.eventID">^4769$</field></rule>"""
LOCAL_NUEVA = """<rule id="100210" level="8"><if_sid>60106, 92651</if_sid>
  <field name="win.system.eventID">^4769$</field></rule>"""


class CheckerTests(unittest.TestCase):

    def _correr(self, local, builtin=BUILTIN):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "ruleset"))
            with open(os.path.join(d, "ruleset", "0580-fake.xml"), "w") as f:
                f.write(builtin)
            ruta = os.path.join(d, "local_rules.xml")
            with open(ruta, "w") as f:
                f.write(local)
            return cs.revisar(os.path.join(d, "ruleset"), ruta)

    def test_flags_the_level0_sibling_that_hid_the_kerberoasting_rule(self):
        hallazgos = self._correr(LOCAL_VIEJA)
        self.assertEqual([(h[0], h[1], h[2]) for h in hallazgos], [("100210", "92651", 0)])

    def test_sibling_listed_as_parent_is_no_longer_reported(self):
        self.assertEqual(self._correr(LOCAL_NUEVA), [])

    def test_sibling_that_only_takes_other_event_ids_is_ignored(self):
        # 60194 pins ^4624$ only; 100210 pins ^4769$.
        self.assertNotIn("60194", [h[1] for h in self._correr(LOCAL_VIEJA)])


    def test_negated_regex_or_inexact_event_id_filters_are_kept_for_review(self):
        """negate="yes" ^4624$ accepts a 4769; a pcre2 or unanchored filter
        cannot be read as an exact list. None of them may be skipped."""
        ids = {h[1] for h in self._correr(LOCAL_VIEJA, NEGADO)}
        # 91002: unanchored 4624 is a substring match, provably not 4769 -> skipped.
        # 91003: multi-line pattern with an empty alternative -> kept.
        # 91004: unanchored 476 is a substring of 4769 -> kept (it can match).
        self.assertEqual(ids, {"91000", "91001", "91003", "91004"})

    def test_filter_parsing(self):
        self.assertEqual(cs.ids_fijados(("", "^4624$|^4769$")), {"4624", "4769"})
        self.assertIsNone(cs.ids_fijados(("", "4624")))                 # local rule: exact only
        self.assertIsNone(cs.acepta((' negate="yes"', "^4624$")))
        self.assertIsNone(cs.acepta((' type="pcre2"', "^4624$")))
        self.assertIsNone(cs.acepta(("", "^46\\d\\d$")))
        self.assertIsNone(cs.acepta(("", "^4624$|\n   |^4625$")))
        f = cs.acepta(("", "^4624$|514"))
        self.assertTrue(f("4624") and f("5140") and not f("4769"))


class RepoRuleTests(unittest.TestCase):

    def test_100210_lists_the_builtin_siblings_a_4769_can_hit_first(self):
        with open(os.path.join(REGLAS, "local_rules.xml"), encoding="utf-8") as f:
            texto = f.read()
        cuerpo = re.search(r'<rule id="100210".*?</rule>', texto, re.S).group(0)
        padres = {x.strip() for x in re.search(r"<if_sid>([^<]+)</if_sid>", cuerpo).group(1).split(",")}
        self.assertEqual(padres, {"60106", "60119", "92651"})

    def test_reviewed_list_parses(self):
        pares = cs.revisadas(os.path.join(REGLAS, "shadowing_reviewed.txt"))
        self.assertIn(("100210", "67022"), pares)
        self.assertEqual(len(pares), 9)


if __name__ == "__main__":
    unittest.main()
