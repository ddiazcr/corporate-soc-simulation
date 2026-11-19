"""
Tests for correlate_alert_evtx.py. SYNTHETIC fixtures only: the values mirror the
published live alert (record 256462) so the shape is realistic, but nothing here
is evidence. Real results come from the DC01 export.

Run from the investigation folder:
    python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import correlate_alert_evtx as c  # noqa: E402

EV = {"targetUserName": "crojas@LAB.LOCAL", "targetDomainName": "LAB.LOCAL", "serviceName": "svc_sql_backup",
      "serviceSid": "S-1-5-21-1-2-3-1114", "ipAddress": "::ffff:192.168.56.103", "ipPort": "59238",
      "ticketOptions": "0x40810010", "ticketEncryptionType": "0x17", "status": "0x0",
      "logonGuid": "{eb7ee933-b7ca-449c-a396-babe91293ca4}"}


def alerta(**cambios):
    ev = dict(EV, **cambios)
    return {"id": "1794425308.5864804", "rule": {"id": "100212", "level": 12},
            "agent": {"id": "004", "name": "DC01"},
            "data": {"win": {"system": {"eventID": "4769", "eventRecordID": "256462",
                                        "computer": "DC01.lab.local",
                                        "systemTime": "2026-11-15T21:37:36.3275507Z"},
                             "eventdata": ev}}}


def evento(rid, eid, t, **datos):
    return {"TimeCreated": t, "RecordId": rid, "EventId": eid, "Computer": "DC01.lab.local", "EventData": datos}


def pascal(d):
    return {k[0].upper() + k[1:]: v for k, v in d.items()}


EVENTOS = [
    evento(256455, 4768, "2026-11-15T21:37:35.9000000Z", TargetUserName="crojas",
           IpAddress="::ffff:192.168.56.103", TicketEncryptionType="0x12", Status="0x0"),
    evento(256462, 4769, "2026-11-15T21:37:36.3275507Z", **pascal(EV)),
    evento(256470, 4769, "2026-11-15T21:39:00.0000000Z", TargetUserName="DC01$@LAB.LOCAL",
           ServiceName="krbtgt", IpAddress="::1", TicketEncryptionType="0x12", Status="0x0"),
    evento(256440, 4625, "2026-11-15T21:30:00.0000000Z", TargetUserName="crojas", IpAddress="192.168.56.103",
           Status="0xc000006d", SubStatus="0xc000006a", LogonType="3", AuthenticationPackageName="NTLM",
           WorkstationName="-"),
    evento(256445, 4771, "2026-11-15T21:31:00.0000000Z", TargetUserName="crojas", ServiceName="krbtgt/LAB.LOCAL",
           IpAddress="::ffff:192.168.56.103", Status="0x25", PreAuthType="2"),
    evento(256450, 4624, "2026-11-15T21:37:36.2000000Z", TargetUserName="crojas", IpAddress="192.168.56.103",
           LogonType="3", AuthenticationPackageName="NTLM", WorkstationName="-"),
    evento(250000, 4769, "2026-11-15T20:00:00.0000000Z", ServiceName="far_away",
           IpAddress="::ffff:192.168.56.103", TicketEncryptionType="0x17", Status="0x0"),
]


def escribir(ruta, obj):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(obj, f)


class CorrelateTests(unittest.TestCase):
    def test_matching_record_passes_every_field(self):
        texto, ok = c.informe(alerta(), EVENTOS, None, 10)
        self.assertTrue(ok)
        self.assertIn("every compared field matches", texto)
        self.assertNotIn("❌", texto)

    def test_a_differing_field_is_reported_and_fails(self):
        texto, ok = c.informe(alerta(ticketEncryptionType="0x12"), EVENTOS, None, 10)
        self.assertFalse(ok)
        self.assertIn("| TicketEncryptionType | `0x12` | `0x17` | ❌ |", texto)

    def test_missing_record_is_reported_not_guessed(self):
        texto, ok = c.informe(alerta(), [e for e in EVENTOS if e["RecordId"] != 256462], None, 10)
        self.assertFalse(ok)
        self.assertIn("is not in the EVTX export", texto)

    def test_timeline_window_and_counts(self):
        texto, _ = c.informe(alerta(), EVENTOS, None, 10)
        self.assertIn("256462 **← alert**", texto)
        self.assertNotIn("far_away", texto)                    # outside ±10 min
        self.assertIn("Service tickets (4769) from 192.168.56.103: 1, for 1 service(s): svc_sql_backup; "
                      "RC4 among them: 1", texto)
        self.assertIn("TGT requests (4768) from 192.168.56.103 before the alert: 1 (accounts: crojas)", texto)

    def test_timeline_keeps_only_events_tied_to_the_client_or_account_unless_all(self):
        texto, _ = c.informe(alerta(), EVENTOS, None, 10)
        self.assertNotIn("DC01$", texto)                       # machine-account ticket omitted
        self.assertIn("5 of 6 in the window; the other 1", texto)
        texto, _ = c.informe(alerta(), EVENTOS, None, 10, todo=True)
        self.assertIn("DC01$", texto)
        self.assertIn("All 6 Kerberos/logon events", texto)

    def test_detail_translates_failure_codes_and_counts_them_per_source(self):
        texto, _ = c.informe(alerta(), EVENTOS, None, 10)
        self.assertIn("type 3, NTLM, no workstation name, 0xc000006a wrong password", texto)
        self.assertIn("0x25 clock skew (KRB_AP_ERR_SKEW), pre-auth 2", texto)
        self.assertIn("failures in the window: 2; from 192.168.56.103: 2", texto)
        self.assertIn("Successful NTLM network logons (4624) from 192.168.56.103: 1 (accounts: crojas)", texto)

    def test_hayabusa_only_records_tied_by_account_or_session_join_the_timeline(self):
        filas = [
            {"timestamp": "2026-11-15T21:30:31.972Z", "ruletitle": "Password Reset By Admin", "level": "med",
             "eventid": 4724, "recordid": 256272, "computer": "DC01.lab.local",
             "details": {"SubjectUserName": "Administrator", "TargetUserName": "crojas", "SubjectLogonId": "0x9f14e"}},
            {"timestamp": "2026-11-15T21:37:36.259Z", "ruletitle": "Potential AD User Enumeration", "level": "med",
             "eventid": 4662, "recordid": 256460, "computer": "DC01.lab.local", "details": {"User": "other", "LID": "0x39e0f5"}},
            {"timestamp": "2026-11-15T21:37:36.300Z", "ruletitle": "Unrelated", "level": "info",
             "eventid": 4662, "recordid": 256499, "computer": "DC01.lab.local", "details": {"User": "svc_backup", "LID": "0x111"}},
        ]
        hb = {"256272": ["med · Password Reset By Admin"], "256460": ["med · Potential AD User Enumeration"],
              "256499": ["info · Unrelated"]}
        eventos = [dict(e) for e in EVENTOS]
        eventos[-2] = dict(eventos[-2], EventData=dict(eventos[-2]["EventData"], TargetLogonId="0x39e0f5"))
        texto, _ = c.informe(alerta(), eventos, (hb, filas), 10)
        self.assertIn("| 256272 | 4724 | Administrator → crojas |", texto)   # tied by account (crojas)
        self.assertIn("256462 **← alert**", texto)                            # alert marker survives
        self.assertIn("Hayabusa detection on the alerted record: none", texto)
        self.assertIn("| 256460 | 4662 | other |", texto)                     # tied by logon session
        self.assertNotIn("Unrelated", texto)
        self.assertIn("Plus 2 record(s) only Hayabusa holds", texto)
        orden = [texto.index(x) for x in ("256440", "256272", "256445", "256460", "256462 **")]
        self.assertEqual(orden, sorted(orden))                                # merged in time order

    def test_hayabusa_rows_are_tied_by_whole_values_not_substrings(self):
        ses = {("dc01.lab.local", "0x39e0f5")}
        fila = lambda det, comp="DC01.lab.local": {"computer": comp, "details": det}
        r = lambda d: c.relacionado_hb(d, "crojas", "192.168.56.103", ses)
        self.assertTrue(r(fila({"TgtUser": "crojas@LAB.LOCAL"})))
        self.assertTrue(r(fila({"TargetUserName": "LAB\\CROJAS"})))
        self.assertFalse(r(fila({"TgtUser": "crojas_backup"})))                 # similar account
        self.assertFalse(r(fila({"Details": "note about crojas"})))             # not an account field
        self.assertTrue(r(fila({"SrcIP": "::ffff:192.168.56.103"})))
        self.assertFalse(r(fila({"SrcIP": "192.168.56.10"})))                   # shared prefix
        self.assertFalse(c.relacionado_hb(fila({"SrcIP": "192.168.56.103"}), "x", "192.168.56.10", set()))
        self.assertTrue(r(fila({"LID": "0x39E0F5"})))
        self.assertFalse(r(fila({"LID": "0x39e0f5"}, comp="WS01.lab.local")))   # same LogonId, other host

    def test_account_base_name(self):
        self.assertEqual({c.base_cuenta(n) for n in ("crojas@LAB.LOCAL", "LAB\\crojas", "CROJAS")}, {"crojas"})

    def test_hayabusa_jsonl_keys_are_case_insensitive_and_absence_is_explicit(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write(json.dumps({"Timestamp": "x", "RuleTitle": "Kerberoasting Activity", "Level": "med",
                                "RecordID": 256462}) + "\n")
            f.write("not json\n")
            f.write(json.dumps({"recordid": "-", "ruletitle": "correlation"}) + "\n")
        try:
            hb, filas = c.leer_hayabusa(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(hb, {"256462": ["med · Kerberoasting Activity"]})
        self.assertEqual(len(filas), 2)                        # correlation row kept, not indexed
        texto, _ = c.informe(alerta(), EVENTOS, hb, 10)
        self.assertIn("Hayabusa detection on the alerted record: med · Kerberoasting Activity", texto)
        texto, _ = c.informe(alerta(), EVENTOS, {}, 10)
        self.assertIn("none (no Hayabusa rule matched it)", texto)

    def test_seven_digit_fractions_and_offsets_parse(self):
        self.assertEqual(c.hora("2026-11-15T21:37:36.3275507Z").microsecond, 327550)
        self.assertEqual(c.hora("2026-11-15T21:37:36+00:00").second, 36)

    def test_offset_survives_the_fraction_cut_and_means_the_same_instant(self):
        local = c.hora("2026-11-15T15:37:36.3275507-06:00")      # reported by the reviewer
        self.assertIsNotNone(local.tzinfo)
        self.assertEqual(local, c.hora("2026-11-15T21:37:36.3275507Z"))
        self.assertEqual(c.hora("2026-11-11T19:28:28.602+0000"), c.hora("2026-11-11T19:28:28.602Z"))
        self.assertLess(c.hora("2026-11-15T15:37:35-06:00"), c.hora("2026-11-15T21:37:36Z"))

    def test_timestamp_without_zone_is_refused(self):
        with self.assertRaises(ValueError):
            c.hora("2026-11-15T21:37:36.123")

    def test_cli_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            pa, pe = os.path.join(d, "a.json"), os.path.join(d, "e.json")
            escribir(pa, alerta())
            with open(pe, "w", encoding="utf-8-sig") as f:        # PowerShell 5.1 writes a BOM
                json.dump(EVENTOS, f)
            self.assertEqual(c.main(["--alert", pa, "--events", pe, "--out", os.path.join(d, "o.md")]), 0)
            escribir(pa, alerta(ipAddress="::1"))
            self.assertEqual(c.main(["--alert", pa, "--events", pe, "--out", os.path.join(d, "o.md")]), 1)


if __name__ == "__main__":
    unittest.main()
