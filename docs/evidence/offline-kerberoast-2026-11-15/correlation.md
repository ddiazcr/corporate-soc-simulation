# Correlation: Wazuh alert 100212 ↔ DC01 EventRecordID 256462

- Wazuh alert id `1794425308.5864804`, agent 004 · DC01, rule 100212 level 12
- EVTX events loaded: 583; Hayabusa detections on 89 records

## 1. Alert vs EVTX record

| Field | Wazuh alert | EVTX (Get-WinEvent) | Match |
|---|---|---|---|
| EventRecordID | `256462` | `256462` | ✅ |
| EventID | `4769` | `4769` | ✅ |
| Computer | `DC01.lab.local` | `DC01.lab.local` | ✅ |
| Event time (UTC, to the second) | `2026-11-15T21:37:36Z` | `2026-11-15T21:37:36Z` | ✅ |
| TargetUserName | `crojas@LAB.LOCAL` | `crojas@LAB.LOCAL` | ✅ |
| TargetDomainName | `LAB.LOCAL` | `LAB.LOCAL` | ✅ |
| ServiceName | `svc_sql_backup` | `svc_sql_backup` | ✅ |
| ServiceSid | `S-1-5-21-153885558-3855985122-1781076326-1114` | `S-1-5-21-153885558-3855985122-1781076326-1114` | ✅ |
| IpAddress | `::ffff:192.168.56.103` | `::ffff:192.168.56.103` | ✅ |
| IpPort | `59238` | `59238` | ✅ |
| TicketOptions | `0x40810010` | `0x40810010` | ✅ |
| TicketEncryptionType | `0x17` | `0x17` | ✅ |
| Status | `0x0` | `0x0` | ✅ |
| LogonGuid | `{eb7ee933-b7ca-449c-a396-babe91293ca4}` | `{eb7ee933-b7ca-449c-a396-babe91293ca4}` | ✅ |

**Result:** every compared field matches.

## 2. Timeline (±10 min, UTC, DC clock)

Events from client 192.168.56.103 or for account `crojas`: 11 of 159 in the window; the other 148 (machine account, local service logons) are omitted — `--all` lists them. Plus 3 record(s) only Hayabusa holds, tied by account, client or logon session.

| Time | Record | Event | Account | Service | Client IP | Encryption | Detail | Hayabusa |
|---|---|---|---|---|---|---|---|---|
| 21:29:00.905 | 256172 | 4625 | Administrator |  | 192.168.56.103 |  | type 3, NTLM, no workstation name, 0xc000006a wrong password | low · Logon Failure (Wrong Password) |
| 21:29:30.120 | 256206 | 4625 | crojas |  | 192.168.56.103 |  | type 3, NTLM, no workstation name, 0xc000006a wrong password | low · Logon Failure (Wrong Password) |
| 21:29:41.132 | 256230 | 4625 | crojas |  | 192.168.56.103 |  | type 3, NTLM, no workstation name, 0xc000006a wrong password | low · Logon Failure (Wrong Password) |
| 21:30:31.972 | 256272 | 4724 | Administrator → crojas |  |  |  | Hayabusa only (not in the native export), logon 0x9f14e | med · Password Reset By Admin |
| 21:31:04.559 | 256285 | 4624 | crojas |  | 192.168.56.103 |  | type 3, NTLM, no workstation name, logon 0x37072c | info · Logon (Network) |
| 21:31:04.620 | 256286 | 4662 | crojas |  |  |  | Hayabusa only (not in the native export), logon 0x37072c | med · Potential AD User Enumeration From Non-Machine Account |
| 21:31:04.650 | 256288 | 4771 | crojas | krbtgt/LAB.LOCAL | 192.168.56.103 |  | 0x25 clock skew (KRB_AP_ERR_SKEW), pre-auth 2 | — |
| 21:31:04.960 | 256290 | 4771 | crojas | krbtgt/LAB.LOCAL | 192.168.56.103 |  | 0x25 clock skew (KRB_AP_ERR_SKEW), pre-auth 2 | — |
| 21:31:04.996 | 256291 | 4634 | crojas |  |  |  | logon 0x37072c | info · Logoff |
| 21:37:36.252 | 256459 | 4624 | crojas |  | 192.168.56.103 |  | type 3, NTLM, no workstation name, logon 0x39e0f5 | info · Logon (Network) |
| 21:37:36.259 | 256460 | 4662 | crojas |  |  |  | Hayabusa only (not in the native export), logon 0x39e0f5 | med · Potential AD User Enumeration From Non-Machine Account |
| 21:37:36.305 | 256461 | 4768 | crojas | krbtgt | 192.168.56.103 | 0x17 (RC4) | pre-auth 2 | info · Kerberos TGT Requested |
| 21:37:36.327 | 256462 **← alert** | 4769 | crojas@LAB.LOCAL | svc_sql_backup | 192.168.56.103 | 0x17 (RC4) |  | med · Possible Kerberoasting (RC4 Kerberos Ticket Req); info · Kerberos Service Ticket Requested; med · Kerberoasting Activity - Initial Query |
| 21:37:36.341 | 256463 | 4634 | crojas |  |  |  | logon 0x39e0f5 | info · Logoff |

## 3. Facts for the analyst (counted in the window, not inferred)

- Service tickets (4769) from 192.168.56.103: 1, for 1 service(s): svc_sql_backup; RC4 among them: 1
- TGT requests (4768) from 192.168.56.103 before the alert: 1 (accounts: crojas)
- Kerberos/logon failures in the window: 5; from 192.168.56.103: 5 — Administrator 4625 type 3, NTLM, no workstation name, 0xc000006a wrong password; crojas 4625 type 3, NTLM, no workstation name, 0xc000006a wrong password; crojas 4625 type 3, NTLM, no workstation name, 0xc000006a wrong password; crojas 4771 0x25 clock skew (KRB_AP_ERR_SKEW), pre-auth 2; crojas 4771 0x25 clock skew (KRB_AP_ERR_SKEW), pre-auth 2
- Successful NTLM network logons (4624) from 192.168.56.103: 2 (accounts: crojas)
- Hayabusa detection on the alerted record: med · Possible Kerberoasting (RC4 Kerberos Ticket Req); info · Kerberos Service Ticket Requested; med · Kerberoasting Activity - Initial Query
