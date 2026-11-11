"""
Validate rules 100210/100212 with the real Wazuh engine, before and after
deploying a new local_rules.xml. Runs ON THE MANAGER, as root:

    sudo python3 run_engine_test.py /tmp/nimbrek/local_rules.xml

Why not wazuh-logtest: in Wazuh 4.9.2, Windows events are decoded by
DecodeWinevt (src/analysisd/decoders/winevtchannel.c), which analysisd calls
only for messages from the eventchannel queue (type 'f'). wazuh-logtest builds
every event as a generic message (src/analysisd/logtest.c,
w_logtest_preprocessing_phase: "1:<location>:<event>") and never calls it, so
rule 60000 (<decoded_as>windows_eventchannel</decoded_as>) and everything below
it cannot match there.

What this does instead: it sends the event to analysisd's own input socket
(/var/ossec/queue/sockets/queue) as an eventchannel message, the same message
type the agent's events arrive as, so the real decoder and the loaded rules
process it, and reads the result from alerts.json.

1. Samples: the latest 100212 alert (4769, svc_sql_backup, RC4, ipAddress ::1)
   and the latest AES 4769, both from this manager's alerts.json. The event is
   rebuilt as Windows XML from the alert's data.win fields.
2. Fidelity check: the rebuilt honeytoken event is injected; the alert it
   produces must carry the same data.win fields as the original (except
   eventRecordID, used as a marker). Otherwise the test stops.
3. Before: four samples are injected with the rules loaded now:
     honeytoken-loopback  ipAddress ::1                     (as captured)
     honeytoken-dc-fqdn   ipAddress ::ffff:192.168.56.10    (address edited)
     honeytoken-network   ipAddress ::ffff:192.168.56.103   (address edited: Kali)
     aes-legit            the captured AES ticket
   A sample taken by a level-0 rule writes no alert ("no alert").
4. The new local_rules.xml is installed (backup kept), checked with
   wazuh-analysisd -t, and the manager restarted. The samples are injected
   again ("after").
5. Expected after: the three honeytoken samples end in 100212, aes-legit never
   reaches 100210/100211/100212. Otherwise the previous rules are restored.

Injected events are real alerts on agent 000 (the manager), with
eventRecordID 9xxxxxxxxx. Stop the AI feed while this runs.
Results: printed and written to engine_test_results.json next to this script.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from xml.sax.saxutils import escape, quoteattr

OSSEC = "/var/ossec"
ALERTS = f"{OSSEC}/logs/alerts/alerts.json"
RULES = f"{OSSEC}/etc/rules/local_rules.xml"
QUEUE = f"{OSSEC}/queue/sockets/queue"
AQUI = os.path.dirname(os.path.abspath(__file__))
HONEY = ("honeytoken-loopback", "honeytoken-dc-fqdn", "honeytoken-network")
# System fields as XML elements (data.win.system key -> element); others are attributes.
SIS_ELEM = [("eventID", "EventID"), ("version", "Version"), ("level", "Level"), ("task", "Task"),
            ("opcode", "Opcode"), ("keywords", "Keywords")]
SIS_TAIL = [("channel", "Channel"), ("computer", "Computer")]


def a_xml(win, record_id, ip=None):
    s, ed = win["system"], dict(win["eventdata"])
    if ip:
        ed["ipAddress"], ed["ipPort"] = ip, "50123"
    x = ["<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>",
         f"<Provider Name={quoteattr(s['providerName'])} Guid={quoteattr(s.get('providerGuid', ''))}/>"]
    x += [f"<{e}>{escape(s[k])}</{e}>" for k, e in SIS_ELEM if k in s]
    x.append(f"<TimeCreated SystemTime={quoteattr(s.get('systemTime', ''))}/>")
    x.append(f"<EventRecordID>{record_id}</EventRecordID><Correlation/>")
    x.append(f"<Execution ProcessID={quoteattr(s.get('processID', '0'))} ThreadID={quoteattr(s.get('threadID', '0'))}/>")
    x += [f"<{e}>{escape(s[k])}</{e}>" for k, e in SIS_TAIL if k in s]
    x.append("<Security/></System><EventData>")
    x += [f"<Data Name={quoteattr(k[0].upper() + k[1:])}>{escape(v)}</Data>" for k, v in ed.items()]
    x.append("</EventData></Event>")
    return json.dumps({"Message": s.get("message", ""), "Event": "".join(x)})


def muestras():
    honey = aes = None
    with open(ALERTS, encoding="utf-8", errors="replace") as f:
        for linea in f:
            if '"4769"' not in linea:
                continue
            try:
                a = json.loads(linea)
            except ValueError:
                continue
            win = a.get("data", {}).get("win", {})
            ed = win.get("eventdata", {})
            if str(win.get("system", {}).get("eventRecordID", "")).startswith("9"):
                continue                                   # our own injected events
            if a.get("rule", {}).get("id") == "100212" and ed.get("ipAddress") == "::1":
                honey = win
            elif ed.get("ticketEncryptionType") == "0x12":
                aes = win
    if not honey or not aes:
        sys.exit("alerts.json no tiene una 100212 desde ::1 y un 4769 AES de hoy. "
                 "Generá una con klist en DC01 y volvé a correr.")
    return honey, aes


class Inyector:
    def __init__(self):
        self.n = int(time.time()) % 100000000

    def marca(self):
        self.n += 1
        return 9000000000 + self.n

    def enviar(self, payload):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.sendto(f"f:EventChannel:{payload}".encode(), QUEUE)
        s.close()


def resultado(marcas, desde, espera=15):
    """alerts.json lines written after offset `desde` that carry each marker."""
    fin, vistos = time.time() + espera, {}
    while time.time() < fin and len(vistos) < len(marcas):
        with open(ALERTS, encoding="utf-8", errors="replace") as f:
            f.seek(desde)
            for linea in f:
                for nombre, m in marcas.items():
                    if f'"eventRecordID":"{m}"' in linea:
                        vistos[nombre] = json.loads(linea)
        time.sleep(1)
    return vistos


def correr(etiqueta, inj, honey, aes):
    casos = {"honeytoken-loopback": (honey, None), "honeytoken-dc-fqdn": (honey, "::ffff:192.168.56.10"),
             "honeytoken-network": (honey, "::ffff:192.168.56.103"), "aes-legit": (aes, None)}
    desde = os.path.getsize(ALERTS)
    marcas = {}
    for nombre, (win, ip) in casos.items():
        marcas[nombre] = inj.marca()
        inj.enviar(a_xml(win, marcas[nombre], ip))
    vistos = resultado(marcas, desde)
    res = {}
    for nombre in casos:
        a = vistos.get(nombre)
        r = {"marca": marcas[nombre], "regla": a and a["rule"]["id"], "nivel": a and a["rule"]["level"],
             "ipAddress": a and a["data"]["win"]["eventdata"].get("ipAddress")}
        res[nombre] = r
        print(f"  [{etiqueta}] {nombre:20s} -> " +
              (f"regla {r['regla']} nivel {r['nivel']} ({r['ipAddress']})" if a else "sin alerta (regla nivel 0 o descartado)"))
    return res


def fidelidad(inj, honey):
    m = inj.marca()
    desde = os.path.getsize(ALERTS)
    inj.enviar(a_xml(honey, m))
    a = resultado({"x": m}, desde).get("x")
    if not a:
        return False, "el evento reconstruido no produjo alerta"
    w = a["data"]["win"]
    dif = [k for k in honey["eventdata"] if honey["eventdata"][k] != w["eventdata"].get(k)]
    dif += [k for k in ("eventID", "providerName", "channel", "keywords", "severityValue")
            if honey["system"].get(k) != w["system"].get(k)]
    return not dif, (f"regla {a['rule']['id']}; campos distintos: {dif}" if dif else f"regla {a['rule']['id']}; campos idénticos")


def reiniciar():
    t = subprocess.run([f"{OSSEC}/bin/wazuh-analysisd", "-t"], capture_output=True, text=True)
    if t.returncode != 0:
        print(t.stdout[-800:], t.stderr[-800:])
        return False
    if subprocess.run(["systemctl", "restart", "wazuh-manager"]).returncode != 0:
        return False
    fin = time.time() + 180
    while time.time() < fin and not os.path.exists(QUEUE):
        time.sleep(2)
    time.sleep(20)  # let analysisd load the ruleset and open its queue
    return os.path.exists(QUEUE)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        sys.exit(__doc__)
    honey, aes = muestras()
    inj = Inyector()
    ok, nota = fidelidad(inj, honey)
    print(f"== Fidelidad de la reconstrucción: {'OK' if ok else 'FALLA'} ({nota})")
    if not ok:
        sys.exit("La reconstrucción no reproduce el evento original; no se sigue.")
    print("== Antes (reglas instaladas ahora)")
    antes = correr("antes", inj, honey, aes)
    respaldo = f"{RULES}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(RULES, respaldo)
    shutil.copyfile(sys.argv[1], RULES)
    shutil.chown(RULES, "wazuh", "wazuh")
    os.chmod(RULES, 0o660)
    print(f"== Reglas nuevas instaladas (respaldo {respaldo}); reiniciando el manager...")
    despues, instalada = None, False
    if reiniciar():
        print("== Después")
        despues = correr("después", inj, honey, aes)
        instalada = (all(despues[n]["regla"] == "100212" for n in HONEY)
                     and despues["aes-legit"]["regla"] not in ("100210", "100211", "100212"))
    if not instalada:
        print("!! No se cumplió lo esperado: restaurando las reglas anteriores.")
        shutil.copyfile(respaldo, RULES)
        reiniciar()
    out = {"momento_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "fidelidad": nota,
           "instalada": instalada, "respaldo": respaldo, "antes": antes, "despues": despues,
           "muestra_honeytoken": a_xml(honey, 0), "muestra_aes": a_xml(aes, 0)}
    ruta = os.path.join(AQUI, "engine_test_results.json")
    with open(ruta, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    os.chmod(ruta, 0o644)
    print(f"\n{'OK: reglas nuevas instaladas y validadas' if instalada else 'FALLÓ: reglas anteriores restauradas'}"
          f" | {ruta}")
    return 0 if instalada else 1


if __name__ == "__main__":
    sys.exit(main())
