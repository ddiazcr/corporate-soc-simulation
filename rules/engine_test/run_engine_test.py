"""
Validate rules 100210/100212 with the real Wazuh engine, before and after
deploying a new version of the NIMBREK rules. Runs ON THE MANAGER, as root:

    sudo python3 run_engine_test.py /tmp/nimbrek/local_rules.xml

The repository file is named local_rules.xml, but on the manager the rules may
live in another file of etc/rules (in this lab: nimbrek_rules.xml). The file
that is replaced is the one that defines the rule IDs of the new file, found
before anything changes (see destino()).

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

0. Preflight (nothing is changed yet): every rule ID of the new file must be
   defined in exactly one rule file of etc/rules, the target, and in no other
   file of etc/rules or ruleset/rules; and the new file must define every rule
   the target defines, since the target is replaced whole. Otherwise installing it would leave
   duplicated IDs, and Wazuh keeps only the first one it loads (warning 7612,
   files in alphabetical order): the test would measure whichever copy wins.
   Found on the manager 2026-11-15, when an earlier version of this script
   wrote the rules to local_rules.xml next to nimbrek_rules.xml.
   Then the manager is restarted with the rules as they are on disk, so
   "before" measures those rules and not whatever an earlier, interrupted run
   left loaded in memory.
1. Samples: the latest 100212 alert (4769, svc_sql_backup, RC4, ipAddress ::1)
   and the latest AES 4769, both from this manager's alerts.json. The event is
   rebuilt as Windows XML from the alert's data.win fields.
2. Fidelity check: the rebuilt honeytoken event is injected; in the alert it
   produces, every data.win.eventdata field of the original and the system
   fields eventID, providerName, channel, keywords and severityValue must
   match (eventRecordID is the marker). Otherwise the test stops.
3. Before: four samples are injected with the rules loaded now:
     honeytoken-loopback  ipAddress ::1                     (as captured)
     honeytoken-dc-fqdn   ipAddress ::ffff:192.168.56.10    (address edited)
     honeytoken-network   ipAddress ::ffff:192.168.56.103   (address edited: Kali)
     aes-legit            the captured AES ticket
   A sample taken by a level-0 rule writes no alert ("no alert").
4. The new file replaces the target (backup kept), is checked with
   wazuh-analysisd -t, and the manager restarted. After every restart,
   ossec.log must not report duplicated rule IDs (7612). The samples are injected
   again ("after").
5. Expected after: the three honeytoken samples end in 100212, and aes-legit
   produces an alert (positive evidence that the engine received and decoded
   it: decoder windows_eventchannel, eventID 4769) whose rule is not
   100210/100211/100212. A missing alert is a failure, not a pass.
   Otherwise - or on ANY error or interruption after the XML was replaced -
   the previous rules are restored, and the manager is checked to be working
   again (service active and an injected canary event alerted) before the
   script says so.

Injected events are real alerts on agent 000 (the manager), with
eventRecordID 9xxxxxxxxx. Stop the AI feed while this runs.
Results: printed and written to engine_test_results.json next to this script.
"""
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from xml.sax.saxutils import escape

OSSEC = "/var/ossec"
ALERTS = f"{OSSEC}/logs/alerts/alerts.json"
RULES_DIR = f"{OSSEC}/etc/rules"
RULESET_DIR = f"{OSSEC}/ruleset/rules"
RULES = None                     # target file, chosen by destino() before anything changes
OSSEC_LOG = f"{OSSEC}/logs/ossec.log"
QUEUE = f"{OSSEC}/queue/sockets/queue"
AQUI = os.path.dirname(os.path.abspath(__file__))
HONEY = ("honeytoken-loopback", "honeytoken-dc-fqdn", "honeytoken-network")
RESTART_TIMEOUT_S = 900
# System fields as XML elements (data.win.system key -> element); others are attributes.
SIS_ELEM = [("eventID", "EventID"), ("version", "Version"), ("level", "Level"), ("task", "Task"),
            ("opcode", "Opcode"), ("keywords", "Keywords")]
SIS_TAIL = [("channel", "Channel"), ("computer", "Computer")]


def attr(v):
    """XML attribute in single quotes, as Windows renders events. The decoder
    gets the XML as a JSON string (cJSON_PrintUnformatted), where double
    quotes become \\" and Wazuh's os_xml rejects Name=\\"...\\" ("Attribute
    'Name' not followed by a \\" or '"). Found on the manager 2026-11-15."""
    return "'" + escape(str(v), {"'": "&apos;"}) + "'"


def a_xml(win, record_id, ip=None):
    s, ed = win["system"], dict(win["eventdata"])
    if ip:
        ed["ipAddress"], ed["ipPort"] = ip, "50123"
    x = ["<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>",
         f"<Provider Name={attr(s['providerName'])} Guid={attr(s.get('providerGuid', ''))}/>"]
    x += [f"<{e}>{escape(s[k])}</{e}>" for k, e in SIS_ELEM if k in s]
    x.append(f"<TimeCreated SystemTime={attr(s.get('systemTime', ''))}/>")
    x.append(f"<EventRecordID>{record_id}</EventRecordID><Correlation/>")
    x.append(f"<Execution ProcessID={attr(s.get('processID', '0'))} ThreadID={attr(s.get('threadID', '0'))}/>")
    x += [f"<{e}>{escape(s[k])}</{e}>" for k, e in SIS_TAIL if k in s]
    x.append("<Security/></System><EventData>")
    x += [f"<Data Name={attr(k[0].upper() + k[1:])}>{escape(v)}</Data>" for k, v in ed.items()]
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


def ids_de(ruta):
    """Rule IDs a file defines (overwrite="yes" rules replace, they do not duplicate)."""
    with open(ruta, encoding="utf-8", errors="replace") as f:
        texto = re.sub(r"<!--.*?-->", "", f.read(), flags=re.S)
    return {m.group(2) for m in re.finditer(r"<rule\b([^>]*?)\bid=\"(\d+)\"([^>]*)>", texto)
            if 'overwrite="yes"' not in m.group(1) + m.group(3)}


def destino(nuevas):
    """The one file of etc/rules that holds the new file's rule IDs; exits on
    any ambiguity before anything is changed."""
    ids = ids_de(nuevas)
    if not ids:
        sys.exit(f"{nuevas} no define reglas.")
    con = {}
    for ruta in sorted(glob.glob(f"{RULES_DIR}/*.xml") + glob.glob(f"{RULESET_DIR}/*.xml")):
        comun = ids & ids_de(ruta)
        if comun:
            con[ruta] = comun
    locales = [r for r in con if os.path.dirname(r) == RULES_DIR]
    if len(con) != 1 or len(locales) != 1:
        detalle = "; ".join(f"{os.path.basename(r)}: {sorted(c)[:6]}" for r, c in con.items()) or "ninguno"
        sys.exit("No se puede elegir un único archivo a reemplazar sin dejar IDs duplicados "
                 f"(archivos con IDs de las reglas nuevas: {detalle}). No se cambió nada.")
    # The target is replaced whole: a rule it defines that the new file lacks
    # would be deleted with no 7612 warning to catch it (review of PR #11).
    faltan = ids_de(locales[0]) - ids
    if faltan:
        sys.exit(f"{os.path.basename(locales[0])} define reglas que {os.path.basename(nuevas)} no trae "
                 f"({sorted(faltan)[:10]}); reemplazarlo las borraría. No se cambió nada.")
    return locales[0]


def sha256(ruta):
    with open(ruta, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def avisos_duplicados(desde):
    """7612 warnings (duplicated rule ID) written to ossec.log after offset `desde`."""
    with open(OSSEC_LOG, encoding="utf-8", errors="replace") as f:
        f.seek(desde)
        return [l.strip() for l in f if "(7612)" in l]


def tam_log():
    return os.path.getsize(OSSEC_LOG)


def resultado(marcas, desde, espera=15):
    """alerts.json lines written after offset `desde` that carry each marker."""
    fin, vistos = time.time() + espera, {}
    while time.time() < fin and len(vistos) < len(marcas):
        with open(ALERTS, encoding="utf-8", errors="replace") as f:
            f.seek(desde)
            texto = f.read()
        # Only complete lines: analysisd may be in the middle of writing the
        # last one (2026-11-15: JSONDecodeError on a half-written alert).
        for linea in texto.split("\n")[:-1]:
            for nombre, m in marcas.items():
                if nombre not in vistos and f'"eventRecordID":"{m}"' in linea:
                    try:
                        vistos[nombre] = json.loads(linea)
                    except ValueError:
                        pass                      # read again on the next pass
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
             "decoder": a and a.get("decoder", {}).get("name"),
             "eventID": a and a["data"]["win"]["system"].get("eventID"),
             "ipAddress": a and a["data"]["win"]["eventdata"].get("ipAddress")}
        res[nombre] = r
        print(f"  [{etiqueta}] {nombre:20s} -> " +
              (f"regla {r['regla']} nivel {r['nivel']} ({r['ipAddress']}, decoder {r['decoder']})" if a
               else "sin alerta (regla nivel 0, descartado o no llegó)"))
    return res


def fidelidad(inj, honey):
    m = inj.marca()
    desde = os.path.getsize(ALERTS)
    inj.enviar(a_xml(honey, m))
    a = resultado({"x": m}, desde).get("x")
    if not a:
        return False, "el evento reconstruido no produjo alerta"
    if a.get("decoder", {}).get("name") != "windows_eventchannel":
        return False, f"decodificado como {a.get('decoder', {}).get('name')}, no windows_eventchannel"
    w = a["data"]["win"]
    dif = [k for k in honey["eventdata"] if honey["eventdata"][k] != w["eventdata"].get(k)]
    dif += [k for k in ("eventID", "providerName", "channel", "keywords", "severityValue")
            if honey["system"].get(k) != w["system"].get(k)]
    return not dif, (f"regla {a['rule']['id']}; campos distintos: {dif}" if dif else f"regla {a['rule']['id']}; coincidieron los campos comparados")


def procesado(r):
    """Positive evidence the engine took the sample: an alert, decoded as eventchannel."""
    return bool(r and r.get("regla") and r.get("decoder") == "windows_eventchannel" and r.get("eventID") == "4769")


def cumple(res):
    return (all(procesado(res[n]) and res[n]["regla"] == "100212" for n in HONEY)
            and procesado(res["aes-legit"])
            and res["aes-legit"]["regla"] not in ("100210", "100211", "100212"))


def operativo(inj, aes, timeout=600):
    """Manager working: service active and an injected canary (the AES sample,
    which alerts as 60106 with any version of local_rules.xml) alerts.
    Re-sent every 10 s: after a restart analysisd opens its socket before it
    has loaded the ruleset, and events sent in that window are lost
    (2026-11-15: a fixed 20 s wait was not enough)."""
    fin = time.time() + timeout
    while time.time() < fin:
        if subprocess.run(["systemctl", "is-active", "--quiet", "wazuh-manager"]).returncode == 0:
            m = inj.marca()
            desde = os.path.getsize(ALERTS)
            try:
                inj.enviar(a_xml(aes, m))
            except OSError:
                pass                           # socket not there yet
            else:
                if "x" in resultado({"x": m}, desde, espera=10):
                    return True
        time.sleep(2)
    return False


def reiniciar():
    t = subprocess.run([f"{OSSEC}/bin/wazuh-analysisd", "-t"], capture_output=True, text=True)
    if t.returncode != 0:
        print(t.stdout[-800:], t.stderr[-800:])
        return False
    # On this lab VM a restart takes several minutes (2026-11-15); bounded, not endless.
    try:
        if subprocess.run(["systemctl", "restart", "wazuh-manager"], timeout=RESTART_TIMEOUT_S).returncode != 0:
            return False
    except subprocess.TimeoutExpired:
        print(f"   !! 'systemctl restart wazuh-manager' no terminó en {RESTART_TIMEOUT_S // 60} min")
        return False
    fin = time.time() + 180
    while time.time() < fin and not os.path.exists(QUEUE):
        time.sleep(2)
    return os.path.exists(QUEUE)          # readiness is checked with a canary (operativo)


def main():
    global RULES
    if os.geteuid() != 0 or len(sys.argv) != 2:
        sys.exit(__doc__)
    RULES = destino(sys.argv[1])
    print(f"== Archivo a reemplazar: {RULES} (sha256 {sha256(RULES)[:16]}); sin IDs duplicados")
    honey, aes = muestras()
    inj = Inyector()
    print("== Reiniciando el manager con las reglas actuales del disco (base del 'antes')...")
    log0 = tam_log()
    if not reiniciar() or not operativo(inj, aes):
        sys.exit("El manager no quedó operativo con las reglas actuales; no se cambió nada.")
    dup = avisos_duplicados(log0)
    if dup:
        sys.exit("ossec.log reporta IDs duplicados con las reglas actuales; no se cambió nada:\n  " + "\n  ".join(dup[:5]))
    ok, nota = fidelidad(inj, honey)
    print(f"== Fidelidad de la reconstrucción: {'OK' if ok else 'FALLA'} ({nota})")
    if not ok:
        sys.exit("La reconstrucción no reproduce el evento original; no se sigue.")
    sha_antes = sha256(RULES)
    print("== Antes (reglas del disco, recién cargadas)")
    antes = correr("antes", inj, honey, aes)
    respaldo = f"{RULES}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(RULES, respaldo)
    despues, instalada, error, recuperado = None, False, None, None
    try:
        shutil.copyfile(sys.argv[1], RULES)
        shutil.chown(RULES, "wazuh", "wazuh")
        os.chmod(RULES, 0o660)
        print(f"== Reglas nuevas instaladas (respaldo {respaldo}); reiniciando el manager...")
        log1 = tam_log()
        if not reiniciar():
            raise RuntimeError("el manager no reinició con las reglas nuevas")
        if not operativo(inj, aes):
            raise RuntimeError("el motor no procesó el evento canario tras el reinicio")
        dup = avisos_duplicados(log1)
        if dup:
            raise RuntimeError(f"IDs de regla duplicados tras instalar: {dup[:3]}")
        print("   motor listo (evento canario alertado)")
        print("== Después")
        despues = correr("después", inj, honey, aes)
        instalada = cumple(despues)
        if not instalada:
            print("!! No se cumplió lo esperado (o faltó evidencia de que el motor procesó una muestra).")
    except BaseException as e:            # includes Ctrl+C: never leave the new rules half-tested
        error = repr(e)
        print(f"!! Error o interrupción: {error}")
    finally:
        if not instalada:
            print("== Restaurando las reglas anteriores...")
            shutil.copyfile(respaldo, RULES)
            shutil.chown(RULES, "wazuh", "wazuh")
            os.chmod(RULES, 0o660)
            print(f"   reglas anteriores copiadas de vuelta ({respaldo}); reiniciando el manager...")
            try:
                recuperado = reiniciar() and operativo(inj, aes)
            except BaseException as e:      # Ctrl+C during the restore itself
                recuperado = False
                error = (error or "") + f" | durante la restauración: {e!r}"
            print("   reglas anteriores restauradas y manager operativo (evento de control alertado)"
                  if recuperado else
                  "   !! el archivo de reglas YA es el anterior, pero no se confirmó que el manager quedó "
                  "operativo: correr 'sudo systemctl restart wazuh-manager' y revisar "
                  "'systemctl status wazuh-manager' y /var/ossec/logs/ossec.log")
    out = {"momento_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "fidelidad": nota,
           "instalada": instalada, "error": error, "manager_recuperado": recuperado,
           "archivo": RULES, "sha256_antes": sha_antes, "sha256_nuevas": sha256(sys.argv[1]),
           "respaldo": respaldo, "antes": antes, "despues": despues,
           "muestra_honeytoken": a_xml(honey, 0), "muestra_aes": a_xml(aes, 0)}
    ruta = os.path.join(AQUI, "engine_test_results.json")
    with open(ruta, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    os.chmod(ruta, 0o644)
    print(f"\n{'OK: reglas nuevas instaladas y validadas' if instalada else 'FALLÓ: ver arriba el estado de la restauración'}"
          f" | {ruta}")
    return 0 if instalada else 1


if __name__ == "__main__":
    sys.exit(main())
