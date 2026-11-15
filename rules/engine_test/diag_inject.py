"""
Diagnose why an event injected into analysisd's queue socket produces no
alert. Runs ON THE MANAGER as root; changes nothing.

    sudo python3 diag_inject.py

1. Socket and analysisd process present.
2. Control: a generic sshd "Failed password" line (queue '1'), which the
   default ruleset alerts on (rule 5710 family). Proves the injection path.
3. The honeytoken eventchannel sample (queue 'f') with two location formats:
   "EventChannel" (manager-local) and "[000] (wazuh-server) any->EventChannel"
   (agent-style). Prints any alert carrying the marker and the new lines of
   ossec.log (decoder errors such as "Malformed EventChannel JSON event" or
   "Could not read XML string" show up there).
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_engine_test as et  # noqa: E402

LOG = "/var/ossec/logs/ossec.log"


def nuevas(ruta, desde):
    with open(ruta, encoding="utf-8", errors="replace") as f:
        f.seek(desde)
        return f.read().splitlines()


def probar(nombre, mensaje, marca, espera=8):
    a0, l0 = os.path.getsize(et.ALERTS), os.path.getsize(LOG)
    s = et.socket.socket(et.socket.AF_UNIX, et.socket.SOCK_DGRAM)
    s.sendto(mensaje.encode(), et.QUEUE)
    s.close()
    time.sleep(espera)
    hits = [x for x in nuevas(et.ALERTS, a0) if marca in x]
    print(f"\n== {nombre}: {'ALERTA' if hits else 'sin alerta'}")
    for h in hits[:2]:
        import json
        a = json.loads(h)
        print(f"   regla {a['rule']['id']} nivel {a['rule']['level']} decoder {a.get('decoder', {}).get('name')}"
              f" location {a.get('location')}")
    for x in nuevas(LOG, l0)[-6:]:
        print("   ossec.log:", x[:220])


def main():
    if os.geteuid() != 0:
        sys.exit(__doc__)
    print("socket:", et.QUEUE, os.path.exists(et.QUEUE))
    print("analysisd:", subprocess.run(["pgrep", "-a", "wazuh-analysisd"], capture_output=True, text=True).stdout.strip())
    marca = f"nimbrekdiag{int(time.time())}"
    probar("control sshd (cola 1)",
           f"1:/var/log/auth.log:Nov 15 10:00:00 wazuh-server sshd[4242]: Failed password for invalid user "
           f"{marca} from 10.9.9.9 port 2222 ssh2", marca)
    honey, _ = et.muestras()
    inj = et.Inyector()
    for loc in ("EventChannel", "[000] (wazuh-server) any->EventChannel"):
        m = inj.marca()
        probar(f"eventchannel location={loc!r}", f"f:{loc}:{et.a_xml(honey, m)}", f'"eventRecordID":"{m}"')
    print("\nmuestra enviada (primeros 400 caracteres):")
    print(et.a_xml(honey, 0)[:400])


if __name__ == "__main__":
    main()
