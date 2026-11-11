"""
List built-in Wazuh rules that can hide a local rule.

analysisd evaluates the children of a matched rule in load order and stops at
the first child that matches. Built-in rules load before local_rules.xml, so a
built-in sibling that matches the same event (often a level-0 "silencer")
takes the event and the local rule is never evaluated, unless the local rule
also lists that sibling as a parent.

For every local rule with <if_sid>, this prints the built-in children of its
parents that are not themselves parents of the local rule and whose event-ID
filter (if any) does not exclude the event IDs the local rule pins.
It is a static check: it says which siblings to review, not which ones match
a given event. Confirm a finding with wazuh-logtest on the manager.

Siblings already reviewed by hand (they need fields the event never has) are
listed in shadowing_reviewed.txt next to this script and are not reported.

Usage:
    python3 check_shadowing.py <wazuh ruleset/rules dir> [local_rules.xml]
Exit status 1 if any unreviewed sibling is found.
"""
import glob
import os
import re
import sys

RULE = re.compile(r'<rule id="(\d+)" level="(\d+)"[^>]*>(.*?)</rule>', re.S)
IF_SID = re.compile(r"<if_sid>([^<]+)</if_sid>")
EVENT_ID = re.compile(r'<field name="win\.system\.eventID"([^>]*)>([^<]*)<')
ALTERNATIVA = re.compile(r"^(\^\d+\$|\d+)$")   # ^4624$ (exact) or 4624 (substring)


def reglas(texto):
    for rid, nivel, cuerpo in RULE.findall(texto):
        padres = {x.strip() for p in IF_SID.findall(cuerpo) for x in p.split(",") if x.strip()}
        ev = EVENT_ID.findall(cuerpo)
        yield rid, int(nivel), padres, (ev[0] if ev else None)


def acepta(filtro):
    """For an event-ID filter, a function id -> bool, or None when its meaning
    cannot be stated safely.

    Understood: a positive OS_Regex filter whose alternatives are all ^N$
    (exact) or N (unanchored, i.e. substring). Anything else - negate="yes"
    (accepts every OTHER ID), a type= (pcre2...), whitespace or an empty
    alternative inside the pattern, any other regex - returns None, so the
    sibling is kept for review instead of being skipped."""
    if not filtro:
        return None
    atributos, patron = filtro
    if "negate" in atributos or "type=" in atributos:
        return None
    alts = patron.split("|")
    if not all(ALTERNATIVA.match(a) for a in alts):   # no strip: whitespace is not understood
        return None
    exactos = {a[1:-1] for a in alts if a.startswith("^")}
    sub = [a for a in alts if not a.startswith("^")]
    return lambda ev: ev in exactos or any(x in ev for x in sub)


def ids_fijados(filtro):
    """Event IDs a local rule pins: only an exact positive list (^N$|^M$)."""
    f = acepta(filtro)
    if f is None or any(not a.startswith("^") for a in filtro[1].split("|")):
        return None
    return set(re.findall(r"\d+", filtro[1]))


def revisar(dir_ruleset, ruta_local):
    builtin = []
    for f in sorted(glob.glob(os.path.join(dir_ruleset, "*.xml"))):
        with open(f, encoding="utf-8", errors="replace") as fh:
            for r in reglas(fh.read()):
                builtin.append((os.path.basename(f),) + r)
    with open(ruta_local, encoding="utf-8") as fh:
        locales = list(reglas(fh.read()))
    hallazgos = []
    for rid, _, padres, filtro in locales:
        mios = ids_fijados(filtro)
        for f, bid, nivel, bpadres, bfiltro in builtin:
            if bid in padres or not (bpadres & padres):
                continue
            suyo = acepta(bfiltro)
            if mios and suyo is not None and not any(suyo(ev) for ev in mios):
                continue  # the sibling provably takes only other event IDs
            hallazgos.append((rid, bid, nivel, f, sorted(bpadres & padres)))
    return hallazgos


def revisadas(ruta):
    pares = set()
    if os.path.exists(ruta):
        with open(ruta, encoding="utf-8") as fh:
            for linea in fh:
                partes = linea.split("#", 1)[0].split()
                if len(partes) >= 2:
                    pares.add((partes[0], partes[1]))
    return pares


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    local = argv[2] if len(argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_rules.xml")
    ok = revisadas(os.path.join(os.path.dirname(os.path.abspath(local)), "shadowing_reviewed.txt"))
    hallazgos = [h for h in revisar(argv[1], local) if (h[0], h[1]) not in ok]
    for rid, bid, nivel, f, comun in hallazgos:
        print(f"local {rid}: built-in sibling {bid} (level {nivel}, {f}) shares parent {','.join(comun)}")
    print(f"{len(hallazgos)} sibling(s) to review ({len(ok)} reviewed in shadowing_reviewed.txt)")
    return 1 if hallazgos else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
