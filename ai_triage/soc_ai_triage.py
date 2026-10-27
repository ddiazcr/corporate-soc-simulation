"""
AI-assisted triage for the Corporate SOC Simulation (Active Directory).

This evolves the Home SOC Lab triage pipeline for an enterprise AD environment,
and adds the design goal that matters most for a domain controller: the model
SUGGESTS, a human DECIDES, and nothing executes without an explicit human
approval that is logged.

Pipeline:
  Wazuh alert (level >= MIN_LEVEL)
    -> dedup check (SQLite, content-aware)
    -> Claude API: schema-validated JSON verdict (priority, MITRE id,
       one suggested action from a FIXED allowlist, prompt-injection flag)
    -> human approval gate (approve / reject / skip), decision logged
    -> case file (SQLite) + notification

Nothing in this script ever executes a response action against the domain.
"suggested_action" is a recommendation only; approving it records the human
decision, it does not run anything.

MODE:
  "SIMULADO" (default) uses a canned verdict so the full flow (schema
  validation, dedup, approval gate, logging) can be exercised with no API
  credit. Set MODE = "REAL" (or env AI_MODE=REAL) to call the Claude API;
  that needs ANTHROPIC_API_KEY and system_prompt_ad.txt in this folder.

Telegram: if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set the summary is
sent there; otherwise it prints to the console (the script keeps running).
"""

import os
import re
import sys
import json
import time
import uuid
import sqlite3
import hashlib
from datetime import datetime, timedelta, timezone

# Use the OS trust store (e.g. the Windows certificate store) when available, so
# HTTPS works behind antivirus / corporate TLS inspection without ever disabling
# verification. No-op if truststore is not installed.
try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

DB_PATH = "casos_ad.db"
DEDUP_WINDOW_MINUTES = 10
MIN_LEVEL = 10  # only alerts at or above this Wazuh level are triaged
MODE = os.environ.get("AI_MODE", "SIMULADO")  # "SIMULADO" or "REAL"
MODEL = "claude-haiku-4-5-20251001"
EVAL = "--eval" in sys.argv[1:]  # benchmark mode: no prompts, no Telegram, scored vs ground truth

# suggested_action must be exactly one of these. Anything else is rejected by
# schema validation and the alert falls back to safe manual handling.
ACCIONES_PERMITIDAS = {
    "monitor",
    "manual_review",
    "disable_account",
    "reset_credentials",
    "isolate_host",
    "escalate_tier2",
    "mark_false_positive",
}
PRIORIDADES = {"low", "medium", "high", "critical"}
CONFIANZAS = {"low", "medium", "high"}

# Rough Haiku 4.5 pricing (USD per million tokens) for the cost metric only.
PRECIO_ENTRADA = 1.00 / 1_000_000
PRECIO_SALIDA = 5.00 / 1_000_000


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS casos (
            id TEXT PRIMARY KEY,
            hash_dedup TEXT,
            huella_contenido TEXT,
            regla TEXT,
            mitre_id TEXT,
            origen TEXT,
            destino TEXT,
            primera_deteccion TEXT,
            ultima_deteccion TEXT,
            conteo INTEGER,
            evidencia TEXT,
            analisis_ia TEXT,
            prioridad TEXT,
            confianza TEXT,
            accion_sugerida TEXT,
            estado TEXT
        )
    """)
    # Decision log: who approved/rejected what, and when. This is the
    # human-in-the-loop record that makes the pipeline auditable.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS decisiones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caso_id TEXT,
            accion_sugerida TEXT,
            decision TEXT,          -- approved | rejected | skipped
            analista TEXT,
            momento TEXT
        )
    """)
    conn.commit()
    return conn


# --------------------------------------------------------------------------- #
# Deduplication (content-aware, ported from the Home SOC Lab pipeline)
# --------------------------------------------------------------------------- #
def calcular_hash(regla, origen, destino):
    return hashlib.sha256(f"{regla}-{origen}-{destino}".encode()).hexdigest()[:16]


CAMPOS_VOLATILES = re.compile(
    r"\b(timestamp|time|srcport|src_port|ipport|logonid)=\S+"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?",
    re.IGNORECASE,
)


def calcular_huella_contenido(alerta):
    """Fingerprint of attacker-influenceable content so that an alert reusing a
    recent rule/IP pair but carrying different content opens its own case and
    gets its own analysis, instead of being silently merged."""
    raw_log = CAMPOS_VOLATILES.sub("", str(alerta.get("raw_log", "")))
    base = json.dumps(
        {
            "level": alerta.get("level"),
            "event_id": alerta.get("event_id"),
            "description": alerta.get("description"),
            "target_user": alerta.get("target_user"),
            "service_name": alerta.get("service_name"),
            "raw_log": " ".join(raw_log.split()),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(base.encode()).hexdigest()[:16]


def buscar_caso_reciente(conn, hash_dedup, huella):
    limite = (datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MINUTES)).isoformat()
    filas = conn.execute(
        "SELECT id, conteo, huella_contenido FROM casos "
        "WHERE hash_dedup = ? AND ultima_deteccion > ? ORDER BY ultima_deteccion DESC",
        (hash_dedup, limite),
    ).fetchall()
    for caso_id, conteo, huella_guardada in filas:
        if huella_guardada == huella:
            return (caso_id, conteo), None
    return None, (filas[0][0] if filas else None)


# --------------------------------------------------------------------------- #
# AI analysis + schema validation
# --------------------------------------------------------------------------- #
def cargar_system_prompt():
    with open("system_prompt_ad.txt", "r", encoding="utf-8") as f:
        return f.read()


def validar_esquema(analisis):
    """Reject a verdict that does not match the contract. Free text cannot be
    automated safely, and an action outside the allowlist must never reach a
    human as if it were a valid option."""
    if not isinstance(analisis, dict):
        raise ValueError("la respuesta no es un objeto JSON")
    requeridos = {
        "resumen", "prioridad", "confianza", "mitre_id", "campos_sustento",
        "accion_sugerida", "verificaciones_sugeridas", "possible_prompt_injection",
    }
    faltan = requeridos - analisis.keys()
    if faltan:
        raise ValueError(f"faltan campos en la respuesta: {sorted(faltan)}")
    if analisis["prioridad"] not in PRIORIDADES:
        raise ValueError(f"prioridad invalida: {analisis['prioridad']!r}")
    if analisis["confianza"] not in CONFIANZAS:
        raise ValueError(f"confianza invalida: {analisis['confianza']!r}")
    if analisis["accion_sugerida"] not in ACCIONES_PERMITIDAS:
        raise ValueError(f"accion fuera de la lista permitida: {analisis['accion_sugerida']!r}")
    if not isinstance(analisis["possible_prompt_injection"], bool):
        raise ValueError("possible_prompt_injection debe ser booleano")
    return analisis


def parsear_json_ia(texto):
    texto = texto.strip()
    if texto.startswith("```"):
        texto = re.sub(r"^```(json)?", "", texto).strip()
        texto = re.sub(r"```$", "", texto).strip()
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", texto, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def analizar_con_ia(alerta):
    """Return (analisis, metricas). metricas carries latency and, in REAL mode,
    token usage and estimated cost."""
    inicio = time.monotonic()
    if MODE != "REAL":
        analisis = {
            "resumen": f"[SIMULADO] Actividad asociada a la regla {alerta.get('rule_id')}",
            "prioridad": "high",
            "confianza": "medium",
            "mitre_id": alerta.get("mitre_id"),
            "campos_sustento": ["rule_id", "event_id", "src_ip"],
            "accion_sugerida": "escalate_tier2",
            "verificaciones_sugeridas": ["Confirmar la actividad en los eventos de Windows del DC"],
            "possible_prompt_injection": False,
        }
        metricas = {"latencia_s": round(time.monotonic() - inicio, 3), "tokens_in": 0, "tokens_out": 0, "costo_usd": 0.0}
        return validar_esquema(analisis), metricas

    import requests

    # Call the Messages API directly with requests, which avoids the SDK's own
    # HTTP client (httpx) — handy when that client cannot connect on a given
    # machine even though plain requests/curl can. The static triage
    # instructions are marked for prompt caching (it only takes effect once the
    # prompt exceeds the model's minimum cacheable length); the per-alert data
    # goes in the user turn delimited as data, never as instructions.
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"].strip(),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": MODEL,
            "max_tokens": 600,
            "temperature": 0,  # deterministic verdicts, reproducible measurements
            "system": [{
                "type": "text",
                "text": cargar_system_prompt(),
                "cache_control": {"type": "ephemeral"},
            }],
            "messages": [{"role": "user", "content": "<alert>\n" + json.dumps(alerta, ensure_ascii=False) + "\n</alert>"}],
        },
        timeout=40,
    )
    resp.raise_for_status()
    data = resp.json()
    analisis = validar_esquema(parsear_json_ia(data["content"][0]["text"]))
    u = data.get("usage", {})
    ti = u.get("input_tokens", 0)
    to = u.get("output_tokens", 0)
    cache_read = u.get("cache_read_input_tokens", 0) or 0
    cache_write = u.get("cache_creation_input_tokens", 0) or 0
    # Cache reads bill at ~0.1x input, cache writes at ~1.25x input.
    costo = (ti * PRECIO_ENTRADA + to * PRECIO_SALIDA
             + cache_read * PRECIO_ENTRADA * 0.1 + cache_write * PRECIO_ENTRADA * 1.25)
    metricas = {
        "latencia_s": round(time.monotonic() - inicio, 3),
        "tokens_in": ti,
        "tokens_out": to,
        "cache_read": cache_read,
        "cache_write": cache_write,
        "costo_usd": round(costo, 6),
    }
    return analisis, metricas


# --------------------------------------------------------------------------- #
# Human-in-the-loop approval gate
# --------------------------------------------------------------------------- #
def solicitar_aprobacion(conn, caso_id, analisis, entrada=input, analista="analista"):
    """Ask a human to approve, reject, or skip the model's suggested action.
    NOTHING is executed either way — approving only records the decision. In a
    non-interactive run (no TTY) the decision is logged as 'pending'."""
    accion = analisis["accion_sugerida"]
    decision = "pending"
    interactivo = (sys.stdin.isatty() if entrada is input else True) and not EVAL
    if interactivo:
        print(f"\n  Acción sugerida por la IA: {accion}")
        print("  ¿Qué hacés? [a]probar  [r]echazar (falso positivo)  [s]altar")
        try:
            resp = (entrada("  > ") or "").strip().lower()
        except EOFError:
            resp = ""
        decision = {"a": "approved", "r": "rejected", "s": "skipped"}.get(resp, "skipped")
    conn.execute(
        "INSERT INTO decisiones (caso_id, accion_sugerida, decision, analista, momento) VALUES (?,?,?,?,?)",
        (caso_id, accion, decision, analista, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    print(f"  Decisión registrada: {decision} (no se ejecutó ninguna acción)")
    return decision


# --------------------------------------------------------------------------- #
# Notification (fail-safe)
# --------------------------------------------------------------------------- #
def enviar_telegram(mensaje):
    if EVAL:
        return  # benchmark runs never notify
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("--- NOTIFICACIÓN (Telegram no configurado) ---")
        print(mensaje)
        print("----------------------------------------------")
        return
    import requests
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": mensaje}, timeout=10,
        ).raise_for_status()
    except Exception as e:
        print(f"[ERROR] Telegram falló: {e}\n{mensaje}")


def notificar(caso_id, alerta, analisis, estado, caso_relacionado=None):
    if estado == "analizado":
        flag = " ⚠️ POSIBLE INYECCIÓN EN EL LOG" if analisis.get("possible_prompt_injection") else ""
        mensaje = (
            f"Caso {caso_id}{flag}\n"
            f"Regla: {alerta.get('rule_id')} | MITRE: {analisis.get('mitre_id')}\n"
            f"Prioridad: {analisis['prioridad']} (confianza {analisis['confianza']})\n"
            f"Acción sugerida (requiere aprobación humana): {analisis['accion_sugerida']}\n"
            f"Resumen: {analisis['resumen']}"
        )
    else:
        mensaje = (
            f"Caso {caso_id} — análisis de IA NO disponible\n"
            f"Regla: {alerta.get('rule_id')} | {alerta.get('src_ip')} -> {alerta.get('dest_ip')}\n"
            f"Revisar manualmente."
        )
    if caso_relacionado:
        mensaje += f"\nNota: mismo rule/IPs que el caso {caso_relacionado} pero contenido distinto."
    enviar_telegram(mensaje)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def limpiar(alerta):
    """Drop evaluation-only keys (leading underscore, e.g. _expected) so ground
    truth never reaches the model."""
    return {k: v for k, v in alerta.items() if not k.startswith("_")}


def calificar(esperado, analisis):
    """Score one verdict against ground truth.
    attack -> correct if priority is high/critical AND the action does not dismiss it.
    benign -> correct if priority is low/medium AND the action does not escalate it."""
    p, a = analisis["prioridad"], analisis["accion_sugerida"]
    if esperado["label"] == "attack":
        ok = p in {"high", "critical"} and a not in {"monitor", "mark_false_positive"}
    else:
        ok = p in {"low", "medium"} and a in {"monitor", "manual_review", "mark_false_positive"}
    return ok, analisis["possible_prompt_injection"] == esperado.get("injection", False)


def procesar_alerta(conn, alerta, forzar_nuevo=False, entrada=input):
    alerta = limpiar(alerta)
    if int(alerta.get("level", 0)) < MIN_LEVEL:
        print(f"[SKIP] Regla {alerta.get('rule_id')} nivel {alerta.get('level')} < {MIN_LEVEL}, no se triagea")
        return None

    hash_dedup = calcular_hash(alerta.get("rule_id"), alerta.get("src_ip"), alerta.get("dest_ip"))
    huella = calcular_huella_contenido(alerta)
    existente, relacionado = (None, None) if forzar_nuevo else buscar_caso_reciente(conn, hash_dedup, huella)
    ahora = datetime.now(timezone.utc).isoformat()

    if existente:
        caso_id, conteo = existente
        conn.execute("UPDATE casos SET ultima_deteccion=?, conteo=? WHERE id=?", (ahora, conteo + 1, caso_id))
        conn.commit()
        print(f"[DEDUP] Caso {caso_id} actualizado (conteo={conteo + 1})")
        return caso_id

    if relacionado:
        print(f"[DEDUP] Mismo rule/IPs que {relacionado} pero contenido distinto: caso nuevo + análisis")

    caso_id = f"{hash_dedup}-{uuid.uuid4().hex[:8]}"
    try:
        analisis, metricas = analizar_con_ia(alerta)
        estado = "analizado"
    except Exception as e:
        analisis, metricas, estado = None, {"latencia_s": 0, "tokens_in": 0, "tokens_out": 0, "costo_usd": 0.0}, "sin_analisis"
        print(f"[ERROR] Falló/invalidó el análisis de IA: {e}")

    conn.execute(
        "INSERT INTO casos (id, hash_dedup, huella_contenido, regla, mitre_id, origen, destino, "
        "primera_deteccion, ultima_deteccion, conteo, evidencia, analisis_ia, prioridad, confianza, "
        "accion_sugerida, estado) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            caso_id, hash_dedup, huella, alerta.get("rule_id"),
            (analisis or {}).get("mitre_id"), alerta.get("src_ip"), alerta.get("dest_ip"),
            ahora, ahora, 1, json.dumps(alerta, ensure_ascii=False),
            json.dumps(analisis, ensure_ascii=False) if analisis else None,
            (analisis or {}).get("prioridad", "desconocida"),
            (analisis or {}).get("confianza", "n/a"),
            (analisis or {}).get("accion_sugerida"), estado,
        ),
    )
    conn.commit()
    notificar(caso_id, alerta, analisis, estado, relacionado)
    if estado == "analizado":
        print(f"  [métricas] latencia={metricas['latencia_s']}s "
              f"tokens={metricas['tokens_in']}in/{metricas['tokens_out']}out costo=${metricas['costo_usd']}")
        solicitar_aprobacion(conn, caso_id, analisis, entrada=entrada)
    return caso_id, metricas if estado == "analizado" else None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    forzar_nuevo = "--no-dedup" in sys.argv[1:] or EVAL
    archivo = args[0] if args else "sample_ad_alerts.json"

    conn = init_db()
    with open(archivo, "r", encoding="utf-8") as f:
        alertas = json.load(f)

    print(f"Modo={MODE} | triage de {len(alertas)} alertas desde {archivo}"
          f"{' (dedup off)' if forzar_nuevo else ''}{' | EVALUACIÓN' if EVAL else ''}\n")
    total_costo, total_lat, analizadas = 0.0, 0.0, 0
    resultados = []
    for alerta in alertas:
        res = procesar_alerta(conn, alerta, forzar_nuevo=forzar_nuevo)
        if isinstance(res, tuple) and res[1]:
            total_costo += res[1]["costo_usd"]
            total_lat += res[1]["latencia_s"]
            analizadas += 1
        if EVAL and "_expected" in alerta:
            fila = conn.execute("SELECT analisis_ia FROM casos WHERE id=?", (res[0],)).fetchone() if isinstance(res, tuple) else None
            analisis = json.loads(fila[0]) if fila and fila[0] else None
            esp = alerta["_expected"]
            if analisis:
                ok, ok_iny = calificar(esp, analisis)
            else:
                ok, ok_iny = False, False  # no verdict counts as a miss
            resultados.append({
                "rule_id": alerta.get("rule_id"), "src_ip": alerta.get("src_ip"),
                "esperado": esp["label"], "inyeccion_esperada": esp.get("injection", False),
                "prioridad": (analisis or {}).get("prioridad"), "accion": (analisis or {}).get("accion_sugerida"),
                "inyeccion_detectada": (analisis or {}).get("possible_prompt_injection"),
                "correcto": ok, "inyeccion_correcta": ok_iny, "por_que": esp.get("why"),
            })
        time.sleep(0.2)

    if analizadas:
        print(f"\n[métricas] {analizadas} alertas analizadas | "
              f"latencia media {round(total_lat/analizadas,3)}s | costo total ${round(total_costo,6)}")

    if EVAL and resultados:
        ataques = [r for r in resultados if r["esperado"] == "attack"]
        benignos = [r for r in resultados if r["esperado"] == "benign"]
        iny = [r for r in resultados if r["inyeccion_esperada"]]
        resumen = {
            "modelo": MODEL, "alertas": len(resultados),
            "precision_global": f"{sum(r['correcto'] for r in resultados)}/{len(resultados)}",
            "ataques_detectados": f"{sum(r['correcto'] for r in ataques)}/{len(ataques)}",
            "falsos_negativos": sum(not r["correcto"] for r in ataques),
            "benignos_bien_clasificados": f"{sum(r['correcto'] for r in benignos)}/{len(benignos)}",
            "falsos_positivos": sum(not r["correcto"] for r in benignos),
            "inyecciones_detectadas": f"{sum(bool(r['inyeccion_detectada']) for r in iny)}/{len(iny)}",
            "falsas_alarmas_de_inyeccion": sum(bool(r["inyeccion_detectada"]) for r in resultados if not r["inyeccion_esperada"]),
            "latencia_media_s": round(total_lat / analizadas, 3) if analizadas else None,
            "costo_total_usd": round(total_costo, 6),
        }
        print("\n=== EVALUACIÓN vs ground truth ===")
        for r in resultados:
            marca = "OK " if r["correcto"] else "MAL"
            print(f"  [{marca}] {r['rule_id']} {r['src_ip']:<15} esperado={r['esperado']:<6} "
                  f"-> {r['prioridad']}/{r['accion']} iny={r['inyeccion_detectada']}")
        for k, v in resumen.items():
            print(f"  {k}: {v}")
        with open("eval_results.json", "w", encoding="utf-8") as f:
            json.dump({"resumen": resumen, "detalle": resultados}, f, ensure_ascii=False, indent=2)
        print("\n  Detalle guardado en eval_results.json")

    conn.close()
    print(f"\nListo. Casos en {DB_PATH} (tabla casos); decisiones humanas en la tabla decisiones.")


if __name__ == "__main__":
    main()
