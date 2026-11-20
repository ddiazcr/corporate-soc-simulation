"""
Imported by every test module BEFORE soc_ai_triage.

The suite must never reach the analyst's real Telegram chat or the model API,
whatever is set in the shell that runs it. On the analysis host
TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are set for live runs, and a test run
from that shell sent [SIMULADO] cases to the real chat (2026-11-18). AI_MODE is
read when soc_ai_triage is imported, so it is cleared here too: tests that need
REAL mode set it themselves with a stubbed `requests`.

Only this test process's environment changes; the parent shell keeps its values.
"""
import os

AISLADAS = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "ANTHROPIC_API_KEY", "AI_MODE")
for _var in AISLADAS:
    os.environ.pop(_var, None)
