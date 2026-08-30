"""
llm_narrator.py
----------------
Turns the rule engine's triggered_rules list into a plain-English
explanation using a LOCAL LLM via Ollama.

Critical design point from the whiteboard (Approach B): the LLM NEVER
decides the risk score. It only narrates a score/verdict/rules that the
deterministic scorer already computed. This means:
  - if Ollama is down, slow, or not installed, the app still works —
    it just falls back to a template-generated explanation instead of
    an LLM-written one. The user always gets SOME explanation.
  - a hallucinated or malformed LLM response can never change the verdict,
    only the wording of why.

Requires Ollama running locally (default: http://localhost:11434) with a
model pulled, e.g.:
    ollama pull llama3.2:3b
(a small model is fine and much faster on CPU-only laptops — this task is
 just "summarize these bullet points," not deep reasoning)
"""

import os
import requests
from typing import List, Dict

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"   # change to whatever you've pulled, e.g. "phi3:mini"
REQUEST_TIMEOUT_SECONDS = 8    # fail fast — a demo can't hang on a slow local model

# On a cloud deployment there is no local Ollama to talk to — every single
# request would otherwise burn the full 8-second timeout waiting on a
# connection that can never succeed, making the whole app feel broken even
# though scoring itself is instant. Setting LLM_NARRATION=off (e.g. in
# Render's environment variables) skips the network call entirely and goes
# straight to the template explanation, which is what public deployments
# should do unless you've also deployed a reachable LLM endpoint. Local/
# desktop use with Ollama running needs no env var — it defaults to on.
LLM_NARRATION_ENABLED = os.environ.get("LLM_NARRATION", "on").lower() != "off"


def _build_prompt(text: str, risk_score: int, verdict: str, triggered_rules: List[Dict]) -> str:
    rules_text = "\n".join(f"- {r['description']}" for r in triggered_rules) or "- No specific rules were triggered."

    return f"""You are a cybersecurity assistant explaining a scam-detection result to a non-technical user in India.

The message being analyzed: "{text[:500]}"

Automated risk score: {risk_score}/100 ({verdict})

Reasons this score was given:
{rules_text}

Write a short explanation (2-3 sentences, plain language, no jargon) of why this message got this verdict, and one clear piece of practical advice for what the user should do next. Do not mention "AI" or "score" mechanics — just explain it like you're warning a friend. Do not change or contradict the verdict of "{verdict}"."""


def _fallback_explanation(risk_score: int, verdict: str, triggered_rules: List[Dict]) -> str:
    """
    Template-based explanation used when Ollama is unavailable. Not as
    fluent as an LLM response, but always available — this is the whole
    point of keeping the LLM out of the scoring path.
    """
    if not triggered_rules:
        return "No suspicious patterns were found in this message. It appears safe, but always stay cautious with unexpected requests for money or personal information."

    top_reasons = ", ".join(r["description"].split(" (")[0] for r in triggered_rules[:3])

    if verdict == "dangerous":
        return (
            f"This message shows strong signs of being a scam: {top_reasons}. "
            f"Do not click any links, share OTPs, or send money. If in doubt, "
            f"contact the organization directly using a number from their official website."
        )
    elif verdict == "suspicious":
        return (
            f"This message has some warning signs: {top_reasons}. "
            f"It may still be legitimate, but verify independently before taking any action "
            f"like clicking links or making a payment."
        )
    else:
        return f"This message triggered minor flags ({top_reasons}) but doesn't show strong scam indicators. Stay generally cautious."


def generate_explanation(text: str, risk_score: int, verdict: str, triggered_rules: List[Dict]) -> str:
    """
    Tries the local LLM first; falls back to a template if Ollama isn't
    reachable or times out, or if LLM_NARRATION=off (see module docstring
    above — this is the normal, expected path on cloud deployments).
    Always returns a usable string — never raises.
    """
    if not LLM_NARRATION_ENABLED:
        return _fallback_explanation(risk_score, verdict, triggered_rules)

    prompt = _build_prompt(text, risk_score, verdict, triggered_rules)

    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        llm_text = data.get("response", "").strip()
        if llm_text:
            return llm_text
    except (requests.exceptions.RequestException, ValueError, KeyError) as e:
        # Ollama not running, model not pulled, timeout, bad JSON, etc.
        # Temporary debug print (Step 3 troubleshooting) — remove once
        # Ollama connection is confirmed working reliably.
        print(f"[llm_narrator] Ollama call failed, using fallback. Reason: {type(e).__name__}: {e}")

    return _fallback_explanation(risk_score, verdict, triggered_rules)
