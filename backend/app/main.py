"""
main.py
-------
FastAPI entrypoint. Run with:
    uvicorn app.main:app --reload --port 8000

Endpoints:
    POST /analyze  - submit a message (text/url/screenshot-OCR'd text/qr-decoded text)
                      returns risk score + reasons + entities
    POST /report   - user confirms a previously-analyzed submission was a scam,
                      writes its entities into the threat graph
    GET  /health   - basic liveness check
"""

import json
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.seed_data import seed
from app.entity_extractor import extract_entities
from app.threat_graph import (
    lookup_entities,
    record_report,
    log_submission,
    get_submission_entities_cache,
)
from app.scorer import score_message
from app.image_processor import extract_text_from_image
from app.qr_processor import decode_qr_from_bytes, parse_upi_link
from app.llm_narrator import generate_explanation
from app.url_checker import (
    resolve_redirect_chain,
    get_domain_age_days,
    check_ssl_validity,
    typosquat_match,
)
from app.entity_extractor import mentioned_brands
from app.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    Entity,
    TriggeredRule,
    ReportRequest,
    ReportResponse,
)

import os

app = FastAPI(title="Raksha - Scam Message Analyzer", version="0.1.0")

# CORS: reads a comma-separated ALLOWED_ORIGINS env var in production
# (e.g. "https://raksha.netlify.app,https://raksha.vercel.app"). Falls
# back to "*" if unset so local development keeps working unchanged.
# Wide-open "*" is fine for a public read-mostly demo tool like this, but
# setting ALLOWED_ORIGINS once you have a real frontend domain is a good
# habit and costs nothing to do.
_allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
_origins_list = ["*"] if _allowed_origins == "*" else [o.strip() for o in _allowed_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins_list,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    # Idempotent — see seed_data.py: only inserts baseline demo entities
    # that don't already exist, never touches real report counts. Running
    # this on every startup means a freshly-deployed or restarted server
    # (e.g. Render's free tier, which resets disk on redeploy) always has
    # working demo data instead of an empty, unimpressive threat graph.
    seed()


@app.get("/health")
def health():
    return {"status": "ok"}


def _run_pipeline(text: str, source: str, qr_parsed: dict = None) -> AnalyzeResponse:
    """
    Shared core: entity extraction -> threat graph lookup -> scoring ->
    logging. All three ingestion endpoints (/analyze, /analyze/screenshot,
    /analyze/qr) funnel into this once they've produced plain text.
    """
    if not text or not text.strip():
        raise HTTPException(
            status_code=400,
            detail="No readable text found (empty input, or OCR/QR decode failed)",
        )

    raw_entities = extract_entities(text)

    # If this came from a decoded UPI QR, the payee VPA is the single most
    # important entity — make sure it's tracked even if our general UPI
    # regex would've missed an unusual handle format.
    if qr_parsed and qr_parsed.get("payee_vpa"):
        vpa_entity = ("upi_id", qr_parsed["payee_vpa"].lower())
        if vpa_entity not in raw_entities:
            raw_entities.append(vpa_entity)

    domains = [value for etype, value in raw_entities if etype == "domain"]
    threat_graph_hits = lookup_entities(raw_entities)

    # Real link-safety checks (redirect resolution, WHOIS domain age, SSL
    # cert validity, typosquat comparison against known brand domains) —
    # see app/url_checker.py. These are network calls, so:
    #   - capped to the first 2 domains found, so one message with many
    #     links can't turn a scan into a 30-second wait
    #   - every individual check already degrades to None on its own
    #     failure/timeout (see url_checker.py docstrings), so a slow or
    #     offline network never breaks the scan — it just means those
    #     specific url_checks-based rules quietly don't fire
    url_checks = {}
    brand_tokens = mentioned_brands(text.lower())
    for domain in domains[:2]:
        url_checks[domain] = {
            "redirect_to": resolve_redirect_chain(domain),
            "domain_age_days": get_domain_age_days(domain),
            "ssl_valid": check_ssl_validity(domain),
            "typosquat": typosquat_match(domain, brand_tokens),
        }

    result = score_message(
        text=text,
        source=source,
        domains=domains,
        threat_graph_hits=threat_graph_hits,
        qr_parsed=qr_parsed,
        url_checks=url_checks,
    )

    submission_id = log_submission(
        raw_text=text,
        source=source,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        triggered_rules_json=json.dumps(result["triggered_rules"]),
    )
    get_submission_entities_cache()[submission_id] = raw_entities

    # LLM narration step: turns the already-decided score/rules into a
    # plain-language explanation. Never influences the score itself —
    # see llm_narrator.py for why, and it degrades gracefully if Ollama
    # isn't running (falls back to a template explanation instead of
    # failing the whole request).
    explanation = generate_explanation(
        text=text,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        triggered_rules=result["triggered_rules"],
    )

    return AnalyzeResponse(
        submission_id=submission_id,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        triggered_rules=[TriggeredRule(**r) for r in result["triggered_rules"]],
        entities=[
            Entity(entity_type=h["entity_type"], value=h["value"], report_count=h["report_count"])
            for h in threat_graph_hits
        ],
        explanation=explanation,
    )


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    return _run_pipeline(text=payload.text, source=payload.source)


@app.post("/analyze/screenshot", response_model=AnalyzeResponse)
async def analyze_screenshot(file: UploadFile = File(...)):
    """
    Accepts an uploaded screenshot (SMS/WhatsApp/email screenshot), runs
    OCR to extract text, then feeds it through the same scoring pipeline
    as /analyze.
    """
    image_bytes = await file.read()
    try:
        text = extract_text_from_image(image_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return _run_pipeline(text=text, source="screenshot")


@app.post("/analyze/qr", response_model=AnalyzeResponse)
async def analyze_qr(file: UploadFile = File(...)):
    """
    Accepts an uploaded QR code image. Decodes it; if it's a UPI payment
    link, parses payee VPA/amount/name for the QR-specific scoring rules.
    If it decodes to a plain URL or other text instead, that's scored
    through the normal text/URL rules.
    """
    image_bytes = await file.read()
    qr_text = decode_qr_from_bytes(image_bytes)

    if not qr_text:
        raise HTTPException(
            status_code=400,
            detail="No QR code detected in the uploaded image — try a clearer photo",
        )

    qr_parsed = parse_upi_link(qr_text)
    return _run_pipeline(text=qr_text, source="qr", qr_parsed=qr_parsed)


@app.post("/report", response_model=ReportResponse)
def report(payload: ReportRequest):
    cache = get_submission_entities_cache()
    entities = cache.get(payload.submission_id)
    if entities is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown submission_id (server may have restarted since analysis)",
        )

    updated = record_report(entities)
    return ReportResponse(
        status="recorded",
        updated_entities=[
            Entity(entity_type=e["entity_type"], value=e["value"], report_count=e["report_count"])
            for e in updated
        ],
    )
