"""
models.py
---------
Pydantic schemas for API requests/responses. Keeping these separate from
scorer.py and main.py means the frontend contract is defined in one place.
"""

from typing import List, Optional
from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    text: str                      # raw message text (already OCR'd/decoded if it came from an image/QR)
    source: str = "text"           # 'text' | 'url' | 'screenshot' | 'qr' | 'forward'


class Entity(BaseModel):
    entity_type: str               # 'phone', 'upi_id', 'domain', 'bank_name'
    value: str
    report_count: int              # how many times this exact entity has been reported before


class TriggeredRule(BaseModel):
    name: str
    description: str
    weight: int                    # how many points this rule added to the score


class AnalyzeResponse(BaseModel):
    submission_id: int
    risk_score: int                # 0-100
    verdict: str                   # 'safe' | 'suspicious' | 'dangerous'
    triggered_rules: List[TriggeredRule]
    entities: List[Entity]
    explanation: Optional[str] = None   # filled in by the LLM narration step (Step 3)


class ReportRequest(BaseModel):
    submission_id: int             # confirms which analyzed message this report is about


class ReportResponse(BaseModel):
    status: str
    updated_entities: List[Entity]
