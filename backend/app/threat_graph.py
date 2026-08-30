"""
threat_graph.py
----------------
This is the "gets smarter with usage" piece of the project.

Every entity (phone, UPI ID, domain) extracted from a message is checked
against everything reported before. The more times an entity has been
reported, the higher its trust penalty when it shows up in a NEW message.

lookup_entities()  -> read-only, used during analysis to compute the score
record_report()    -> write, called only when a user explicitly clicks
                       "report this as a scam" (never automatically -
                       see the false-positive note from the whiteboard)
"""

from typing import List, Tuple
from app.database import get_connection


def lookup_entities(entities: List[Tuple[str, str]]) -> List[dict]:
    """
    Given a list of (entity_type, value) tuples, return their current
    report_count from the threat graph (0 if never seen before).
    """
    results = []
    with get_connection() as conn:
        for entity_type, value in entities:
            row = conn.execute(
                "SELECT report_count FROM entities WHERE entity_type = ? AND entity_value = ?",
                (entity_type, value),
            ).fetchone()
            results.append(
                {
                    "entity_type": entity_type,
                    "value": value,
                    "report_count": row["report_count"] if row else 0,
                }
            )
    return results


def record_report(entities: List[Tuple[str, str]]) -> List[dict]:
    """
    Increments (or creates) the report_count for each entity. Called when
    a user confirms a message as a scam via the /report endpoint.
    Returns the updated rows.
    """
    updated = []
    with get_connection() as conn:
        for entity_type, value in entities:
            conn.execute(
                """
                INSERT INTO entities (entity_type, entity_value, report_count)
                VALUES (?, ?, 1)
                ON CONFLICT(entity_type, entity_value)
                DO UPDATE SET
                    report_count = report_count + 1,
                    last_seen = datetime('now')
                """,
                (entity_type, value),
            )
            row = conn.execute(
                "SELECT report_count FROM entities WHERE entity_type = ? AND entity_value = ?",
                (entity_type, value),
            ).fetchone()
            updated.append(
                {"entity_type": entity_type, "value": value, "report_count": row["report_count"]}
            )
        conn.commit()
    return updated


def log_submission(raw_text: str, source: str, risk_score: int, verdict: str, triggered_rules_json: str) -> int:
    """Logs an analyzed message. Returns the new submission's id."""
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO submissions (raw_text, source, risk_score, verdict, triggered_rules)
            VALUES (?, ?, ?, ?, ?)
            """,
            (raw_text, source, risk_score, verdict, triggered_rules_json),
        )
        conn.commit()
        return cursor.lastrowid


def get_submission_entities_cache() -> dict:
    """
    Used by /report to recall which entities belonged to a submission_id,
    since the client only sends back the submission_id, not the raw text.
    In-memory cache is fine for a hackathon demo (single process).
    """
    return _SUBMISSION_ENTITY_CACHE


_SUBMISSION_ENTITY_CACHE: dict = {}
