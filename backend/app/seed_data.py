"""
seed_data.py
------------
Populates the threat graph with realistic-looking (but fake) scam entities
so the demo can show "this has been reported N times before" without
needing real users first. This solves the cold-start problem called out
on the whiteboard.

Run once: python -m app.seed_data
"""

from app.database import init_db, get_connection

SEED_ENTITIES = [
    # (entity_type, value, report_count)
    ("phone", "9123456780", 14),
    ("phone", "9988776655", 7),
    ("phone", "8877665544", 22),
    ("upi_id", "kyc-update@ybl", 31),
    ("upi_id", "refund2024@oksbi", 9),
    ("upi_id", "prizewinner@paytm", 18),
    ("domain", "sbi-kyc-verify.xyz", 27),
    ("domain", "paytm-reward.top", 12),
    ("domain", "hdfc-secure-login.info", 19),
    ("domain", "irctc-refund.click", 6),
    ("domain", "bit.ly", 3),  # shorteners get a small baseline, not scam-specific
]


def seed():
    """
    Idempotent seeding: inserts baseline demo entities ONLY if they don't
    already exist. On first-ever run this populates the cold-start demo
    data as before.

    Critical fix for cloud deployment: the original version used
    "ON CONFLICT ... DO UPDATE SET report_count = excluded.report_count",
    which RESET the count back to the seed baseline every single time
    seed() ran — including on every server restart. In production we call
    seed() automatically on every startup (see main.py) so the app never
    ships without demo data; with the old UPDATE behavior, that would have
    silently wiped out every real report a real user had submitted in
    between restarts. DO NOTHING makes seeding safe to call any number of
    times without ever touching real, already-existing data.
    """
    init_db()
    with get_connection() as conn:
        for entity_type, value, count in SEED_ENTITIES:
            conn.execute(
                """
                INSERT INTO entities (entity_type, entity_value, report_count)
                VALUES (?, ?, ?)
                ON CONFLICT(entity_type, entity_value) DO NOTHING
                """,
                (entity_type, value, count),
            )
        conn.commit()
    print(f"Seed check complete ({len(SEED_ENTITIES)} baseline entities, existing data untouched).")


if __name__ == "__main__":
    seed()
