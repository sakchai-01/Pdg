from app.core.database import get_sync_db_connection
from datetime import datetime

def save_to_db(url, domain, risk_score, reason=""):
    conn = get_sync_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO phishing_urls (url, domain, risk_score, reason, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        domain,
        risk_score,
        reason,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()
