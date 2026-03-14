import sqlite3
from datetime import datetime

import os
# User requested specific DB File: phishing_db.sqlite
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishing_db.sqlite")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS phishing_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            risk_score INTEGER,
            reason TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_to_db(url, domain, risk_score, reason=""):
    conn = sqlite3.connect(DB_PATH)
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
