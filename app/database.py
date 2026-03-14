import os
import aiosqlite
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "..", "phishing_db.sqlite")

# Note: In a production environment, you would use Redis or Supabase here.
# Example: redis_client = redis.Redis(host='localhost', port=6379, db=0)

async def get_db_connection():
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn

async def init_db():
    async with aiosqlite.connect(DB_PATH) as conn:
        # ===== PHISHING BLACKLIST =====
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                threat_level TEXT,
                source TEXT,
                category TEXT DEFAULT 'Unknown',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.commit()

async def get_db_connection():
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn
