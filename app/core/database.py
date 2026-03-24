import os
import aiosqlite
import sqlite3
from datetime import datetime

# Define Absolute Path for Database
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(PROJECT_ROOT, "phishing_db.sqlite")

async def get_db_connection():
    """
    Async connection for FastAPI routes
    """
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn

def get_sync_db_connection():
    """
    Sync connection for background threads (Scraper/Crawler)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

async def init_db():
    """
    Initialize all required tables in one place
    """
    # 1. Table for Blacklists (API/Manual)
    # 2. Table for Phishing URLs (Scraper/Crawler)
    
    # We will consolidate them into a more robust schema or keep both for compatibility but managed here.
    async with aiosqlite.connect(DB_PATH) as conn:
        # Table: blacklists
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                domain TEXT,
                threat_level TEXT,
                source TEXT,
                category TEXT DEFAULT 'Unknown',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table: phishing_urls (for scraper compatibility)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS phishing_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                domain TEXT,
                risk_score INTEGER,
                reason TEXT,
                created_at TEXT
            )
        """)
        
        await conn.commit()
