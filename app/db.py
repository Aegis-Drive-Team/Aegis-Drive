# db.py – handles all database stuff so app.py and other files stay clean
# switched from SQLite to Supabase Postgres (using psycopg + dotenv)

import os
import sqlite3

DB_DIR = os.getenv("DB_DIR", ".")              # e.g., /var/data on Render (Disk mount)
os.makedirs(DB_DIR, exist_ok=True)             # ensure path exists
DB_FILE = os.path.join(DB_DIR, "lookups.db")

def get_connection():
    return sqlite3.connect(DB_FILE)

#creates the database locally each time it's run
def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        report_source TEXT,          -- 'AbuseIPDB', 'User', 'System'
        category TEXT,               -- 'SSH Attack', 'Spam', etc.
        report TEXT,                 -- free text/summary
        observed_at TEXT,            -- when provider says it was seen
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()
    init_user_db()

def init_user_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT CHECK(role IN ('admin', 'user')) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()


# function to insert ip address and information about it into the database
def insert_report(ip: str, report_source: str, category: str, report: str, observed_at: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ip_reports (ip, report_source, category, report, observed_at)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, report_source, category, report, observed_at))
    conn.commit()
    conn.close()

# function to retrieve reports  
def get_reports_by_ip(ip):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ip, report_source, category, report, observed_at, created_at
        FROM ip_reports
        WHERE ip = ?
        ORDER BY created_at DESC
    """, (ip,))
    rows = cur.fetchall()
    conn.close()
    return rows
