import sqlite3
from pathlib import Path
from datetime import datetime

# Get the folder containing database.py
BASE_DIR = Path(__file__).resolve().parent

# Create a dedicated database folder
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Store the SQLite database inside the data folder
DB_PATH = DATA_DIR / "phishshift.db"


def init_db():
    try:
        with sqlite3.connect(str(DB_PATH)) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_preview TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    risk TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    scanned_at TEXT NOT NULL
                )
            """)
            connection.commit()

        print(f"Database ready: {DB_PATH}")

    except sqlite3.Error as error:
        print(f"Database error: {error}")
        raise


def save_scan(message, result):
    preview = message.replace("\n", " ")[:180]
    scanned_at = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    with sqlite3.connect(str(DB_PATH)) as connection:
        connection.execute("""
            INSERT INTO scans (
                message_preview,
                score,
                risk,
                prediction,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            preview,
            result["score"],
            result["risk"],
            result["prediction"],
            scanned_at
        ))
        connection.commit()


def get_recent_scans(limit=5):
    with sqlite3.connect(str(DB_PATH)) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT message_preview, score, risk,
                   prediction, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]