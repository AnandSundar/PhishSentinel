"""
Database Module for PhishSentinel
Provides SQLite storage for analysis history.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
import os


# Database path
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "phishsentinel.db"
)


def init_database() -> None:
    """
    Initialize the SQLite database with required tables.
    Creates the data directory if it doesn't exist.
    """
    # Create data directory if it doesn't exist
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    # Create connection and cursor
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create analyses table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            summary TEXT,
            raw_json TEXT NOT NULL,
            sender_email TEXT,
            subject TEXT
        )
    """
    )

    # Create index for timestamp
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_timestamp ON analyses(timestamp DESC)
    """
    )

    conn.commit()
    conn.close()


def save_analysis(
    analysis_id: str,
    threat_score: int,
    threat_level: str,
    summary: str,
    raw_state: Dict[str, Any],
    sender_email: Optional[str] = None,
    subject: Optional[str] = None,
) -> bool:
    """
    Save analysis result to database.

    Args:
        analysis_id: Unique analysis identifier
        threat_score: Calculated threat score
        threat_level: Threat level string
        summary: Summary report
        raw_state: Full state dictionary
        sender_email: Sender email address
        subject: Email subject

    Returns:
        True if successful, False otherwise
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        timestamp = datetime.now().isoformat()

        # Convert state to JSON
        raw_json = json.dumps(raw_state, default=str)

        cursor.execute(
            """
            INSERT INTO analyses (id, timestamp, threat_score, threat_level, summary, raw_json, sender_email, subject)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                analysis_id,
                timestamp,
                threat_score,
                threat_level,
                summary,
                raw_json,
                sender_email,
                subject,
            ),
        )

        conn.commit()
        conn.close()

        return True
    except Exception as e:
        print(f"Error saving analysis: {e}")
        return False


def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a specific analysis by ID.

    Args:
        analysis_id: Analysis identifier

    Returns:
        Analysis dictionary or None if not found
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, timestamp, threat_score, threat_level, summary, raw_json, sender_email, subject
            FROM analyses
            WHERE id = ?
        """,
            (analysis_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "id": row[0],
                "timestamp": row[1],
                "threat_score": row[2],
                "threat_level": row[3],
                "summary": row[4],
                "raw_json": row[5],
                "sender_email": row[6],
                "subject": row[7],
            }

        return None
    except Exception as e:
        print(f"Error retrieving analysis: {e}")
        return None


def get_analysis_history(limit: int = 20) -> List[Dict[str, Any]]:
    """
    Retrieve analysis history.

    Args:
        limit: Maximum number of records to retrieve

    Returns:
        List of analysis dictionaries
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, timestamp, threat_score, threat_level, summary, sender_email, subject
            FROM analyses
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            results.append(
                {
                    "id": row[0],
                    "timestamp": row[1],
                    "threat_score": row[2],
                    "threat_level": row[3],
                    "summary": row[4][:200] if row[4] else "",  # Truncate summary
                    "sender_email": row[5],
                    "subject": row[6],
                }
            )

        return results
    except Exception as e:
        print(f"Error retrieving history: {e}")
        return []


def delete_analysis(analysis_id: str) -> bool:
    """
    Delete an analysis by ID.

    Args:
        analysis_id: Analysis identifier

    Returns:
        True if successful, False otherwise
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))

        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()

        return deleted
    except Exception as e:
        print(f"Error deleting analysis: {e}")
        return False


def get_statistics() -> Dict[str, Any]:
    """
    Get statistics about stored analyses.

    Returns:
        Dictionary with statistics
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Total count
        cursor.execute("SELECT COUNT(*) FROM analyses")
        total = cursor.fetchone()[0]

        # Average threat score
        cursor.execute("SELECT AVG(threat_score) FROM analyses")
        avg_score = cursor.fetchone()[0] or 0

        # Threat level distribution
        cursor.execute(
            """
            SELECT threat_level, COUNT(*) 
            FROM analyses 
            GROUP BY threat_level
        """
        )
        distribution = dict(cursor.fetchall())

        # Recent analyses (last 7 days)
        cursor.execute(
            """
            SELECT COUNT(*) FROM analyses
            WHERE timestamp > datetime('now', '-7 days')
        """
        )
        recent_count = cursor.fetchone()[0]

        conn.close()

        return {
            "total_analyses": total,
            "average_threat_score": round(avg_score, 2),
            "threat_level_distribution": distribution,
            "recent_analyses_7_days": recent_count,
        }
    except Exception as e:
        print(f"Error getting statistics: {e}")
        return {
            "total_analyses": 0,
            "average_threat_score": 0,
            "threat_level_distribution": {},
            "recent_analyses_7_days": 0,
        }


def parse_raw_json(raw_json: str) -> Dict[str, Any]:
    """
    Parse raw JSON string back to dictionary.

    Args:
        raw_json: JSON string

    Returns:
        Parsed dictionary
    """
    try:
        return json.loads(raw_json)
    except Exception as e:
        print(f"Error parsing raw JSON: {e}")
        return {}


# Initialize database on module import
init_database()
