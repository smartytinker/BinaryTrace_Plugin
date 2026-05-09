"""
database.py
Handles SQLite database operations for sample deduplication and history tracking.
"""
import sqlite3
import json
import os
import logging
from datetime import datetime
from models import AnalysisReport

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_name="malware_history.db"):
        # Store the database in the exact same folder as the plugin
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.path.join(current_dir, db_name)
        self._init_db()

    def _init_db(self):
        """Creates the necessary tables if they don't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Table for storing the core sample data
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS samples (
                        file_hash TEXT PRIMARY KEY,
                        file_name TEXT,
                        timestamp TEXT,
                        risk_score INTEGER,
                        is_packed BOOLEAN,
                        raw_report_json TEXT
                    )
                ''')
                
                # Table for storing IOCs to allow cross-referencing later
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS iocs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_hash TEXT,
                        ioc_type TEXT,
                        value TEXT,
                        FOREIGN KEY(file_hash) REFERENCES samples(file_hash)
                    )
                ''')
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")

    def sample_exists(self, file_hash: str) -> bool:
        """Checks if we have already analyzed this exact file."""
        if not file_hash or file_hash == "UNKNOWN":
            return False
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM samples WHERE file_hash = ?", (file_hash,))
            return cursor.fetchone() is not None

    def save_report(self, report: AnalysisReport):
        """Saves the fully typed analysis report into the database."""
        file_hash = report.threat_intel.file_hash
        
        # Don't save if we somehow failed to hash it
        if not file_hash or file_hash == "UNKNOWN":
            logger.warning("Cannot save report to DB: Missing file hash.")
            return

        timestamp = datetime.utcnow().isoformat()
        raw_json = json.dumps(report.to_dict())

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 1. Insert the main sample record
                cursor.execute('''
                    INSERT OR REPLACE INTO samples 
                    (file_hash, file_name, timestamp, risk_score, is_packed, raw_report_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    file_hash, 
                    report.file, 
                    timestamp, 
                    report.risk_assessment.score, 
                    report.packer_info.is_packed, 
                    raw_json
                ))
                
                # 2. Insert the IOCs (URLs)
                for url in report.iocs.urls:
                    cursor.execute('INSERT INTO iocs (file_hash, ioc_type, value) VALUES (?, ?, ?)', 
                                 (file_hash, 'URL', url))
                
                # 3. Insert the IOCs (IPs)
                for ip in report.iocs.ips:
                    cursor.execute('INSERT INTO iocs (file_hash, ioc_type, value) VALUES (?, ?, ?)', 
                                 (file_hash, 'IP', ip))
                                 
                conn.commit()
                logger.info(f"Successfully saved report for {file_hash} to database.")
                
        except Exception as e:
            logger.error(f"Failed to save report to database: {e}")
        
    def get_report(self, file_hash: str) -> AnalysisReport:
        """Fetches a saved report from the database and reconstructs it."""
        if not file_hash:
            return None

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT raw_report_json FROM samples WHERE file_hash = ?", (file_hash,))
                row = cursor.fetchone()

                if row:
                    raw_json = json.loads(row[0])
                    return AnalysisReport.from_dict(raw_json)
        except Exception as e:
            logger.error(f"Failed to fetch report from database: {e}")
            
        return None