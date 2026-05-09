"""
api.py
Enterprise REST API to query the Malware Analysis Database.
"""
from fastapi import FastAPI, HTTPException
from database import DatabaseManager
import uvicorn
import os

# Initialize the API
app = FastAPI(
    title="Malware Triage Engine API",
    description="REST API for querying analyzed malware samples and their IOCs.",
    version="1.0"
)

# Initialize the Database connection
db = DatabaseManager()

@app.get("/")
def read_root():
    """Health check endpoint."""
    return {"status": "online", "message": "Malware Triage API is running."}

@app.get("/report/{file_hash}")
def get_report(file_hash: str):
    """Fetches a complete analysis report by its SHA256 hash."""
    if not db.sample_exists(file_hash):
        raise HTTPException(status_code=404, detail="Sample not found in database.")
    
    report = db.get_report(file_hash)
    return report.to_dict()

@app.get("/iocs/{file_hash}")
def get_iocs(file_hash: str):
    """Fetches just the networking IOCs (URLs and IPs) for a specific sample."""
    if not db.sample_exists(file_hash):
        raise HTTPException(status_code=404, detail="Sample not found in database.")
    
    report = db.get_report(file_hash)
    return {
        "file_hash": file_hash,
        "urls": report.iocs.urls,
        "ips": report.iocs.ips
    }

if __name__ == "__main__":
    print("🚀 Starting Enterprise Malware API...")
    print("🔗 Interactive API Docs available at: http://127.0.0.1:8000/docs")
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)