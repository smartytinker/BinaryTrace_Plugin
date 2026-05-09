"""
api.py
Enterprise REST API with a styled landing page and custom Swagger UI.
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html
from database import DatabaseManager
import uvicorn

# 1. Professional API Metadata
app = FastAPI(
    title="TriageEngine Pro",
    description="""
    **Enterprise Automated Malware Analysis API.**
    
    This API provides programmatic access to the malware analysis database. 
    Integrate these endpoints with your SIEM, SOAR, or EDR platforms to fetch 
    IOCs, MITRE mappings, and behavioral telemetry instantly.
    """,
    version="2.0.0",
    contact={
        "name": "Security Operations Center",
        "url": "https://your-company.com/security",
    },
    docs_url=None  # <-- NEW: Turn off the default boring docs
)
db = DatabaseManager()

# 2. Sleek Tailwind CSS Landing Page for the Root URL
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def read_root():
    """Renders a professional landing page for the API."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TriageEngine Pro API</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-gray-100 font-sans antialiased flex items-center justify-center h-screen">
        <div class="max-w-2xl bg-gray-800 p-10 rounded-lg shadow-2xl border border-gray-700">
            <div class="flex items-center mb-6">
                <svg class="w-10 h-10 text-blue-500 mr-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                <h1 class="text-4xl font-bold tracking-tight text-white">TriageEngine Pro</h1>
            </div>
            
            <p class="text-lg text-gray-400 mb-8">
                Welcome to the Enterprise Malware Analysis API. The backend database is currently online and accepting queries.
            </p>
            
            <div class="flex space-x-4">
                <a href="/docs" class="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-md shadow-lg transition duration-200">
                    Open API Dashboard (Swagger)
                </a>
                <a href="/redoc" class="bg-gray-700 hover:bg-gray-600 text-white font-semibold py-3 px-6 rounded-md shadow-lg transition duration-200 border border-gray-600">
                    View Redoc Specs
                </a>
            </div>
            
            <div class="mt-10 pt-6 border-t border-gray-700 text-sm text-gray-500">
                <p>System Status: <span class="text-green-400 font-bold">ONLINE</span> • Connected to local SQLite Cache</p>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/docs", include_in_schema=False)
def custom_swagger_ui_html():
    """Overrides the default Swagger UI metadata without breaking the layout."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - API Dashboard",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        # We removed the broken CSS theme line here!
        swagger_favicon_url="https://cdn-icons-png.flaticon.com/512/2092/2092063.png"
    )
# --- Keep your existing endpoints exactly the same below ---

@app.get("/report/{file_hash}", tags=["Reports"])
def get_report(file_hash: str):
    """Fetches a complete analysis report by its SHA256 hash."""
    if not db.sample_exists(file_hash):
        raise HTTPException(status_code=404, detail="Sample not found in database.")
    return db.get_report(file_hash).to_dict()

@app.get("/iocs/{file_hash}", tags=["Threat Intelligence"])
def get_iocs(file_hash: str):
    """Fetches just the networking IOCs (URLs and IPs) for a specific sample."""
    if not db.sample_exists(file_hash):
        raise HTTPException(status_code=404, detail="Sample not found in database.")
    report = db.get_report(file_hash)
    return {"file_hash": file_hash, "urls": report.iocs.urls, "ips": report.iocs.ips}

if __name__ == "__main__":
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)