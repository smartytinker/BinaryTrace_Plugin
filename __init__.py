"""
plugin.py / __init__.py
Binary Ninja UI Plugin integration with an Advanced HTML Dashboard.
"""
import binaryninja as bn
from analyzer import MalwareAnalyzer
from threat_intel import ThreatIntelEngine
from database import DatabaseManager

def format_html_report(report) -> str:
    """Generates a professional, styled HTML dashboard for the analysis results."""
    
    # 1. Sleek Dark Mode CSS
    css = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #c9d1d9; line-height: 1.6; }
        .container { padding: 20px; max-width: 1200px; margin: 0 auto; }
        .header { border-bottom: 2px solid #30363d; padding-bottom: 15px; margin-bottom: 25px; }
        h1 { color: #58a6ff; font-size: 2em; margin: 0; }
        h2 { color: #8b949e; margin-top: 35px; border-bottom: 1px solid #30363d; padding-bottom: 5px; }
        h3 { color: #c9d1d9; }
        
        /* Badges */
        .badge { display: inline-block; padding: 4px 10px; font-size: 0.85em; font-weight: 600; border-radius: 2em; margin-bottom: 10px; }
        .badge-critical { background-color: #da3633; color: white; }
        .badge-high { background-color: #d29922; color: white; }
        .badge-medium { background-color: #b08800; color: white; }
        .badge-low { background-color: #238636; color: white; }
        .badge-info { background-color: #1f6feb; color: white; }
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.95em; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background-color: #161b22; color: #8b949e; text-transform: uppercase; font-size: 0.85em; }
        tr:hover { background-color: #161b22; }
        
        /* Code blocks & Cards */
        .code { background-color: #161b22; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; color: #ff7b72; }
        .card { background-color: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-bottom: 15px; }
        ul { margin: 0; padding-left: 20px; }
    </style>
    """

    # 2. Determine Risk Color
    score = report.risk_assessment.score
    if score >= 75:
        risk_class, risk_label = "badge-critical", "CRITICAL"
    elif score >= 50:
        risk_class, risk_label = "badge-high", "HIGH"
    elif score >= 25:
        risk_class, risk_label = "badge-medium", "MEDIUM"
    else:
        risk_class, risk_label = "badge-low", "LOW"

    # 3. Build HTML Body
    html = f"<html><head>{css}</head><body><div class='container'>"
    
    # Header
    html += f"""
    <div class='header'>
        <h1>🦠 Malware Triage Report</h1>
        <p style='color: #8b949e;'>Target: <span class='code'>{report.file}</span></p>
        <span class='badge {risk_class}'>Risk Score: {score}/100 ({risk_label})</span>
        <span class='badge badge-info'>SHA256: {report.threat_intel.file_hash}</span>
    </div>
    """

    # Capabilities Table
    if report.capabilities:
        html += "<h2>🛡️ Detected MITRE ATT&CK Capabilities</h2>"
        html += "<table><tr><th>Technique ID</th><th>Tactic</th><th>Description</th><th>Evidence</th></tr>"
        for cap in report.capabilities:
            evidence = ", ".join([f"<span class='code'>{e}</span>" for e in cap.evidence])
            html += f"<tr><td><strong>{cap.technique_id}</strong></td><td>{cap.tactic}</td><td>{cap.description}</td><td>{evidence}</td></tr>"
        html += "</table>"

    # Threat Intel Section
    vt = report.threat_intel
    html += "<h2>🌐 External Threat Intelligence</h2>"
    html += "<div class='card'>"
    html += f"<p><strong>VirusTotal Detections:</strong> {vt.vt_positives} / {vt.vt_total}</p>"
    if vt.yara_matches:
        html += "<p><strong>YARA Signatures Triggered:</strong></p><ul>"
        for match in vt.yara_matches:
            html += f"<li><span class='code'>{match.rule_name}</span>: {match.description}</li>"
        html += "</ul>"
    else:
        html += "<p><em>No local YARA signatures triggered.</em></p>"
    html += "</div>"

    # Suspicious Functions
    if report.top_suspicious_functions:
        html += "<h2>🔬 Top Suspicious Functions</h2>"
        for func in report.top_suspicious_functions:
            html += f"<div class='card'>"
            html += f"<h3>🚩 {func.name} @ <span class='code'>{func.address}</span> <span class='badge badge-high' style='float:right;'>Score: {func.suspicion_score}</span></h3>"
            html += "<ul>"
            for r in func.reasons:
                html += f"<li>{r}</li>"
            html += "</ul></div>"

    html += "</div></body></html>"
    return html
def run_plugin_analysis(bv: bn.BinaryView):
    """The function triggered when the user clicks the plugin button."""
    bn.show_message_box("Malware Analyzer", "Analysis started! Check the log for progress.", bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.InformationIcon)
    
    try:
        db = DatabaseManager()
        ti_engine = ThreatIntelEngine(bv.file.filename)
        
        # 1. EARLY EXIT: Check if we already analyzed this file!
        file_hash = ti_engine.get_file_hash()
        if db.sample_exists(file_hash):
            bn.log_info(f"CACHE HIT: Loading existing report for {file_hash}")
            cached_report = db.get_report(file_hash)
            
            if cached_report:
                html_content = format_html_report(cached_report) # <--- Fixed!
                bv.show_html_report(f"Analysis (Cached): {bv.file.filename}", html_content) # <--- Fixed!
                return  # We are done! Skip the rest of the analysis.

        # 2. CACHE MISS: Run the full heavy analysis
        bn.log_info(f"CACHE MISS: Running full triage for {file_hash}")
        with MalwareAnalyzer(bv=bv) as analyzer:
            
            strings = analyzer.extract_strings()
            urls, ips = analyzer.filter_iocs(strings) if hasattr(analyzer, 'filter_iocs') else ([], [])

            # Gather intel
            threat_intel = ti_engine.gather_intelligence(ips)

            # Run full analysis
            report = analyzer.run_full_analysis()
            report.threat_intel = threat_intel 

            # Save to the enterprise database
            try:
                db.save_report(report)
            except Exception as e:
                bn.log_error(f"Database save failed: {e}")
                
            # Format and show HTML!
            html_content = format_html_report(report)
            bv.show_html_report(f"Analysis: {bv.file.filename}", html_content)
            
    except Exception as e:
        bn.log_error(f"Malware Analyzer Plugin crashed: {e}")
        bn.show_message_box("Error", f"Analysis failed: {e}", bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.ErrorIcon)


# Register the command in the Binary Ninja UI menu
bn.PluginCommand.register(
    "Malware Analyzer \\ Run Full Triage",
    "Runs the automated malware triage engine and generates a report.",
    run_plugin_analysis
)