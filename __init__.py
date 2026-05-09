"""
plugin.py
Binary Ninja UI Plugin integration for the Malware Analyzer.
"""
import binaryninja as bn
from analyzer import MalwareAnalyzer
from threat_intel import ThreatIntelEngine

def format_markdown_report(report) -> str:
    """Converts the typed AnalysisReport into a beautiful Markdown dashboard."""
    md = f"# 🦠 Malware Analysis Report: `{report.file}`\n\n"
    
    # -- RISK SCORE --
    score = report.risk_assessment.score
    risk_color = "🔴 CRITICAL" if score >= 75 else "🟠 HIGH" if score >= 50 else "🟡 MEDIUM" if score >= 25 else "🟢 LOW"
    md += f"## ⚠️ Risk Assessment: {risk_color} ({score}/100)\n"
    for reason in report.risk_assessment.reasons:
        md += f"* {reason}\n"

    # -- CAPABILITIES (MITRE) --
    if report.capabilities:
        md += "\n## 🛡️ MITRE ATT&CK Capabilities\n"
        md += "| Technique | Tactic | Description | Evidence |\n"
        md += "|---|---|---|---|\n"
        for cap in report.capabilities:
            evidence_str = ", ".join(cap.evidence)
            md += f"| **{cap.technique_id}** | {cap.tactic} | {cap.description} | `{evidence_str}` |\n"

    # -- THREAT INTEL --
    md += "\n## 🌐 Threat Intelligence\n"
    vt = report.threat_intel
    md += f"**File Hash (SHA256):** `{vt.file_hash}`\n\n"
    md += f"**VirusTotal:** {vt.vt_positives} / {vt.vt_total} engines detected this.\n\n"
    
    if vt.yara_matches:
        md += "**YARA Matches:**\n"
        for match in vt.yara_matches:
            md += f"* 🎯 `{match.rule_name}`: {match.description}\n"

    # -- SUSPICIOUS FUNCTIONS --
    if report.top_suspicious_functions:
        md += "\n## 🔬 Top Suspicious Functions (Start Reversing Here)\n"
        for func in report.top_suspicious_functions:
            md += f"### 🚩 Function `{func.name}` @ `{func.address}` (Score: {func.suspicion_score})\n"
            for r in func.reasons:
                md += f"* {r}\n"

    # -- IOCs --
    if report.iocs.urls or report.iocs.ips:
        md += "\n## 📡 Network Indicators (IOCs)\n"
        for url in report.iocs.urls:
            md += f"* 🔗 URL: `{url}`\n"
        for ip in report.iocs.ips:
            score = vt.malicious_ips.get(ip, 0)
            md += f"* 🌍 IP: `{ip}` (AbuseIPDB Confidence: {score}%)\n"

    return md


def run_plugin_analysis(bv: bn.BinaryView):
    """The function triggered when the user clicks the plugin button."""
    bn.show_message_box("Malware Analyzer", "Analysis started! Check the log for progress, a report will open shortly.", bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.InformationIcon)
    
    try:
        # Use our analyzer, but pass it the open GUI view!
        with MalwareAnalyzer(bv=bv) as analyzer:
            
            # Since we are in the GUI, we need to extract strings & IPs manually to pass to Threat Intel
            strings = analyzer.extract_strings()
            urls, ips = analyzer.filter_iocs(strings) if hasattr(analyzer, 'filter_iocs') else ([], []) # Fallback if imported differently

            # Gather intel
            ti_engine = ThreatIntelEngine(bv.file.filename)
            threat_intel = ti_engine.gather_intelligence(ips)

            # Run full analysis
            report = analyzer.run_full_analysis()
            # Override threat intel since it was gathered separately for GUI
            report.threat_intel = threat_intel 

            # Format and show!
            markdown_content = format_markdown_report(report)
            bv.show_markdown_report(f"Analysis: {bv.file.filename}", markdown_content)
            
    except Exception as e:
        bn.log_error(f"Malware Analyzer Plugin crashed: {e}")
        bn.show_message_box("Error", f"Analysis failed: {e}", bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.ErrorIcon)


# Register the command in the Binary Ninja UI menu
bn.PluginCommand.register(
    "Malware Analyzer \\ Run Full Triage",
    "Runs the automated malware triage engine and generates a report.",
    run_plugin_analysis
)