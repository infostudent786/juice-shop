import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

# --- Configuration ---
REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
OUTPUT_FILE = os.path.join(REPORTS_DIR, "dashboard.html")

def load_json(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
    return None

def parse_dependency_check(filename):
    path = os.path.join(REPORTS_DIR, filename)
    sca_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    if os.path.exists(path):
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            ns = {'ns': 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd'}
            for dependency in root.findall('.//ns:dependency', ns):
                vulnerabilities = dependency.find('ns:vulnerabilities', ns)
                if vulnerabilities is not None:
                    for v in vulnerabilities.findall('ns:vulnerability', ns):
                        sca_summary["total"] += 1
                        severity = v.find('ns:severity', ns).text
                        if severity == "CRITICAL": sca_summary["critical"] += 1
                        elif severity == "HIGH": sca_summary["high"] += 1
                        elif severity == "MEDIUM": sca_summary["medium"] += 1
                        elif severity == "LOW": sca_summary["low"] += 1
        except Exception as e:
            print(f"Error parsing {filename}: {e}")
    return sca_summary

def parse_zap_report(filename):
    data = load_json(filename)
    zap_summary = {"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    if data and "site" in data:
        for site in data["site"]:
            for alert in site.get("alerts", []):
                zap_summary["total"] += 1
                risk = alert.get("riskdesc", "").split(" (")[0]
                if risk == "High": zap_summary["high"] += 1
                elif risk == "Medium": zap_summary["medium"] += 1
                elif risk == "Low": zap_summary["low"] += 1
                elif risk == "Informational": zap_summary["informational"] += 1
    return zap_summary

def parse_jmeter_results(filename):
    path = os.path.join(REPORTS_DIR, filename)
    perf_summary = {"samples": 0, "errors": 0, "avg_rt": 0, "max_rt": 0}
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:] # Skip header
                if lines:
                    rts = []
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) >= 8:
                            perf_summary["samples"] += 1
                            rts.append(int(parts[1]))
                            if parts[7] == "false":
                                perf_summary["errors"] += 1
                    if rts:
                        perf_summary["avg_rt"] = sum(rts) / len(rts)
                        perf_summary["max_rt"] = max(rts)
        except Exception as e:
            print(f"Error parsing {filename}: {e}")
    return perf_summary

def generate_dashboard():
    # 1. Parse all results
    sca = parse_dependency_check("dependency-check-report.xml")
    zap = parse_zap_report("zap-report.json")
    perf = parse_jmeter_results("jmeter-results.jtl")
    # For Sonar, we'll assume a summary is provided or we'll mock it if not available
    sonar = load_json("sonar-summary.json") or {"critical": 0, "major": 0, "minor": 0}

    # 2. Rule-Based AI Logic
    recommendations = []
    risk_level = "LOW"
    
    if sca["critical"] > 0 or sonar["critical"] > 0 or zap["high"] > 0:
        risk_level = "CRITICAL"
        recommendations.append({"priority": "HIGH", "issue": "Critical vulnerabilities detected in code/dependencies", "fix": "Immediate remediation required for production deployment."})
    elif sca["high"] > 0 or zap["medium"] > 0:
        risk_level = "HIGH"
        recommendations.append({"priority": "MEDIUM", "issue": "High severity security findings", "fix": "Address high-priority issues within 48 hours."})
    
    if perf["errors"] > (perf["samples"] * 0.05):
        recommendations.append({"priority": "HIGH", "issue": f"High error rate in performance test ({perf['errors']} errors)", "fix": "Re-check server stability and database connections."})
    
    if perf["avg_rt"] > 1000:
        recommendations.append({"priority": "LOW", "issue": "High average response latency", "fix": "Investigate frontend bundling and API response times."})

    # 3. Build HTML
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>DevSecOps AI Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: auto; }}
            header {{ text-align: center; padding-bottom: 40px; border-bottom: 2px solid #1e293b; margin-bottom: 40px; }}
            h1 {{ color: #38bdf8; margin: 0; font-size: 2.5rem; }}
            .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }}
            .card {{ background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); }}
            .card h3 {{ margin-top: 0; color: #94a3b8; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; }}
            .card div {{ font-size: 2rem; font-weight: bold; color: #f1f5f9; }}
            .card.risk-CRITICAL {{ border-left: 5px solid #ef4444; }}
            .card.risk-HIGH {{ border-left: 5px solid #f97316; }}
            .card.risk-MEDIUM {{ border-left: 5px solid #facc15; }}
            .card.risk-LOW {{ border-left: 5px solid #22c55e; }}
            .ai-section {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 30px; border-radius: 16px; border: 1px solid #38bdf8; margin-bottom: 40px; }}
            .ai-title {{ display: flex; align-items: center; font-size: 1.5rem; font-weight: bold; margin-bottom: 20px; color: #38bdf8; }}
            .ai-title span {{ margin-right: 10px; font-size: 2rem; }}
            .recommendation-item {{ background: #334155; padding: 15px; border-radius: 8px; margin-bottom: 10px; display: flex; align-items: flex-start; gap: 15px; border-left: 4px solid #38bdf8; }}
            .rec-priority {{ font-weight: bold; color: #38bdf8; min-width: 80px; }}
            .rec-content {{ flex-grow: 1; }}
            .rec-fix {{ font-size: 0.85rem; color: #94a3b8; margin-top: 5px; }}
            .details-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #334155; }}
            th {{ color: #94a3b8; font-size: 0.85rem; }}
            .footer {{ text-align: center; margin-top: 50px; color: #64748b; font-size: 0.8rem; }}
            .status-tag {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
            .status-RED {{ background: #ef4444; color: white; }}
            .status-YELLOW {{ background: #facc15; color: #0f172a; }}
            .status-GREEN {{ background: #22c55e; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>DevSecOps Intelligence Suite</h1>
                <p>Security Analysis & Performance Report | Last Updated: {now}</p>
            </header>

            <div class="summary-cards">
                <div class="card risk-{risk_level}">
                    <h3>Overall Risk Profile</h3>
                    <div>{risk_level}</div>
                </div>
                <div class="card">
                    <h3>SAST/SCA Issues</h3>
                    <div>{sca['critical'] + sca['high'] + sonar['critical']}</div>
                </div>
                <div class="card">
                    <h3>DAST (ZAP) High/Med</h3>
                    <div>{zap['high'] + zap['medium']}</div>
                </div>
                <div class="card">
                    <h3>Performance (Avg RT)</h3>
                    <div>{int(perf['avg_rt'])}ms</div>
                </div>
            </div>

            <div class="ai-section">
                <div class="ai-title"><span>🤖</span> AI Security Analyst — Insights</div>
                {''.join([f'''
                <div class="recommendation-item">
                    <div class="rec-priority">{r['priority']}</div>
                    <div class="rec-content">
                        <strong>{r['issue']}</strong>
                        <div class="rec-fix">Recommended Fix: {r['fix']}</div>
                    </div>
                </div>
                ''' for r in recommendations]) if recommendations else '<p style="color: #22c55e;">No critical security or performance issues found. System is stable.</p>'}
            </div>

            <div class="details-grid">
                <div class="card">
                    <h3>SCA Vulnerabilities (Dependency-Check)</h3>
                    <table>
                        <tr><th>Severity</th><th>Count</th></tr>
                        <tr><td>Critical</td><td>{sca['critical']}</td></tr>
                        <tr><td>High</td><td>{sca['high']}</td></tr>
                        <tr><td>Medium</td><td>{sca['medium']}</td></tr>
                        <tr><td>Low</td><td>{sca['low']}</td></tr>
                    </table>
                </div>
                <div class="card">
                    <h3>DAST Findings (OWASP ZAP)</h3>
                    <table>
                        <tr><th>Risk Level</th><th>Alerts</th></tr>
                        <tr><td>High</td><td>{zap['high']}</td></tr>
                        <tr><td>Medium</td><td>{zap['medium']}</td></tr>
                        <tr><td>Low</td><td>{zap['low']}</td></tr>
                        <tr><td>Informational</td><td>{zap['informational']}</td></tr>
                    </table>
                </div>
                <div class="card">
                    <h3>Performance Benchmark (JMeter)</h3>
                    <table>
                        <tr><th>Metric</th><th>Value</th></tr>
                        <tr><td>Total Requests</td><td>{perf['samples']}</td></tr>
                        <tr><td>Failed Requests</td><td>{perf['errors']}</td></tr>
                        <tr><td>Average Latency</td><td>{int(perf['avg_rt'])}ms</td></tr>
                        <tr><td>Max Latency</td><td>{perf['max_rt']}ms</td></tr>
                    </table>
                </div>
                <div class="card">
                    <h3>SAST Findings (SonarQube)</h3>
                    <table>
                        <tr><th>Issue Type</th><th>Count</th></tr>
                        <tr><td>Critical</td><td>{sonar['critical']}</td></tr>
                        <tr><td>Major</td><td>{sonar['major']}</td></tr>
                        <tr><td>Minor</td><td>{sonar['minor']}</td></tr>
                    </table>
                </div>
            </div>

            <div class="footer">
                &copy; DevSecOps Pipeline Automation | Created by Antigravity AI
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(OUTPUT_FILE, "w") as f:
        f.write(html_content)
    print(f"Dashboard generated at: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_dashboard()
