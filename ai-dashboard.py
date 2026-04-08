#!/usr/bin/env python3
"""
SHIVA AI — Free DevSecOps Intelligence Dashboard
Expert-system AI engine: zero API cost, full OWASP Top 10 coverage,
deterministic security analysis derived entirely from scan outputs.
"""

import json, os, csv, math
from datetime import datetime

REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
OUTPUT_FILE = os.path.join(REPORTS_DIR, "dashboard.html")
BUILD_NUMBER = os.getenv("BUILD_NUMBER", "local")
JOB_NAME    = os.getenv("JOB_NAME", "devsecops-juice-shop")
BUILD_URL   = os.getenv("BUILD_URL", "#")
APP_URL     = os.getenv("APP_URL", "http://localhost:3000")

# ─────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 (2021) knowledge base
# ─────────────────────────────────────────────────────────────────────────────
OWASP_TOP10 = {
    "A01": {"name": "Broken Access Control",      "color": "#ef4444"},
    "A02": {"name": "Cryptographic Failures",      "color": "#f97316"},
    "A03": {"name": "Injection",                   "color": "#ef4444"},
    "A04": {"name": "Insecure Design",             "color": "#f59e0b"},
    "A05": {"name": "Security Misconfiguration",   "color": "#f59e0b"},
    "A06": {"name": "Vulnerable Components",        "color": "#ef4444"},
    "A07": {"name": "Auth Failures",               "color": "#ef4444"},
    "A08": {"name": "Data Integrity Failures",     "color": "#f97316"},
    "A09": {"name": "Logging Failures",            "color": "#f59e0b"},
    "A10": {"name": "SSRF",                        "color": "#f97316"},
}

# CWE → OWASP mapping used by the AI engine
CWE_TO_OWASP = {
    "89":  "A03", "564": "A03", "943": "A03",          # Injection
    "79":  "A03", "80": "A03",                          # XSS → Injection
    "22":  "A01", "284": "A01", "285": "A01",           # Access Control
    "326": "A02", "327": "A02", "328": "A02",           # Crypto
    "759": "A02", "916": "A02",
    "287": "A07", "307": "A07", "521": "A07",           # Auth
    "601": "A01", "639": "A01",                         # IDOR / Redirect
    "502": "A08", "915": "A08",                         # Deserialization
    "1021":"A05", "693": "A05", "346": "A05",           # Misconfiguration
    "200": "A02", "359": "A02",                         # Info Disclosure
    "918": "A10",                                       # SSRF
    "400": "A05", "770": "A05",                         # Resource exhaustion
}

# ZAP alert name → OWASP mapping
ZAP_NAME_TO_OWASP = {
    "sql injection":              "A03",
    "xss":                        "A03",
    "cross site scripting":       "A03",
    "path traversal":             "A01",
    "missing csp":                "A05",
    "content security policy":    "A05",
    "cors":                       "A05",
    "x-frame-options":            "A05",
    "anti-csrf":                  "A05",
    "csrf":                       "A05",
    "cookie":                     "A02",
    "secure flag":                "A02",
    "httponly":                   "A02",
    "sensitive data":             "A02",
    "information disclosure":     "A02",
    "authentication":             "A07",
    "session":                    "A07",
    "ssrf":                       "A10",
    "server side request":        "A10",
    "directory browsing":         "A05",
    "heartbleed":                 "A06",
    "vulnerable":                 "A06",
}

# CVE severity rules with OWASP links
CVE_RULES = {
    "log4j":        {"owasp": "A06", "desc": "Log4Shell RCE", "fix": "Upgrade log4j-core to ≥2.17.1"},
    "spring":       {"owasp": "A06", "desc": "Spring4Shell RCE", "fix": "Upgrade Spring Framework to ≥5.3.18"},
    "protobuf":     {"owasp": "A08", "desc": "Deserialization vuln", "fix": "Upgrade protobufjs to ≥6.11.4"},
    "lodash":       {"owasp": "A03", "desc": "Prototype pollution", "fix": "Upgrade lodash to ≥4.17.21"},
    "express":      {"owasp": "A05", "desc": "Security misconfiguration", "fix": "Upgrade express to latest"},
    "jsonwebtoken": {"owasp": "A07", "desc": "Auth bypass", "fix": "Upgrade jsonwebtoken to ≥9.0.0"},
    "webpack":      {"owasp": "A05", "desc": "Dev config exposure", "fix": "Use production webpack config"},
    "sanitize":     {"owasp": "A03", "desc": "Input sanitization bypass", "fix": "Upgrade sanitize-html"},
    "sqlite":       {"owasp": "A03", "desc": "SQL injection possible", "fix": "Use parameterised queries"},
    "node-forge":   {"owasp": "A02", "desc": "Crypto weakness", "fix": "Upgrade node-forge to ≥1.3.1"},
}

# Sonar rule → OWASP mapping
SONAR_RULE_OWASP = {
    "squid:S2068": "A02",  "squid:S4426": "A02",  "squid:S5542": "A02",
    "squid:S5547": "A02",  "squid:S5659": "A02",  "squid:S2076": "A03",
    "squid:S2631": "A03",  "squid:S3649": "A03",  "squid:S5131": "A03",
    "squid:S2083": "A01",  "squid:S5144": "A10",  "squid:S4790": "A02",
    "squid:S2245": "A02",  "squid:S6096": "A01",
}

# ─────────────────────────────────────────────────────────────────────────────
# Data loaders
# ─────────────────────────────────────────────────────────────────────────────
def load_json(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            print(f"  [WARN] {filename}: {e}")
    return None

def parse_npm_audit(filename="npm-audit.json"):
    result = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "findings": []}
    data = load_json(filename)
    if not data:
        return result
    meta = data.get("metadata", {}).get("vulnerabilities", {})
    result["critical"] = meta.get("critical", 0)
    result["high"]     = meta.get("high", 0)
    result["medium"]   = meta.get("moderate", 0)
    result["low"]      = meta.get("low", 0)
    result["total"]    = meta.get("total", sum([result["critical"], result["high"], result["medium"], result["low"]]))
    for pkg, details in data.get("vulnerabilities", {}).items():
        sev = details.get("severity", "unknown").upper()
        via = details.get("via", [])
        cves = [v.get("cve","") for v in via if isinstance(v, dict) and v.get("cve")]
        url  = next((v.get("url","") for v in via if isinstance(v, dict)), "")
        result["findings"].append({
            "package":  pkg,
            "severity": sev,
            "cves":     cves,
            "url":      url,
            "fix":      str(details.get("fixAvailable", "Manual update required"))
        })
    result["findings"].sort(key=lambda x: ["CRITICAL","HIGH","MODERATE","MEDIUM","LOW"].index(x["severity"]) if x["severity"] in ["CRITICAL","HIGH","MODERATE","MEDIUM","LOW"] else 99)
    return result

def parse_zap(filename="zap-report.json"):
    result = {"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0, "findings": []}
    data = load_json(filename)
    if not data:
        return result
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" (")[0].strip()
            result["total"] += 1
            if risk == "High":          result["high"] += 1
            elif risk == "Medium":      result["medium"] += 1
            elif risk == "Low":         result["low"] += 1
            elif risk == "Informational": result["informational"] += 1
            instances = [i.get("uri","") for i in alert.get("instances", [])][:5]
            cweid = alert.get("cweid","")
            result["findings"].append({
                "name":      alert.get("alert", alert.get("name", "N/A")),
                "risk":      risk,
                "solution":  alert.get("solution","N/A"),
                "instances": instances,
                "cweid":     cweid,
                "desc":      alert.get("desc","")[:200],
            })
    result["findings"].sort(key=lambda x: {"High":0,"Medium":1,"Low":2,"Informational":3}.get(x["risk"],4))
    return result

def parse_jmeter(filename="jmeter-results.jtl"):
    result = {"samples":0,"errors":0,"avg_rt":0,"p95_rt":0,"p99_rt":0,"max_rt":0,"throughput":0,"endpoints":{}}
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        return result
    try:
        rows = []
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        if not rows:
            return result
        all_rt = []
        ep_data = {}
        for row in rows:
            label   = row.get("label", row.get("s","unknown"))
            elapsed = int(row.get("elapsed", row.get("t",0)))
            success = str(row.get("success", row.get("s","true"))).lower() == "true"
            result["samples"] += 1
            all_rt.append(elapsed)
            if not success:
                result["errors"] += 1
            if label not in ep_data:
                ep_data[label] = {"times":[],"errors":0}
            ep_data[label]["times"].append(elapsed)
            if not success:
                ep_data[label]["errors"] += 1
        all_rt_s = sorted(all_rt)
        n = len(all_rt_s)
        result["avg_rt"]    = round(sum(all_rt)/n, 1)
        result["max_rt"]    = all_rt_s[-1]
        result["p95_rt"]    = all_rt_s[min(int(n*0.95), n-1)]
        result["p99_rt"]    = all_rt_s[min(int(n*0.99), n-1)]
        # Throughput: requests/sec estimated
        result["throughput"] = round(n / max(result["max_rt"]/1000, 1), 2)
        for label, d in ep_data.items():
            ts = sorted(d["times"])
            cnt = len(ts)
            p95 = ts[min(int(cnt*0.95), cnt-1)]
            result["endpoints"][label] = {
                "count": cnt,
                "avg":   round(sum(ts)/cnt, 1),
                "p95":   p95,
                "max":   ts[-1],
                "errors": d["errors"],
                "error_rate": round(d["errors"]/cnt*100, 2)
            }
    except Exception as e:
        print(f"  [WARN] jmeter parse: {e}")
    return result

# ─────────────────────────────────────────────────────────────────────────────
# FREE AI ENGINE — Expert System
# Deterministic security intelligence derived from scan results.
# Covers OWASP Top 10 (2021), CWE mapping, severity correlation,
# risk scoring, compliance notes and prioritised remediations.
# Zero API calls. Zero cost.
# ─────────────────────────────────────────────────────────────────────────────
class SecurityAI:
    """Rule-based expert engine that produces AI-quality security analysis."""

    def __init__(self, sca, zap, perf, sonar_summary, sonar_issues):
        self.sca    = sca
        self.zap    = zap
        self.perf   = perf
        self.sonar  = sonar_summary
        self.issues = sonar_issues.get("issues", [])
        self.owasp_hits  = {}   # A0x → list of findings
        self.remediations = []
        self._analyse()

    # ── Core analysis ────────────────────────────────────────────────────────
    def _analyse(self):
        self._map_sca_to_owasp()
        self._map_zap_to_owasp()
        self._map_sonar_to_owasp()
        self._map_perf_risks()
        self._build_remediations()

    def _add_hit(self, owasp_id, source, finding):
        if owasp_id not in self.owasp_hits:
            self.owasp_hits[owasp_id] = []
        self.owasp_hits[owasp_id].append({"source": source, **finding})

    def _map_sca_to_owasp(self):
        """Map npm audit / dependency findings to OWASP."""
        for f in self.sca.get("findings", []):
            pkg  = f["package"].lower()
            sev  = f["severity"]
            rule = next((CVE_RULES[k] for k in CVE_RULES if k in pkg), None)
            owasp = rule["owasp"] if rule else "A06"
            self._add_hit(owasp, "SCA", {
                "title":    f"Vulnerable dependency: {f['package']} ({sev})",
                "detail":   rule["desc"] if rule else f"CVE in {f['package']}",
                "fix":      rule["fix"] if rule else f["fix"],
                "severity": sev,
                "cves":     f.get("cves", []),
            })

    def _map_zap_to_owasp(self):
        """Map ZAP alerts to OWASP via CWE or name matching."""
        for f in self.zap.get("findings", []):
            name  = f["name"].lower()
            cweid = str(f.get("cweid",""))
            owasp = CWE_TO_OWASP.get(cweid)
            if not owasp:
                owasp = next((v for k,v in ZAP_NAME_TO_OWASP.items() if k in name), "A05")
            self._add_hit(owasp, "DAST", {
                "title":    f['name'],
                "detail":   f.get("desc","")[:150],
                "fix":      f.get("solution","Review and patch")[:150],
                "severity": f["risk"],
                "urls":     f.get("instances",[])[:3],
            })

    def _map_sonar_to_owasp(self):
        """Map SonarQube issues to OWASP."""
        for issue in self.issues:
            rule  = issue.get("rule","")
            owasp = SONAR_RULE_OWASP.get(rule, "A04")
            sev   = issue.get("severity","MAJOR")
            self._add_hit(owasp, "SAST", {
                "title":    issue.get("message","Code issue")[:100],
                "detail":   f"File: {issue.get('component','').split(':')[-1]}  Line: {issue.get('line','')}",
                "fix":      "Fix flagged code pattern — see SonarQube for exact rule guidance.",
                "severity": sev,
            })

    def _map_perf_risks(self):
        """Flag performance findings as security-adjacent risks."""
        p95 = self.perf.get("p95_rt", 0)
        err = self.perf.get("errors", 0)
        samples = max(self.perf.get("samples", 1), 1)
        err_rate = err / samples * 100
        if p95 > 3000:
            self._add_hit("A05", "Perf", {
                "title":    f"High P95 latency: {p95}ms under load",
                "detail":   "Slow responses can indicate DoS vulnerability or resource exhaustion.",
                "fix":      "Profile slow endpoints; add rate limiting and response caching.",
                "severity": "HIGH",
            })
        if err_rate > 5:
            self._add_hit("A05", "Perf", {
                "title":    f"High error rate under load: {err_rate:.1f}%",
                "detail":   "Errors above 5% suggest instability and potential DoS exposure.",
                "fix":      "Investigate error responses; enforce circuit-breaker patterns.",
                "severity": "MEDIUM",
            })

    # ── Risk scoring ─────────────────────────────────────────────────────────
    def score(self):
        """Compute 0–100 security score using weighted deductions."""
        s = 100
        # SCA
        s -= self.sca.get("critical", 0) * 12
        s -= self.sca.get("high", 0)     * 6
        s -= self.sca.get("medium", 0)   * 2
        # SAST
        s -= self.sonar.get("critical", 0) * 10
        s -= self.sonar.get("major",    0) * 3
        # DAST
        s -= self.zap.get("high",   0) * 15
        s -= self.zap.get("medium", 0) * 5
        s -= self.zap.get("low",    0) * 1
        # Perf
        if self.perf.get("p95_rt", 0) > 3000: s -= 5
        err = self.perf.get("errors",0)/max(self.perf.get("samples",1),1)*100
        if err > 5: s -= 5
        return max(0, min(100, s))

    def grade(self):
        sc = self.score()
        if sc >= 90: return "A", "#22c55e"
        if sc >= 75: return "B", "#84cc16"
        if sc >= 55: return "C", "#f59e0b"
        if sc >= 35: return "D", "#f97316"
        return "F", "#ef4444"

    def risk_level(self):
        sc = self.score()
        if sc >= 75: return "Low",      "#22c55e"
        if sc >= 55: return "Medium",   "#f59e0b"
        if sc >= 35: return "High",     "#f97316"
        return "Critical", "#ef4444"

    def build_decision(self):
        """Fail build if any critical/high issues exist in any tool."""
        if self.sca.get("critical", 0) > 0:   return "FAIL", "Critical CVEs in dependencies"
        if self.sca.get("high", 0) > 0:        return "FAIL", "High-severity CVEs in dependencies"
        if self.zap.get("high", 0) > 0:        return "FAIL", "High-risk DAST alerts"
        if self.sonar.get("critical", 0) > 0:  return "FAIL", "Critical SAST findings"
        return "PASS", "All thresholds met"

    # ── Remediation engine ───────────────────────────────────────────────────
    def _build_remediations(self):
        seen = set()
        priority = 1
        # Critical CVEs first
        for f in self.sca.get("findings",[]):
            if f["severity"] in ("CRITICAL","HIGH") and f["package"] not in seen:
                seen.add(f["package"])
                rule = next((CVE_RULES[k] for k in CVE_RULES if k in f["package"].lower()), None)
                self.remediations.append({
                    "priority": priority,
                    "tool":     "SCA",
                    "owasp":    rule["owasp"] if rule else "A06",
                    "issue":    f"Vulnerable: {f['package']} ({f['severity']})",
                    "fix":      rule["fix"] if rule else f["fix"],
                    "effort":   "Low",
                    "impact":   "Critical",
                })
                priority += 1
        # DAST high
        for f in self.zap.get("findings",[]):
            if f["risk"] == "High" and f["name"] not in seen:
                seen.add(f["name"])
                self.remediations.append({
                    "priority": priority,
                    "tool":     "DAST",
                    "owasp":    CWE_TO_OWASP.get(str(f.get("cweid","")), "A05"),
                    "issue":    f["name"],
                    "fix":      f.get("solution","Review ZAP report for fix details.")[:200],
                    "effort":   "Medium",
                    "impact":   "High",
                })
                priority += 1
        # SAST critical
        for issue in self.issues[:5]:
            msg = issue.get("message","")[:60]
            if msg not in seen:
                seen.add(msg)
                self.remediations.append({
                    "priority": priority,
                    "tool":     "SAST",
                    "owasp":    SONAR_RULE_OWASP.get(issue.get("rule",""), "A04"),
                    "issue":    msg,
                    "fix":      "Review SonarQube rule definition and apply recommended code fix.",
                    "effort":   "Medium",
                    "impact":   issue.get("severity","MAJOR"),
                })
                priority += 1

    # ── AI narrative ─────────────────────────────────────────────────────────
    def executive_summary(self):
        grade, _ = self.grade()
        risk, _  = self.risk_level()
        decision, reason = self.build_decision()
        total_vulns = (
            self.sca.get("critical",0) + self.sca.get("high",0) +
            self.zap.get("high",0) + self.sonar.get("critical",0)
        )
        summary_parts = []
        if total_vulns == 0:
            summary_parts.append(f"Security posture is strong with a Grade {grade}. No critical or high-severity findings detected across SAST, SCA, and DAST stages.")
        else:
            summary_parts.append(
                f"Pipeline analysis detected {total_vulns} critical/high-severity finding(s) across toolchain, "
                f"resulting in a Grade {grade} ({risk} risk). Build decision: {decision} — {reason}."
            )
        owasp_affected = [f"{k}: {OWASP_TOP10[k]['name']}" for k in sorted(self.owasp_hits.keys()) if k in OWASP_TOP10]
        if owasp_affected:
            summary_parts.append(f"OWASP Top 10 categories affected: {', '.join(owasp_affected[:4])}.")
        if self.sca.get("critical",0) > 0:
            summary_parts.append(
                f"SCA scan found {self.sca['critical']} critical CVE(s) in third-party dependencies — "
                f"immediate patching required before deployment."
            )
        if self.zap.get("high",0) > 0:
            summary_parts.append(
                f"DAST (ZAP) identified {self.zap['high']} high-risk alert(s) in the running application, "
                f"confirming exploitable vulnerabilities under live conditions."
            )
        p95 = self.perf.get("p95_rt",0)
        summary_parts.append(
            f"Performance testing recorded P95 latency of {p95}ms — "
            f"{'within acceptable limits' if p95 <= 2000 else 'exceeds 2s threshold, indicating instability risk'}."
        )
        return " ".join(summary_parts)

    def compliance_notes(self):
        notes = []
        if self.zap.get("findings"):
            high_names = [f["name"] for f in self.zap["findings"] if f["risk"]=="High"]
            if any("sql" in n.lower() for n in high_names):
                notes.append("OWASP A03 (Injection) — SQL injection confirmed via DAST; PCI-DSS Req 6.3 applies.")
            if any("xss" in n.lower() or "cross site" in n.lower() for n in high_names):
                notes.append("OWASP A03 (Injection) — XSS confirmed; GDPR data exposure risk.")
            if any("csp" in n.lower() for f in self.zap["findings"] for n in [f["name"].lower()]):
                notes.append("OWASP A05 (Misconfiguration) — Missing CSP header; add Content-Security-Policy.")
            if any("cookie" in n.lower() or "session" in n.lower() for n in [f["name"].lower() for f in self.zap["findings"]]):
                notes.append("OWASP A07 (Auth Failures) — Cookie/session misconfiguration detected.")
        if self.sca.get("critical",0) > 0:
            notes.append("OWASP A06 (Vulnerable Components) — Critical CVEs violate NIST SP 800-190 container guidance.")
        if not notes:
            notes.append("No active compliance violations detected. Continue monitoring with each build.")
        return notes

    def ai_insights(self):
        """Generate tool-specific AI insights."""
        insights = {}
        # SCA insight
        if self.sca.get("total", 0) > 0:
            crit = self.sca["critical"]
            high = self.sca["high"]
            insights["sca"] = (
                f"Dependency scan found {self.sca['total']} vulnerabilities ({crit} critical, {high} high). "
                f"{'Log4Shell or similar critical RCE CVEs detected — treat as P0 incident.' if crit > 0 else 'No critical CVEs, but high-severity issues require sprint-level attention.'} "
                f"Run `npm audit fix` to auto-resolve {min(high, self.sca.get('total',0))} fixable issues. "
                f"Pin vulnerable transitive dependencies in package.json overrides."
            )
        else:
            insights["sca"] = "No dependency vulnerabilities found. Maintain this by running `npm audit` on every PR."
        # ZAP insight
        if self.zap.get("total", 0) > 0:
            insights["dast"] = (
                f"ZAP full scan produced {self.zap['total']} alerts ({self.zap['high']} high, {self.zap['medium']} medium). "
                f"High-risk findings represent confirmed exploitable paths in the live application — "
                f"not theoretical. Prioritise: SQL injection → input parameterisation; "
                f"XSS → output encoding; missing headers → helmet.js middleware."
            )
        else:
            insights["dast"] = "No active DAST alerts. Ensure ZAP ran against an authenticated session for full coverage."
        # SAST insight
        crit_sonar = self.sonar.get("critical", 0)
        insights["sast"] = (
            f"SonarQube SAST identified {crit_sonar} critical issue(s). "
            f"{'Critical findings often indicate hardcoded secrets, SQL injection vectors, or insecure crypto — review each rule before dismissing.' if crit_sonar > 0 else 'Code quality gates are passing. Set coverage thresholds ≥80% to prevent regression.'} "
            f"Integrate SonarLint in your IDE for shift-left detection before commit."
        )
        # Perf insight
        p95 = self.perf.get("p95_rt", 0)
        err = self.perf.get("errors", 0)
        samples = max(self.perf.get("samples", 1), 1)
        err_rate = round(err/samples*100, 2)
        insights["perf"] = (
            f"Load test: {samples} requests, P95={p95}ms, error rate={err_rate}%. "
            f"{'Performance is acceptable.' if p95 <= 2000 and err_rate <= 5 else 'Latency or error rate exceeds safe thresholds — investigate before deploying under production load.'} "
            f"Consider adding rate-limiting (express-rate-limit) and caching (Redis) for endpoints with P95 > 1000ms."
        )
        return insights


# ─────────────────────────────────────────────────────────────────────────────
# HTML Generation — Jenkins CSP-compatible (all inline styles)
# Premium UI — no external fonts, no CDN, pure inline CSS
# ─────────────────────────────────────────────────────────────────────────────

# ── Design tokens ────────────────────────────────────────────────────────────
BG       = "#07090f"      # deepest background
BG2      = "#0d1117"      # page bg
BG3      = "#111827"      # card bg
BG4      = "#1a2236"      # card inner / table rows
BORDER   = "#1f2d45"      # subtle border
BORDER2  = "#253352"      # hover border
TEXT     = "#e2eaf6"      # primary text
MUTED    = "#6b7fa3"      # secondary text
DIM      = "#3a4a6b"      # tertiary / disabled
CYAN     = "#22d3ee"      # brand accent
PURPLE   = "#a78bfa"      # secondary accent
GREEN    = "#34d399"       # pass / success
AMBER    = "#fbbf24"       # warning
ORANGE   = "#fb923c"       # high severity
RED      = "#f87171"       # critical / fail

def sev_color(sev):
    s = str(sev).upper()
    if s in ("CRITICAL","BLOCKER"): return RED
    if s in ("HIGH",):              return ORANGE
    if s in ("MEDIUM","MODERATE","MAJOR"): return AMBER
    return MUTED

def risk_color(r):
    r = str(r).lower()
    if r == "high":   return RED
    if r == "medium": return AMBER
    if r == "low":    return GREEN
    return MUTED

def owasp_badge(owasp_id):
    info = OWASP_TOP10.get(owasp_id, {"name": "Unknown", "color": DIM})
    c = info["color"]
    return (
        f'<span style="display:inline-flex;align-items:center;gap:4px;padding:3px 9px;'
        f'border-radius:20px;font-size:0.7rem;font-weight:700;letter-spacing:.04em;'
        f'background:{c}18;color:{c};border:1px solid {c}40;white-space:nowrap;">'
        f'<span style="width:5px;height:5px;border-radius:50%;background:{c};'
        f'display:inline-block;flex-shrink:0;"></span>'
        f'{owasp_id} {info["name"]}</span>'
    )

def bar(pct, color=CYAN, height="6px", bg=BG):
    pct = max(0, min(100, pct))
    glow = f"box-shadow:0 0 6px {color}66;" if pct > 60 else ""
    return (
        f'<div style="background:{bg};border-radius:3px;height:{height};'
        f'overflow:hidden;border:1px solid {BORDER};">'
        f'<div style="width:{pct}%;background:{color};height:100%;border-radius:3px;{glow}"></div>'
        f'</div>'
    )

def glowing_dot(color):
    return (f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;'
            f'background:{color};box-shadow:0 0 6px {color};flex-shrink:0;"></span>')

def section_header(icon, title, accent):
    return (
        f'<div style="display:flex;align-items:center;gap:12px;margin:0 0 24px;">'
        f'<div style="width:3px;height:28px;border-radius:2px;background:{accent};'
        f'box-shadow:0 0 8px {accent}88;"></div>'
        f'<span style="font-size:1.15rem;font-weight:700;color:{TEXT};letter-spacing:-.01em;">'
        f'{icon} {title}</span>'
        f'</div>'
    )

def stat_pill(label, value, color, sub=""):
    sub_html = f'<div style="font-size:0.7rem;color:{DIM};margin-top:3px;">{sub}</div>' if sub else ""
    return (
        f'<div style="background:{BG4};border:1px solid {BORDER};border-radius:14px;'
        f'padding:18px 20px;border-top:2px solid {color};">'
        f'<div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:.1em;'
        f'color:{MUTED};margin-bottom:8px;">{label}</div>'
        f'<div style="font-size:1.9rem;font-weight:800;color:{color};line-height:1;">{value}</div>'
        f'{sub_html}'
        f'</div>'
    )

def table_wrap(headers, body_html, min_width="600px"):
    th_cells = "".join(
        f'<th style="padding:12px 16px;color:{MUTED};text-align:left;font-size:0.72rem;'
        f'text-transform:uppercase;letter-spacing:.08em;font-weight:600;'
        f'border-bottom:1px solid {BORDER};white-space:nowrap;">{h}</th>'
        for h in headers
    )
    return (
        f'<div style="background:{BG3};border:1px solid {BORDER};border-radius:16px;'
        f'overflow:hidden;overflow-x:auto;">'
        f'<table style="width:100%;border-collapse:collapse;min-width:{min_width};">'
        f'<thead style="background:{BG};"><tr>{th_cells}</tr></thead>'
        f'<tbody>{body_html}</tbody>'
        f'</table></div>'
    )

def td(content, style=""):
    return f'<td style="padding:13px 16px;border-bottom:1px solid {BORDER};{style}">{content}</td>'

def severity_chip(sev):
    c = sev_color(sev)
    icons = {"CRITICAL":"◆","BLOCKER":"◆","HIGH":"▲","MEDIUM":"●","MODERATE":"●","MAJOR":"●","LOW":"▼"}
    icon = icons.get(str(sev).upper(), "●")
    return (f'<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;'
            f'border-radius:20px;font-size:0.72rem;font-weight:700;background:{c}18;'
            f'color:{c};border:1px solid {c}40;">'
            f'<span style="font-size:8px;">{icon}</span>{sev}</span>')


def generate_dashboard():
    print("\n=== SHIVA AI — Free Security Intelligence Engine ===")
    print("Loading scan reports...")


    sca            = parse_npm_audit()
    zap            = parse_zap()
    perf           = parse_jmeter()
    sonar_summary  = load_json("sonar-summary.json") or {"critical": 0, "major": 0}
    sonar_issues   = load_json("sonar-issues.json")  or {"issues": []}

    print(f"  SCA:  {sca['total']} vulns  ({sca['critical']} critical)")
    print(f"  DAST: {zap['total']} alerts ({zap['high']} high)")
    print(f"  SAST: {sonar_summary.get('critical',0)} critical")
    print(f"  Perf: {perf['samples']} samples, P95={perf['p95_rt']}ms")
    print("Running AI expert engine...")

    ai = SecurityAI(sca, zap, perf, sonar_summary, sonar_issues)
    score     = ai.score()
    grade, gc = ai.grade()
    risk, rc  = ai.risk_level()
    decision, dreason = ai.build_decision()
    summary   = ai.executive_summary()
    insights  = ai.ai_insights()
    comp      = ai.compliance_notes()
    remeds    = ai.remediations[:8]
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"  Score: {score}/100 | Grade: {grade} | Risk: {risk} | Build: {decision}")

    # ── Score ring SVG (bigger, more detailed) ────────────────────────────────
    R    = 58
    circ = 2 * 3.14159265 * R
    dash = circ * score / 100
    ring_track_col = BG4
    score_ring = (
        f'<svg width="160" height="160" viewBox="0 0 160 160">'
        f'<circle cx="80" cy="80" r="{R}" fill="none" stroke="{ring_track_col}" stroke-width="10"/>'
        f'<circle cx="80" cy="80" r="{R}" fill="none" stroke="{gc}" stroke-width="10"'
        f' stroke-dasharray="{dash:.2f} {circ:.2f}" stroke-linecap="round"'
        f' transform="rotate(-90 80 80)"/>'
        f'<text x="80" y="71" text-anchor="middle" fill="{gc}"'
        f' font-size="32" font-weight="900" font-family="system-ui,sans-serif">{score}</text>'
        f'<text x="80" y="89" text-anchor="middle" fill="{MUTED}"'
        f' font-size="11" font-family="system-ui,sans-serif">out of 100</text>'
        f'<text x="80" y="112" text-anchor="middle" fill="{gc}"'
        f' font-size="18" font-weight="800" font-family="system-ui,sans-serif">Grade {grade}</text>'
        f'</svg>'
    )

    # ── OWASP cards ───────────────────────────────────────────────────────────
    owasp_cards = ""
    for oid, info in OWASP_TOP10.items():
        hits = ai.owasp_hits.get(oid, [])
        cnt  = len(hits)
        col  = info["color"] if cnt > 0 else DIM
        bg_t = BG4 if cnt > 0 else BG3
        hit_list = "".join(
            f'<div style="display:flex;align-items:flex-start;gap:7px;padding:6px 0;'
            f'border-bottom:1px solid {BORDER};">'
            f'<span style="color:{sev_color(h.get("severity","LOW"))};font-size:9px;margin-top:4px;flex-shrink:0;">◆</span>'
            f'<span style="font-size:0.75rem;color:{TEXT};line-height:1.4;">'
            f'<span style="color:{MUTED};font-size:0.68rem;text-transform:uppercase;'
            f'letter-spacing:.06em;margin-right:4px;">[{h["source"]}]</span>'
            f'{h["title"][:65]}</span></div>'
            for h in hits[:3]
        )
        remaining = cnt - 3
        more_badge = (
            f'<div style="font-size:0.7rem;color:{MUTED};padding-top:5px;text-align:right;">'
            f'+{remaining} more</div>'
        ) if remaining > 0 else ""
        owasp_cards += (
            f'<div style="background:{bg_t};border:1px solid {col if cnt>0 else BORDER};'
            f'border-radius:14px;padding:18px;border-top:3px solid {col};">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">'
            f'<span style="font-size:0.75rem;font-weight:800;color:{col};letter-spacing:.06em;">{oid}</span>'
            f'<span style="background:{col}20;color:{col};padding:2px 9px;border-radius:20px;'
            f'font-size:0.68rem;font-weight:700;border:1px solid {col}40;">'
            f'{cnt} hit{"s" if cnt!=1 else ""}</span>'
            f'</div>'
            f'<div style="font-size:0.78rem;color:{MUTED};margin-bottom:10px;'
            f'font-weight:500;">{info["name"]}</div>'
            f'{"<div>" + hit_list + more_badge + "</div>" if hit_list else f"<div style=font-size:0.75rem;color:{DIM};>No findings</div>"}'
            f'</div>'
        )

    # ── Remediation rows ──────────────────────────────────────────────────────
    remed_rows = ""
    for r in remeds:
        owasp_id   = r.get("owasp","A04")
        ic         = sev_color(r["impact"])
        tool_colors = {"SCA": ORANGE, "DAST": RED, "SAST": PURPLE, "Perf": CYAN}
        tc = tool_colors.get(r["tool"], MUTED)
        remed_rows += (
            f'<tr style="background:{BG3};">'
            + td(f'<span style="display:inline-flex;align-items:center;justify-content:center;'
                 f'width:24px;height:24px;border-radius:50%;background:{BORDER2};'
                 f'color:{CYAN};font-size:0.75rem;font-weight:800;">#{r["priority"]}</span>')
            + td(f'<span style="display:inline-block;padding:3px 9px;border-radius:6px;'
                 f'background:{tc}20;color:{tc};font-size:0.72rem;font-weight:700;'
                 f'border:1px solid {tc}40;">{r["tool"]}</span>')
            + td(owasp_badge(owasp_id))
            + td(f'<span style="color:{TEXT};font-size:0.85rem;">{r["issue"][:70]}</span>')
            + td(f'<span style="color:{MUTED};font-size:0.82rem;line-height:1.5;">{r["fix"][:140]}</span>')
            + td(severity_chip(r["impact"]))
            + '</tr>'
        )

    # ── SCA rows ──────────────────────────────────────────────────────────────
    sca_rows = ""
    for idx, f in enumerate(sca.get("findings",[])[:20]):
        pkg  = f["package"]
        sev  = f["severity"]
        cves = ", ".join(f.get("cves",[])) or "—"
        fix  = f.get("fix","Manual update")
        rule = next((CVE_RULES[k] for k in CVE_RULES if k in pkg.lower()), None)
        ow   = owasp_badge(rule["owasp"]) if rule else owasp_badge("A06")
        row_bg = BG4 if idx % 2 == 0 else BG3
        sca_rows += (
            f'<tr style="background:{row_bg};">'
            + td(f'<span style="font-family:monospace;font-size:0.83rem;color:{CYAN};">{pkg}</span>')
            + td(severity_chip(sev))
            + td(f'<span style="font-size:0.78rem;color:{MUTED};font-family:monospace;">{cves[:40]}</span>')
            + td(ow)
            + td(f'<span style="font-size:0.8rem;color:{MUTED};">{str(fix)[:80]}</span>')
            + '</tr>'
        )

    # ── ZAP rows ──────────────────────────────────────────────────────────────
    zap_rows = ""
    for idx, f in enumerate(zap.get("findings",[])[:20]):
        cw  = f.get("cweid","")
        ow  = owasp_badge(CWE_TO_OWASP.get(str(cw), next(
            (v for k,v in ZAP_NAME_TO_OWASP.items() if k in f["name"].lower()), "A05")))
        urls_html = "".join(
            f'<div style="font-size:0.72rem;color:{CYAN};word-break:break-all;'
            f'padding:1px 0;">{u[:70]}</div>'
            for u in f.get("instances",[])[:2]
        )
        row_bg = BG4 if idx % 2 == 0 else BG3
        zap_rows += (
            f'<tr style="background:{row_bg};">'
            + td(f'<span style="color:{TEXT};font-weight:600;font-size:0.85rem;">{f["name"]}</span>')
            + td(severity_chip(f["risk"]))
            + td(f'<span style="font-size:0.75rem;color:{DIM};font-family:monospace;">CWE-{cw}</span>')
            + td(ow)
            + td(f'<span style="font-size:0.8rem;color:{MUTED};line-height:1.5;">{f.get("solution","")[:100]}</span>')
            + td(urls_html or f'<span style="color:{DIM};font-size:0.75rem;">—</span>')
            + '</tr>'
        )

    # ── Sonar rows ────────────────────────────────────────────────────────────
    sonar_rows = ""
    for idx, iss in enumerate(sonar_issues.get("issues",[])[:20]):
        sev  = iss.get("severity","MAJOR")
        rule = iss.get("rule","")
        comp = iss.get("component","").split(":")[-1]
        ow   = owasp_badge(SONAR_RULE_OWASP.get(rule,"A04"))
        row_bg = BG4 if idx % 2 == 0 else BG3
        sonar_rows += (
            f'<tr style="background:{row_bg};">'
            + td(f'<span style="color:{TEXT};font-size:0.84rem;">{iss.get("message","")[:85]}</span>')
            + td(severity_chip(sev))
            + td(f'<span style="font-family:monospace;font-size:0.78rem;color:{MUTED};">{comp[:40]}</span>')
            + td(f'<span style="font-family:monospace;font-size:0.72rem;color:{DIM};">{rule}</span>')
            + td(ow)
            + '</tr>'
        )

    # ── Perf rows ─────────────────────────────────────────────────────────────
    perf_rows = ""
    for idx, (label, ep) in enumerate(perf.get("endpoints",{}).items()):
        p95_col = RED   if ep["p95"] > 3000 else AMBER if ep["p95"] > 1500 else GREEN
        err_col = RED   if ep["error_rate"] > 5       else GREEN
        pct     = min(100, int(ep["p95"] / 30))
        row_bg  = BG4 if idx % 2 == 0 else BG3
        perf_rows += (
            f'<tr style="background:{row_bg};">'
            + td(f'<span style="font-family:monospace;font-size:0.83rem;color:{CYAN};">{label}</span>')
            + td(f'<span style="color:{MUTED};">{ep["count"]}</span>')
            + td(f'<span style="color:{MUTED};">{round(ep["avg"])}ms</span>')
            + td(
                f'<div style="display:flex;align-items:center;gap:10px;">'
                f'<span style="color:{p95_col};font-weight:700;min-width:52px;">{ep["p95"]}ms</span>'
                f'<div style="flex:1;min-width:60px;">{bar(pct, p95_col)}</div>'
                f'</div>'
              )
            + td(f'<span style="color:{err_col};font-weight:700;">{ep["error_rate"]}%</span>')
            + td(f'<span style="color:{MUTED};">{ep["errors"]}</span>')
            + '</tr>'
        )

    # ── Compliance rows ───────────────────────────────────────────────────────
    comp_rows = "".join(
        f'<div style="display:flex;align-items:flex-start;gap:12px;padding:12px 16px;'
        f'background:{BG4};border-radius:10px;border-left:3px solid {AMBER};margin-bottom:8px;">'
        f'<span style="color:{AMBER};font-size:14px;flex-shrink:0;margin-top:1px;">⚠</span>'
        f'<span style="font-size:0.87rem;color:{TEXT};line-height:1.6;">{note}</span>'
        f'</div>'
        for note in comp
    )

    # ── Decision badge ────────────────────────────────────────────────────────
    decision_col = GREEN if decision == "PASS" else RED
    d_icon       = "✓" if decision == "PASS" else "✗"

    # ── Nav link helper ───────────────────────────────────────────────────────
    def nav_link(href, icon, label, accent=CYAN):
        return (
            f'<a href="{href}" style="display:flex;align-items:center;gap:10px;'
            f'color:{MUTED};text-decoration:none;padding:9px 12px;'
            f'border-radius:9px;margin-bottom:3px;font-size:0.85rem;'
            f'border:1px solid transparent;transition:all .15s;">'
            f'<span style="font-size:13px;">{icon}</span>{label}</a>'
        )

    # ── Tool badge helper ─────────────────────────────────────────────────────
    def tool_stat(label, val, sub, col, icon):
        chk = f'<span style="font-size:10px;color:{col};">{"▲" if col==RED or col==ORANGE else "✓"}</span>'
        return (
            f'<div style="background:{BG4};border:1px solid {BORDER};border-radius:14px;'
            f'padding:20px;border-top:3px solid {col};">'
            f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">'
            f'<span style="font-size:0.68rem;text-transform:uppercase;letter-spacing:.1em;color:{MUTED};">{label}</span>'
            f'{chk}</div>'
            f'<div style="font-size:2rem;font-weight:900;color:{col};line-height:1;">{val}</div>'
            f'<div style="font-size:0.72rem;color:{DIM};margin-top:5px;">{sub}</div>'
            f'</div>'
        )

    # ── Insight card helper ───────────────────────────────────────────────────
    def insight_card(icon, title, col, body):
        return (
            f'<div style="background:{BG4};border:1px solid {BORDER};border-radius:14px;'
            f'padding:20px;border-left:3px solid {col};">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">'
            f'{glowing_dot(col)}'
            f'<span style="font-weight:700;color:{col};font-size:0.9rem;">{icon} {title}</span>'
            f'</div>'
            f'<div style="font-size:0.83rem;color:{MUTED};line-height:1.75;">{body}</div>'
            f'</div>'
        )

    err_rate_val = round(perf["errors"] / max(perf["samples"],1) * 100, 1)
    owasp_hit_count = len(ai.owasp_hits)

    # ─────────────────────────────────────────────────────────────────────────
    # FULL HTML
    # ─────────────────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SHIVA AI &#x2022; Build #{BUILD_NUMBER}</title>
</head>
<body style="background:{BG2};color:{TEXT};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0;min-height:100vh;">

<!-- ═══════════════════════════════ TOP BAR ═══════════════════════════════ -->
<div style="background:{BG};border-bottom:1px solid {BORDER};padding:0 32px;
            display:flex;align-items:stretch;justify-content:space-between;
            min-height:64px;flex-wrap:wrap;gap:0;">

  <!-- Logo + meta -->
  <div style="display:flex;align-items:center;gap:16px;padding:14px 0;">
    <div style="width:38px;height:38px;border-radius:10px;background:{CYAN}18;
                border:1px solid {CYAN}40;display:flex;align-items:center;
                justify-content:center;font-size:20px;">🛡️</div>
    <div>
      <div style="font-size:1rem;font-weight:800;color:{TEXT};letter-spacing:-.02em;">
        SHIVA AI
        <span style="font-size:0.7rem;font-weight:500;color:{MUTED};margin-left:6px;
                     letter-spacing:.04em;text-transform:uppercase;">Security Intelligence</span>
      </div>
      <div style="font-size:0.72rem;color:{DIM};margin-top:1px;">
        {JOB_NAME} &nbsp;&#x2022;&nbsp; Build #{BUILD_NUMBER} &nbsp;&#x2022;&nbsp;
        {now} &nbsp;&#x2022;&nbsp;
        <a href="{BUILD_URL}" style="color:{CYAN};text-decoration:none;">Jenkins &#x2197;</a>
      </div>
    </div>
  </div>

  <!-- Status pills -->
  <div style="display:flex;align-items:center;gap:10px;padding:14px 0;flex-wrap:wrap;">
    <div style="background:{decision_col}15;border:1px solid {decision_col}50;
                border-radius:10px;padding:10px 18px;text-align:center;">
      <div style="font-size:0.65rem;color:{DIM};text-transform:uppercase;letter-spacing:.1em;margin-bottom:2px;">Build</div>
      <div style="font-size:1.1rem;font-weight:900;color:{decision_col};">{d_icon} {decision}</div>
    </div>
    <div style="background:{rc}15;border:1px solid {rc}50;
                border-radius:10px;padding:10px 18px;text-align:center;">
      <div style="font-size:0.65rem;color:{DIM};text-transform:uppercase;letter-spacing:.1em;margin-bottom:2px;">Risk</div>
      <div style="font-size:1.1rem;font-weight:900;color:{rc};">{risk}</div>
    </div>
    <div style="background:{gc}15;border:1px solid {gc}50;
                border-radius:10px;padding:10px 18px;text-align:center;">
      <div style="font-size:0.65rem;color:{DIM};text-transform:uppercase;letter-spacing:.1em;margin-bottom:2px;">Grade</div>
      <div style="font-size:1.1rem;font-weight:900;color:{gc};">{grade} &nbsp;<span style="font-size:0.75rem;color:{MUTED};">({score}/100)</span></div>
    </div>
    <div style="background:{BORDER};border:1px solid {BORDER2};
                border-radius:10px;padding:10px 18px;text-align:center;">
      <div style="font-size:0.65rem;color:{DIM};text-transform:uppercase;letter-spacing:.1em;margin-bottom:2px;">OWASP Hits</div>
      <div style="font-size:1.1rem;font-weight:900;color:{AMBER};">{owasp_hit_count}/10</div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════ LAYOUT ═══════════════════════════════════ -->
<div style="display:flex;min-height:calc(100vh - 64px);">

  <!-- ─── SIDEBAR ─────────────────────────────────────────────────────── -->
  <div style="width:230px;flex-shrink:0;background:{BG};border-right:1px solid {BORDER};
              padding:24px 14px;display:flex;flex-direction:column;gap:2px;">

    <div style="font-size:0.65rem;color:{DIM};text-transform:uppercase;letter-spacing:.12em;
                padding:0 6px;margin-bottom:8px;">Navigation</div>

    {nav_link("#overview",    "◈", "Overview",       CYAN)}
    {nav_link("#ai-analysis", "◎", "AI Analysis",    PURPLE)}
    {nav_link("#owasp",       "⬡", "OWASP Top 10",   AMBER)}
    {nav_link("#remediations","⬢", "Remediations",   GREEN)}
    {nav_link("#sast",        "◉", "SAST — Sonar",   PURPLE)}
    {nav_link("#sca",         "◈", "SCA — npm",      ORANGE)}
    {nav_link("#dast",        "◎", "DAST — ZAP",     RED)}
    {nav_link("#perf",        "⬡", "Performance",    CYAN)}
    {nav_link("#compliance",  "⬢", "Compliance",     AMBER)}

    <!-- Score ring -->
    <div style="margin-top:auto;padding-top:24px;border-top:1px solid {BORDER};text-align:center;">
      <div style="font-size:0.65rem;color:{DIM};text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;">Security Score</div>
      {score_ring}
    </div>

    <div style="text-align:center;padding:16px 6px 0;border-top:1px solid {BORDER};
                font-size:0.68rem;color:{DIM};line-height:1.8;">
      Free AI Engine v3.0<br>
      OWASP Top 10 (2021)<br>
      CWE Mapping &#x2022; Zero cost
    </div>
  </div>

  <!-- ─── MAIN CONTENT ─────────────────────────────────────────────────── -->
  <div style="flex:1;padding:36px 44px;overflow-x:hidden;max-width:1300px;">

    <!-- ══ OVERVIEW ══ -->
    <div id="overview" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("◈", "Executive Overview", CYAN)}

      <!-- Metric grid -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:14px;">
        {tool_stat("SAST Criticals", sonar_summary.get("critical",0), "Gate = 0", RED if sonar_summary.get("critical",0)>0 else GREEN, "🔍")}
        {tool_stat("SCA Critical",   sca["critical"],  f'{sca["total"]} total CVEs', RED if sca["critical"]>0 else GREEN, "📦")}
        {tool_stat("SCA High",       sca["high"],      f'{sca["medium"]} medium', ORANGE if sca["high"]>0 else GREEN, "📦")}
        {tool_stat("DAST High",      zap["high"],      f'{zap["total"]} total alerts', RED if zap["high"]>0 else GREEN, "🕷️")}
        {tool_stat("P95 Latency",    f'{perf["p95_rt"]}ms', "Gate ≤ 2000ms", RED if perf["p95_rt"]>2000 else GREEN, "⚡")}
        {tool_stat("Error Rate",     f'{err_rate_val}%', "Gate ≤ 5%", RED if err_rate_val>5 else GREEN, "⚡")}
      </div>

      <!-- Severity distribution bars -->
      <div style="background:{BG3};border:1px solid {BORDER};border-radius:14px;padding:20px;">
        <div style="font-size:0.72rem;color:{MUTED};text-transform:uppercase;letter-spacing:.09em;margin-bottom:16px;">Severity distribution across all tools</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;">
          <div>
            <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:5px;">
              <span style="color:{RED};font-weight:600;">Critical</span>
              <span style="color:{TEXT};">{sca["critical"] + sonar_summary.get("critical",0)}</span>
            </div>
            {bar(min(100, (sca["critical"]+sonar_summary.get("critical",0))*8), RED)}
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:5px;">
              <span style="color:{ORANGE};font-weight:600;">High</span>
              <span style="color:{TEXT};">{sca["high"] + zap["high"]}</span>
            </div>
            {bar(min(100, (sca["high"]+zap["high"])*5), ORANGE)}
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:5px;">
              <span style="color:{AMBER};font-weight:600;">Medium</span>
              <span style="color:{TEXT};">{sca["medium"] + zap["medium"]}</span>
            </div>
            {bar(min(100, (sca["medium"]+zap["medium"])*3), AMBER)}
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:5px;">
              <span style="color:{GREEN};font-weight:600;">Low</span>
              <span style="color:{TEXT};">{sca["low"] + zap["low"]}</span>
            </div>
            {bar(min(100, (sca["low"]+zap["low"])*2), GREEN)}
          </div>
        </div>
      </div>
    </div>

    <!-- ══ AI ANALYSIS ══ -->
    <div id="ai-analysis" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("◎", "AI Security Analysis — Expert Engine", PURPLE)}

      <!-- Executive summary card -->
      <div style="background:{BG3};border:1px solid {BORDER};border-radius:16px;padding:24px;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap;">
          {glowing_dot(CYAN)}
          <span style="font-weight:700;color:{TEXT};font-size:0.95rem;">Executive Summary</span>
          <span style="margin-left:auto;background:{rc}18;color:{rc};padding:3px 12px;
                       border-radius:20px;font-size:0.72rem;font-weight:700;border:1px solid {rc}40;">
            {risk} Risk &#x2022; {decision}</span>
        </div>
        <div style="font-size:0.88rem;color:{MUTED};line-height:1.85;
                    background:{BG4};padding:18px 20px;border-radius:10px;
                    border-left:3px solid {CYAN};">{summary}</div>
      </div>

      <!-- Insight cards -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px;">
        {insight_card("📦", "SCA Intelligence",  ORANGE, insights["sca"])}
        {insight_card("🕷️", "DAST Intelligence", RED,    insights["dast"])}
        {insight_card("🔍", "SAST Intelligence", PURPLE, insights["sast"])}
        {insight_card("⚡", "Perf Intelligence", CYAN,   insights["perf"])}
      </div>
    </div>

    <!-- ══ OWASP TOP 10 ══ -->
    <div id="owasp" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("⬡", "OWASP Top 10 (2021) Coverage Map", AMBER)}
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:14px;">
        {owasp_cards}
      </div>
    </div>

    <!-- ══ REMEDIATIONS ══ -->
    <div id="remediations" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("⬢", "AI-Prioritised Remediation Plan", GREEN)}
      {table_wrap(
        ["#", "Tool", "OWASP", "Issue", "Recommended Fix", "Impact"],
        remed_rows or f'<tr><td colspan="6" style="padding:24px;text-align:center;color:{DIM};font-size:0.85rem;">No remediation items — excellent security posture!</td></tr>',
        "700px"
      )}
    </div>

    <!-- ══ SAST ══ -->
    <div id="sast" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("◉", "SAST — SonarQube Findings", PURPLE)}
      <!-- Mini stat strip -->
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(RED)}
          <span style="font-size:0.8rem;color:{MUTED};">Critical:</span>
          <span style="font-size:0.85rem;font-weight:700;color:{RED};">{sonar_summary.get("critical",0)}</span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(AMBER)}
          <span style="font-size:0.8rem;color:{MUTED};">Major:</span>
          <span style="font-size:0.85rem;font-weight:700;color:{AMBER};">{sonar_summary.get("major",0)}</span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(CYAN)}
          <span style="font-size:0.8rem;color:{MUTED};">Gate status:</span>
          <span style="font-size:0.85rem;font-weight:700;color:{GREEN if sonar_summary.get('critical',0)==0 else RED};">
            {"OK" if sonar_summary.get("critical",0)==0 else "FAILED"}</span>
        </div>
      </div>
      {table_wrap(
        ["Message", "Severity", "File", "Rule ID", "OWASP"],
        sonar_rows or f'<tr><td colspan="5" style="padding:24px;text-align:center;color:{DIM};">No critical/major issues found</td></tr>',
        "700px"
      )}
    </div>

    <!-- ══ SCA ══ -->
    <div id="sca" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("◈", "SCA — Dependency Vulnerabilities (npm audit)", ORANGE)}
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(RED)}
          <span style="font-size:0.8rem;color:{MUTED};">Critical: <strong style="color:{RED};">{sca["critical"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(ORANGE)}
          <span style="font-size:0.8rem;color:{MUTED};">High: <strong style="color:{ORANGE};">{sca["high"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(AMBER)}
          <span style="font-size:0.8rem;color:{MUTED};">Medium: <strong style="color:{AMBER};">{sca["medium"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(GREEN)}
          <span style="font-size:0.8rem;color:{MUTED};">Low: <strong style="color:{GREEN};">{sca["low"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(MUTED)}
          <span style="font-size:0.8rem;color:{MUTED};">Total: <strong style="color:{TEXT};">{sca["total"]}</strong></span>
        </div>
      </div>
      {table_wrap(
        ["Package", "Severity", "CVEs", "OWASP", "Fix"],
        sca_rows or f'<tr><td colspan="5" style="padding:24px;text-align:center;color:{DIM};">No dependency vulnerabilities found</td></tr>',
        "680px"
      )}
    </div>

    <!-- ══ DAST ══ -->
    <div id="dast" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("◎", "DAST — OWASP ZAP Active Scan Results", RED)}
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(RED)}
          <span style="font-size:0.8rem;color:{MUTED};">High: <strong style="color:{RED};">{zap["high"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(AMBER)}
          <span style="font-size:0.8rem;color:{MUTED};">Medium: <strong style="color:{AMBER};">{zap["medium"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(GREEN)}
          <span style="font-size:0.8rem;color:{MUTED};">Low: <strong style="color:{GREEN};">{zap["low"]}</strong></span>
        </div>
        <div style="background:{BG3};border:1px solid {BORDER};border-radius:10px;padding:10px 16px;
                    display:flex;align-items:center;gap:8px;">
          {glowing_dot(MUTED)}
          <span style="font-size:0.8rem;color:{MUTED};">Total: <strong style="color:{TEXT};">{zap["total"]}</strong></span>
        </div>
      </div>
      {table_wrap(
        ["Alert", "Risk", "CWE", "OWASP", "Remediation", "Affected URLs"],
        zap_rows or f'<tr><td colspan="6" style="padding:24px;text-align:center;color:{DIM};">No ZAP alerts found</td></tr>',
        "820px"
      )}
    </div>

    <!-- ══ PERFORMANCE ══ -->
    <div id="perf" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("⚡", "Performance — JMeter Load Test Results", CYAN)}

      <!-- Summary stat strip -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:16px;">
        <div style="background:{BG4};border:1px solid {BORDER};border-radius:12px;padding:16px;">
          <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.09em;color:{MUTED};margin-bottom:6px;">Samples</div>
          <div style="font-size:1.6rem;font-weight:800;color:{TEXT};">{perf["samples"]}</div>
        </div>
        <div style="background:{BG4};border:1px solid {BORDER};border-radius:12px;padding:16px;">
          <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.09em;color:{MUTED};margin-bottom:6px;">Avg RT</div>
          <div style="font-size:1.6rem;font-weight:800;color:{TEXT};">{round(perf["avg_rt"])}ms</div>
        </div>
        <div style="background:{BG4};border:1px solid {BORDER};border-radius:12px;padding:16px;
                    border-top:3px solid {RED if perf["p95_rt"]>2000 else GREEN};">
          <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.09em;color:{MUTED};margin-bottom:6px;">P95</div>
          <div style="font-size:1.6rem;font-weight:800;color:{RED if perf["p95_rt"]>2000 else GREEN};">{perf["p95_rt"]}ms</div>
        </div>
        <div style="background:{BG4};border:1px solid {BORDER};border-radius:12px;padding:16px;">
          <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.09em;color:{MUTED};margin-bottom:6px;">P99</div>
          <div style="font-size:1.6rem;font-weight:800;color:{TEXT};">{perf["p99_rt"]}ms</div>
        </div>
        <div style="background:{BG4};border:1px solid {BORDER};border-radius:12px;padding:16px;">
          <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.09em;color:{MUTED};margin-bottom:6px;">Throughput</div>
          <div style="font-size:1.6rem;font-weight:800;color:{CYAN};">{perf["throughput"]}/s</div>
        </div>
        <div style="background:{BG4};border:1px solid {BORDER};border-radius:12px;padding:16px;
                    border-top:3px solid {RED if perf["errors"]>0 else GREEN};">
          <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.09em;color:{MUTED};margin-bottom:6px;">Errors</div>
          <div style="font-size:1.6rem;font-weight:800;color:{RED if perf["errors"]>0 else GREEN};">{perf["errors"]}</div>
        </div>
      </div>

      {table_wrap(
        ["Endpoint", "Samples", "Avg RT", "P95 + bar", "Error %", "Errors"],
        perf_rows or f'<tr><td colspan="6" style="padding:24px;text-align:center;color:{DIM};">No JMeter data available</td></tr>',
        "600px"
      )}
    </div>

    <!-- ══ COMPLIANCE ══ -->
    <div id="compliance" style="margin-bottom:56px;scroll-margin-top:24px;">
      {section_header("⬢", "Compliance & Regulatory Notes", AMBER)}
      <div style="background:{BG3};border:1px solid {BORDER};border-radius:16px;padding:24px;">
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px;">
          {"".join(f'<span style="background:{AMBER}18;color:{AMBER};border:1px solid {AMBER}40;'
                   f'padding:3px 10px;border-radius:20px;font-size:0.7rem;font-weight:600;">{tag}</span>'
                   for tag in ["OWASP Top 10 (2021)","PCI-DSS","GDPR","NIST SP 800-190","CWE"])}
        </div>
        {comp_rows or f'<div style="color:{DIM};font-size:0.85rem;">No compliance violations detected.</div>'}
      </div>
    </div>

    <!-- Footer -->
    <div style="text-align:center;padding:28px 0;border-top:1px solid {BORDER};
                font-size:0.72rem;color:{DIM};line-height:2;">
      SHIVA AI Security Intelligence Suite v3.0 &nbsp;&#x2022;&nbsp;
      Free Expert Engine &nbsp;&#x2022;&nbsp; Build #{BUILD_NUMBER}<br>
      Zero API cost &nbsp;&#x2022;&nbsp; OWASP Top 10 (2021) &nbsp;&#x2022;&nbsp;
      CWE Mapping &nbsp;&#x2022;&nbsp; Deterministic Analysis
    </div>

  </div><!-- /main -->
</div><!-- /layout -->
</body>
</html>"""

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)
    print(f"\n  Dashboard → {OUTPUT_FILE}")
    print(f"  Score: {score}/100 | Grade: {grade} | Build: {decision}")
    print("=== Done ===\n")


if __name__ == "__main__":
    generate_dashboard()
