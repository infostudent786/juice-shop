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
# ─────────────────────────────────────────────────────────────────────────────
def sev_color(sev):
    s = str(sev).upper()
    if s in ("CRITICAL","BLOCKER"): return "#ef4444"
    if s in ("HIGH",):              return "#f97316"
    if s in ("MEDIUM","MODERATE","MAJOR"): return "#f59e0b"
    return "#94a3b8"

def risk_color(r):
    r = str(r).lower()
    if r == "high":   return "#ef4444"
    if r == "medium": return "#f59e0b"
    if r == "low":    return "#22c55e"
    return "#94a3b8"

def owasp_badge(owasp_id):
    info = OWASP_TOP10.get(owasp_id, {"name": "Unknown", "color": "#64748b"})
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:12px;'
            f'font-size:0.75rem;font-weight:700;background:{info["color"]}22;'
            f'color:{info["color"]};border:1px solid {info["color"]}55;">'
            f'{owasp_id}: {info["name"]}</span>')

def bar(pct, color="#3b82f6", height="8px"):
    pct = max(0, min(100, pct))
    return (f'<div style="background:#1e293b;border-radius:4px;height:{height};overflow:hidden;">'
            f'<div style="width:{pct}%;background:{color};height:100%;border-radius:4px;"></div></div>')


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

    # ── OWASP section HTML ───────────────────────────────────────────────────
    owasp_cards = ""
    for oid, info in OWASP_TOP10.items():
        hits = ai.owasp_hits.get(oid, [])
        cnt  = len(hits)
        col  = info["color"] if cnt > 0 else "#334155"
        hit_list = "".join(
            f'<div style="font-size:0.8rem;color:#cbd5e1;padding:4px 0;border-bottom:1px solid #334155;">'
            f'<span style="color:{sev_color(h.get("severity","LOW"))};">●</span> [{h["source"]}] {h["title"][:70]}</div>'
            for h in hits[:4]
        )
        owasp_cards += f"""
        <div style="background:#1e293b;border:1px solid {col};border-radius:12px;padding:18px;
                    border-top:4px solid {col};">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <span style="font-weight:700;color:{col};">{oid}</span>
                <span style="background:{col}22;color:{col};padding:2px 10px;border-radius:20px;
                             font-size:0.8rem;font-weight:700;">
                    {cnt} finding{'s' if cnt!=1 else ''}
                </span>
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;margin-bottom:10px;">{info['name']}</div>
            {hit_list if hit_list else '<div style="font-size:0.8rem;color:#475569;">No findings</div>'}
        </div>"""

    # ── Remediation rows ─────────────────────────────────────────────────────
    remed_rows = ""
    for r in remeds:
        owasp_id = r.get("owasp","A04")
        impact_col = "#ef4444" if r["impact"] in ("Critical","HIGH","CRITICAL") else \
                     "#f97316" if r["impact"] in ("High",) else "#f59e0b"
        remed_rows += f"""
        <tr>
            <td style="padding:12px;border-bottom:1px solid #1e293b;font-weight:700;color:#e2e8f0;">#{r['priority']}</td>
            <td style="padding:12px;border-bottom:1px solid #1e293b;">
                <span style="background:#334155;color:#94a3b8;padding:2px 8px;border-radius:6px;
                             font-size:0.75rem;">{r['tool']}</span>
            </td>
            <td style="padding:12px;border-bottom:1px solid #1e293b;">{owasp_badge(owasp_id)}</td>
            <td style="padding:12px;border-bottom:1px solid #1e293b;color:#e2e8f0;">{r['issue']}</td>
            <td style="padding:12px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:0.85rem;">{r['fix']}</td>
            <td style="padding:12px;border-bottom:1px solid #1e293b;">
                <span style="color:{impact_col};font-weight:700;font-size:0.85rem;">{r['impact']}</span>
            </td>
        </tr>"""

    # ── SCA rows ─────────────────────────────────────────────────────────────
    sca_rows = ""
    for f in sca.get("findings",[])[:20]:
        pkg  = f["package"]
        sev  = f["severity"]
        cves = ", ".join(f.get("cves",[])) or "—"
        fix  = f.get("fix","Manual update")
        rule = next((CVE_RULES[k] for k in CVE_RULES if k in pkg.lower()), None)
        ow   = owasp_badge(rule["owasp"]) if rule else owasp_badge("A06")
        sca_rows += f"""
        <tr>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-family:monospace;
                       font-size:0.85rem;color:#e2e8f0;">{pkg}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">
                <span style="color:{sev_color(sev)};font-weight:700;">{sev}</span></td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-size:0.8rem;color:#94a3b8;">{cves}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">{ow}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:0.85rem;">{fix}</td>
        </tr>"""

    # ── ZAP rows ─────────────────────────────────────────────────────────────
    zap_rows = ""
    for f in zap.get("findings",[])[:20]:
        cw  = f.get("cweid","")
        ow  = owasp_badge(CWE_TO_OWASP.get(str(cw), next(
            (v for k,v in ZAP_NAME_TO_OWASP.items() if k in f["name"].lower()), "A05")))
        urls = " ".join(
            f'<div style="font-size:0.75rem;color:#60a5fa;word-break:break-all;">{u[:80]}</div>'
            for u in f.get("instances",[])[:2]
        )
        zap_rows += f"""
        <tr>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-weight:600;color:#e2e8f0;">{f['name']}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">
                <span style="color:{risk_color(f['risk'])};font-weight:700;">{f['risk'].upper()}</span></td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-size:0.8rem;color:#64748b;">CWE-{cw}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">{ow}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-size:0.85rem;color:#94a3b8;">
                {f.get('solution','')[:120]}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">{urls}</td>
        </tr>"""

    # ── Sonar rows ───────────────────────────────────────────────────────────
    sonar_rows = ""
    for iss in sonar_issues.get("issues",[])[:20]:
        sev  = iss.get("severity","MAJOR")
        rule = iss.get("rule","")
        comp = iss.get("component","").split(":")[-1]
        ow   = owasp_badge(SONAR_RULE_OWASP.get(rule,"A04"))
        sonar_rows += f"""
        <tr>
            <td style="padding:11px;border-bottom:1px solid #1e293b;color:#e2e8f0;">{iss.get('message','')[:90]}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">
                <span style="color:{sev_color(sev)};font-weight:700;">{sev}</span></td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-family:monospace;
                       font-size:0.8rem;color:#94a3b8;">{comp}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-family:monospace;
                       font-size:0.8rem;color:#64748b;">{rule}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">{ow}</td>
        </tr>"""

    # ── Perf rows ─────────────────────────────────────────────────────────────
    perf_rows = ""
    for label, ep in perf.get("endpoints",{}).items():
        p95_col = "#ef4444" if ep["p95"] > 3000 else "#f59e0b" if ep["p95"] > 1500 else "#22c55e"
        err_col = "#ef4444" if ep["error_rate"] > 5 else "#22c55e"
        pct = min(100, int(ep["p95"]/30))
        perf_rows += f"""
        <tr>
            <td style="padding:11px;border-bottom:1px solid #1e293b;font-family:monospace;
                       font-size:0.85rem;color:#e2e8f0;">{label}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;color:#94a3b8;">{ep['count']}</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;color:#94a3b8;">{round(ep['avg'],0)}ms</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="color:{p95_col};font-weight:700;">{ep['p95']}ms</span>
                    {bar(pct, p95_col, "6px")}
                </div>
            </td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;color:{err_col};font-weight:700;">
                {ep['error_rate']}%</td>
            <td style="padding:11px;border-bottom:1px solid #1e293b;color:#94a3b8;">{ep['errors']}</td>
        </tr>"""

    # ── Compliance rows ───────────────────────────────────────────────────────
    comp_rows = "".join(
        f'<div style="padding:10px 14px;background:#1e293b;border-radius:8px;'
        f'border-left:3px solid #f59e0b;margin-bottom:8px;'
        f'font-size:0.9rem;color:#cbd5e1;">{note}</div>'
        for note in comp
    )

    # ── Score ring SVG ────────────────────────────────────────────────────────
    r   = 54
    circ = 2 * 3.14159 * r
    dash = circ * score / 100
    score_ring = f"""
    <svg width="140" height="140" viewBox="0 0 140 140">
      <circle cx="70" cy="70" r="{r}" fill="none" stroke="#1e293b" stroke-width="12"/>
      <circle cx="70" cy="70" r="{r}" fill="none" stroke="{gc}" stroke-width="12"
              stroke-dasharray="{dash:.1f} {circ:.1f}" stroke-linecap="round"
              transform="rotate(-90 70 70)"/>
      <text x="70" y="62" text-anchor="middle" fill="{gc}"
            font-size="28" font-weight="900" font-family="system-ui">{score}</text>
      <text x="70" y="82" text-anchor="middle" fill="#94a3b8"
            font-size="13" font-family="system-ui">/ 100</text>
      <text x="70" y="100" text-anchor="middle" fill="{gc}"
            font-size="22" font-weight="900" font-family="system-ui">Grade {grade}</text>
    </svg>"""

    decision_col = "#22c55e" if decision == "PASS" else "#ef4444"
    d_icon       = "✓" if decision == "PASS" else "✗"

    # ── Full HTML ──────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SHIVA AI — Build #{BUILD_NUMBER}</title>
</head>
<body style="background:#0f172a;color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:0;">

<!-- TOP BAR -->
<div style="background:#1e293b;border-bottom:1px solid #334155;padding:14px 32px;
            display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
  <div>
    <div style="font-size:1.3rem;font-weight:800;color:#22d3ee;letter-spacing:-0.02em;">
      🛡️ SHIVA AI — Security Intelligence Dashboard
    </div>
    <div style="font-size:0.8rem;color:#64748b;margin-top:3px;">
      Job: {JOB_NAME} &nbsp;|&nbsp; Build #{BUILD_NUMBER} &nbsp;|&nbsp;
      Generated: {now} &nbsp;|&nbsp;
      <a href="{BUILD_URL}" style="color:#38bdf8;">View in Jenkins →</a>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:16px;">
    <div style="text-align:center;">
      <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em;">Build Decision</div>
      <div style="font-size:1.4rem;font-weight:900;color:{decision_col};">{d_icon} {decision}</div>
      <div style="font-size:0.75rem;color:#64748b;">{dreason}</div>
    </div>
    <div style="text-align:center;">
      <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em;">Risk Level</div>
      <div style="font-size:1.4rem;font-weight:900;color:{rc};">{risk}</div>
    </div>
  </div>
</div>

<!-- SIDEBAR + MAIN LAYOUT -->
<div style="display:flex;">

  <!-- SIDEBAR -->
  <div style="width:220px;min-height:100vh;background:#1e293b;border-right:1px solid #334155;
              padding:24px 16px;flex-shrink:0;">
    <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.1em;
                margin-bottom:16px;">Navigation</div>
    <a href="#overview" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">📊 Overview</a>
    <a href="#ai-analysis" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">🤖 AI Analysis</a>
    <a href="#owasp" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">🔟 OWASP Top 10</a>
    <a href="#remediations" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">🔧 Remediations</a>
    <a href="#sast" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">🔍 SAST — SonarQube</a>
    <a href="#sca" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">📦 SCA — npm audit</a>
    <a href="#dast" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">🕷️ DAST — ZAP</a>
    <a href="#perf" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">⚡ Performance</a>
    <a href="#compliance" style="display:block;color:#94a3b8;text-decoration:none;padding:9px 12px;
       border-radius:8px;margin-bottom:4px;font-size:0.9rem;">📋 Compliance</a>

    <div style="margin-top:32px;padding-top:16px;border-top:1px solid #334155;">
      <div style="font-size:0.7rem;color:#64748b;margin-bottom:8px;">Security Score</div>
      {score_ring}
    </div>
    <div style="margin-top:16px;font-size:0.72rem;color:#475569;line-height:1.6;">
      Free AI Engine v3.0<br>OWASP Top 10 (2021)<br>CWE Mapping<br>Zero API cost
    </div>
  </div>

  <!-- MAIN -->
  <div style="flex:1;padding:32px 40px;max-width:1200px;">

    <!-- ── OVERVIEW ── -->
    <div id="overview" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #22d3ee;
                 padding-left:12px;">Executive Overview</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;">
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;">
          <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;">SAST Critical</div>
          <div style="font-size:1.8rem;font-weight:800;color:{sev_color('CRITICAL') if sonar_summary.get('critical',0)>0 else '#22c55e'};">
            {sonar_summary.get('critical',0)}</div>
          <div style="font-size:0.75rem;color:#475569;">Gate = 0</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;">
          <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;">SCA Critical</div>
          <div style="font-size:1.8rem;font-weight:800;color:{sev_color('CRITICAL') if sca['critical']>0 else '#22c55e'};">
            {sca['critical']}</div>
          <div style="font-size:0.75rem;color:#475569;">{sca['total']} total</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;">
          <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;">DAST High</div>
          <div style="font-size:1.8rem;font-weight:800;color:{risk_color('high') if zap['high']>0 else '#22c55e'};">
            {zap['high']}</div>
          <div style="font-size:0.75rem;color:#475569;">{zap['total']} total alerts</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;">
          <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;">P95 Latency</div>
          <div style="font-size:1.8rem;font-weight:800;color:{'#ef4444' if perf['p95_rt']>2000 else '#22c55e'};">
            {perf['p95_rt']}ms</div>
          <div style="font-size:0.75rem;color:#475569;">Gate ≤ 2000ms</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;">
          <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;">Error Rate</div>
          <div style="font-size:1.8rem;font-weight:800;color:{'#ef4444' if perf['errors']/max(perf['samples'],1)*100>5 else '#22c55e'};">
            {round(perf['errors']/max(perf['samples'],1)*100,1)}%</div>
          <div style="font-size:0.75rem;color:#475569;">Gate ≤ 5%</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;">
          <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;">OWASP Hits</div>
          <div style="font-size:1.8rem;font-weight:800;color:#f59e0b;">{len(ai.owasp_hits)}</div>
          <div style="font-size:0.75rem;color:#475569;">categories affected</div>
        </div>
      </div>
    </div>

    <!-- ── AI ANALYSIS ── -->
    <div id="ai-analysis" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #818cf8;
                 padding-left:12px;">🤖 AI Security Analysis — Expert Engine</h2>

      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;padding:24px;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
          <div style="width:8px;height:8px;border-radius:50%;background:#22d3ee;"></div>
          <span style="font-weight:700;color:#e2e8f0;font-size:1rem;">Executive Summary</span>
          <span style="background:{rc}22;color:{rc};padding:2px 10px;border-radius:20px;font-size:0.78rem;font-weight:700;margin-left:auto;">
            {risk} Risk</span>
        </div>
        <div style="font-size:0.9rem;color:#cbd5e1;line-height:1.8;background:#0f172a;padding:16px;
                    border-radius:8px;border-left:3px solid #22d3ee;">{summary}</div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;">
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;
                    border-top:3px solid #f97316;">
          <div style="font-weight:700;color:#f97316;margin-bottom:8px;">📦 SCA Intelligence</div>
          <div style="font-size:0.85rem;color:#94a3b8;line-height:1.7;">{insights['sca']}</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;
                    border-top:3px solid #ef4444;">
          <div style="font-weight:700;color:#ef4444;margin-bottom:8px;">🕷️ DAST Intelligence</div>
          <div style="font-size:0.85rem;color:#94a3b8;line-height:1.7;">{insights['dast']}</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;
                    border-top:3px solid #818cf8;">
          <div style="font-weight:700;color:#818cf8;margin-bottom:8px;">🔍 SAST Intelligence</div>
          <div style="font-size:0.85rem;color:#94a3b8;line-height:1.7;">{insights['sast']}</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;
                    border-top:3px solid #22d3ee;">
          <div style="font-weight:700;color:#22d3ee;margin-bottom:8px;">⚡ Performance Intelligence</div>
          <div style="font-size:0.85rem;color:#94a3b8;line-height:1.7;">{insights['perf']}</div>
        </div>
      </div>
    </div>

    <!-- ── OWASP TOP 10 ── -->
    <div id="owasp" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #f59e0b;
                 padding-left:12px;">🔟 OWASP Top 10 Coverage Map</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;">
        {owasp_cards}
      </div>
    </div>

    <!-- ── REMEDIATIONS ── -->
    <div id="remediations" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #22c55e;
                 padding-left:12px;">🔧 AI-Prioritised Remediation Plan</h2>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;">
          <thead style="background:#0f172a;">
            <tr>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">#</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Tool</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">OWASP</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Issue</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Recommended Fix</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Impact</th>
            </tr>
          </thead>
          <tbody>
            {remed_rows or '<tr><td colspan="6" style="padding:20px;text-align:center;color:#475569;">No remediation items — excellent security posture!</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── SAST ── -->
    <div id="sast" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #818cf8;
                 padding-left:12px;">🔍 SAST — SonarQube Findings</h2>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;min-width:700px;">
          <thead style="background:#0f172a;">
            <tr>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Message</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Severity</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">File</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Rule</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">OWASP</th>
            </tr>
          </thead>
          <tbody>
            {sonar_rows or '<tr><td colspan="5" style="padding:20px;text-align:center;color:#475569;">No critical/major SonarQube issues found</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── SCA ── -->
    <div id="sca" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #f97316;
                 padding-left:12px;">📦 SCA — Dependency Vulnerabilities</h2>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;min-width:700px;">
          <thead style="background:#0f172a;">
            <tr>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Package</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Severity</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">CVEs</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">OWASP</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Fix</th>
            </tr>
          </thead>
          <tbody>
            {sca_rows or '<tr><td colspan="5" style="padding:20px;text-align:center;color:#475569;">No dependency vulnerabilities found</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── DAST ── -->
    <div id="dast" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #ef4444;
                 padding-left:12px;">🕷️ DAST — OWASP ZAP Alerts</h2>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;min-width:800px;">
          <thead style="background:#0f172a;">
            <tr>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Alert</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Risk</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">CWE</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">OWASP</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Remediation</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">URLs</th>
            </tr>
          </thead>
          <tbody>
            {zap_rows or '<tr><td colspan="6" style="padding:20px;text-align:center;color:#475569;">No ZAP alerts found</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── PERFORMANCE ── -->
    <div id="perf" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #22d3ee;
                 padding-left:12px;">⚡ Performance — JMeter Results</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px;">
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
          <div style="font-size:0.75rem;color:#64748b;">Total Samples</div>
          <div style="font-size:1.5rem;font-weight:800;color:#e2e8f0;">{perf['samples']}</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
          <div style="font-size:0.75rem;color:#64748b;">Avg Response</div>
          <div style="font-size:1.5rem;font-weight:800;color:#e2e8f0;">{round(perf['avg_rt'])}ms</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
          <div style="font-size:0.75rem;color:#64748b;">P95</div>
          <div style="font-size:1.5rem;font-weight:800;color:{'#ef4444' if perf['p95_rt']>2000 else '#22c55e'};">
            {perf['p95_rt']}ms</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
          <div style="font-size:0.75rem;color:#64748b;">P99</div>
          <div style="font-size:1.5rem;font-weight:800;color:#e2e8f0;">{perf['p99_rt']}ms</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
          <div style="font-size:0.75rem;color:#64748b;">Throughput</div>
          <div style="font-size:1.5rem;font-weight:800;color:#e2e8f0;">{perf['throughput']}/s</div>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
          <div style="font-size:0.75rem;color:#64748b;">Total Errors</div>
          <div style="font-size:1.5rem;font-weight:800;color:{'#ef4444' if perf['errors']>0 else '#22c55e'};">
            {perf['errors']}</div>
        </div>
      </div>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;min-width:600px;">
          <thead style="background:#0f172a;">
            <tr>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Endpoint</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Samples</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Avg</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">P95</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Error %</th>
              <th style="padding:12px;color:#64748b;text-align:left;font-size:0.8rem;">Errors</th>
            </tr>
          </thead>
          <tbody>
            {perf_rows or '<tr><td colspan="6" style="padding:20px;text-align:center;color:#475569;">No JMeter data available</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── COMPLIANCE ── -->
    <div id="compliance" style="margin-bottom:48px;scroll-margin-top:20px;">
      <h2 style="color:#e2e8f0;font-size:1.3rem;margin:0 0 20px;border-left:4px solid #f59e0b;
                 padding-left:12px;">📋 Compliance & Regulatory Notes</h2>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px;">
        <div style="font-size:0.8rem;color:#475569;margin-bottom:14px;text-transform:uppercase;
                    letter-spacing:.08em;">OWASP Top 10 (2021) · PCI-DSS · GDPR · NIST SP 800-190</div>
        {comp_rows}
      </div>
    </div>

    <div style="text-align:center;padding:24px 0;color:#334155;font-size:0.8rem;
                border-top:1px solid #1e293b;">
      SHIVA AI Security Intelligence Suite v3.0 — Free Expert Engine — Build #{BUILD_NUMBER}<br>
      Zero API cost · OWASP Top 10 (2021) · CWE Mapping · Deterministic Analysis
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
