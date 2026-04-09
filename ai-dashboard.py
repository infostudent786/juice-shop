#!/usr/bin/env python3
"""
SHIVA AI — Free DevSecOps Intelligence Dashboard v4.0
Expert-system AI engine: zero API cost, full OWASP Top 10 coverage,
deterministic security analysis derived entirely from scan outputs.

FIXES in v4.0:
  - Sonar issues parser now handles BOTH old (squid:) and new (java:) rule prefixes
  - sonar-summary.json now counts major correctly via a second curl call
  - Dependency-Check JSON parsed and fed into SCA findings (uses installed plugin)
  - npm audit parser handles BOTH npm v6 (advisories) and npm v7+ (vulnerabilities) formats
  - ZAP parser handles both site-array and flat-array report formats
  - JMeter parser handles both "elapsed/success" and "t/s" column names
  - Build-gate logic uses combined sca+depcheck critical count
  - Score and grade now reflect dependency-check findings
"""

import json, os, csv, math
from datetime import datetime

REPORTS_DIR  = os.getenv("REPORTS_DIR", "./reports")
OUTPUT_FILE  = os.path.join(REPORTS_DIR, "dashboard.html")
BUILD_NUMBER = os.getenv("BUILD_NUMBER", "local")
JOB_NAME     = os.getenv("JOB_NAME", "devsecops-juice-shop")
BUILD_URL    = os.getenv("BUILD_URL", "#")
APP_URL      = os.getenv("APP_URL", "http://localhost:3000")

# ─────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 (2021) knowledge base
# ─────────────────────────────────────────────────────────────────────────────
OWASP_TOP10 = {
    "A01": {"name": "Broken Access Control",    "color": "#ef4444"},
    "A02": {"name": "Cryptographic Failures",   "color": "#f97316"},
    "A03": {"name": "Injection",                "color": "#ef4444"},
    "A04": {"name": "Insecure Design",          "color": "#f59e0b"},
    "A05": {"name": "Security Misconfiguration","color": "#f59e0b"},
    "A06": {"name": "Vulnerable Components",    "color": "#ef4444"},
    "A07": {"name": "Auth Failures",            "color": "#ef4444"},
    "A08": {"name": "Data Integrity Failures",  "color": "#f97316"},
    "A09": {"name": "Logging Failures",         "color": "#f59e0b"},
    "A10": {"name": "SSRF",                     "color": "#f97316"},
}

CWE_TO_OWASP = {
    "89":  "A03","564":"A03","943":"A03",
    "79":  "A03","80": "A03",
    "22":  "A01","284":"A01","285":"A01",
    "326": "A02","327":"A02","328":"A02",
    "759": "A02","916":"A02",
    "287": "A07","307":"A07","521":"A07",
    "601": "A01","639":"A01",
    "502": "A08","915":"A08",
    "1021":"A05","693":"A05","346":"A05",
    "200": "A02","359":"A02",
    "918": "A10",
    "400": "A05","770":"A05",
    "295": "A02","297":"A02","310":"A02",
    "20":  "A03","94": "A03","78": "A03",
    "352": "A05",
    "730": "A05","400":"A05",
}

ZAP_NAME_TO_OWASP = {
    "sql injection":           "A03",
    "xss":                     "A03",
    "cross site scripting":    "A03",
    "path traversal":          "A01",
    "missing csp":             "A05",
    "content security policy": "A05",
    "cors":                    "A05",
    "x-frame-options":         "A05",
    "anti-csrf":               "A05",
    "csrf":                    "A05",
    "cookie":                  "A02",
    "secure flag":             "A02",
    "httponly":                "A02",
    "sensitive data":          "A02",
    "information disclosure":  "A02",
    "authentication":          "A07",
    "session":                 "A07",
    "ssrf":                    "A10",
    "server side request":     "A10",
    "directory browsing":      "A05",
    "heartbleed":              "A06",
    "vulnerable":              "A06",
    "remote file":             "A03",
    "command injection":       "A03",
    "xml external entity":     "A05",
    "xxe":                     "A05",
    "open redirect":           "A01",
    "insecure deserialization":"A08",
}

CVE_RULES = {
    "log4j":        {"owasp":"A06","desc":"Log4Shell RCE","fix":"Upgrade log4j-core to ≥2.17.1"},
    "spring":       {"owasp":"A06","desc":"Spring4Shell RCE","fix":"Upgrade Spring Framework to ≥5.3.18"},
    "protobuf":     {"owasp":"A08","desc":"Deserialization vuln","fix":"Upgrade protobufjs to ≥6.11.4"},
    "lodash":       {"owasp":"A03","desc":"Prototype pollution","fix":"Upgrade lodash to ≥4.17.21"},
    "express":      {"owasp":"A05","desc":"Security misconfiguration","fix":"Upgrade express to latest"},
    "jsonwebtoken": {"owasp":"A07","desc":"Auth bypass","fix":"Upgrade jsonwebtoken to ≥9.0.0"},
    "webpack":      {"owasp":"A05","desc":"Dev config exposure","fix":"Use production webpack config"},
    "sanitize":     {"owasp":"A03","desc":"Input sanitization bypass","fix":"Upgrade sanitize-html"},
    "sqlite":       {"owasp":"A03","desc":"SQL injection possible","fix":"Use parameterised queries"},
    "node-forge":   {"owasp":"A02","desc":"Crypto weakness","fix":"Upgrade node-forge to ≥1.3.1"},
    "minimist":     {"owasp":"A03","desc":"Prototype pollution","fix":"Upgrade minimist to ≥1.2.6"},
    "moment":       {"owasp":"A05","desc":"ReDoS vulnerability","fix":"Upgrade moment to ≥2.29.4"},
    "axios":        {"owasp":"A10","desc":"SSRF via redirect","fix":"Upgrade axios to ≥1.6.0"},
    "ejs":          {"owasp":"A03","desc":"Template injection","fix":"Upgrade ejs to ≥3.1.10"},
    "vm2":          {"owasp":"A03","desc":"Sandbox escape / RCE","fix":"Replace vm2 (unmaintained)"},
}

# FIX: Support BOTH old squid: prefix AND new java:/javascript:/typescript: prefixes
SONAR_RULE_OWASP = {
    # Old-style squid rules
    "squid:S2068":"A02","squid:S4426":"A02","squid:S5542":"A02",
    "squid:S5547":"A02","squid:S5659":"A02","squid:S2076":"A03",
    "squid:S2631":"A03","squid:S3649":"A03","squid:S5131":"A03",
    "squid:S2083":"A01","squid:S5144":"A10","squid:S4790":"A02",
    "squid:S2245":"A02","squid:S6096":"A01",
    # New-style java: rules (SonarQube 9+)
    "java:S2068":"A02","java:S4426":"A02","java:S5542":"A02",
    "java:S5547":"A02","java:S5659":"A02","java:S2076":"A03",
    "java:S2631":"A03","java:S3649":"A03","java:S5131":"A03",
    "java:S2083":"A01","java:S5144":"A10","java:S4790":"A02",
    "java:S2245":"A02","java:S6096":"A01","java:S6350":"A03",
    # JavaScript / TypeScript rules
    "javascript:S2068":"A02","javascript:S5547":"A02","javascript:S4426":"A02",
    "javascript:S5131":"A03","javascript:S3649":"A03","javascript:S2076":"A03",
    "javascript:S2083":"A01","javascript:S5144":"A10","javascript:S4790":"A02",
    "typescript:S2068":"A02","typescript:S5547":"A02","typescript:S5131":"A03",
    "typescript:S2083":"A01","typescript:S4790":"A02",
    # Web/HTML rules
    "Web:S5131":"A03","Web:S4529":"A05","Web:S5725":"A02",
}

SEVERITY_ORDER = ["BLOCKER","CRITICAL","MAJOR","MINOR","INFO"]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def load_json(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return json.load(f)
        except Exception as e:
            print(f"  [WARN] {filename}: {e}")
    else:
        print(f"  [INFO] {filename} not found, skipping.")
    return None

# ─────────────────────────────────────────────────────────────────────────────
# FIX: npm audit — supports BOTH v6 (advisories{}) AND v7+ (vulnerabilities{})
# ─────────────────────────────────────────────────────────────────────────────
def parse_npm_audit(filename="npm-audit.json"):
    result = {"total":0,"critical":0,"high":0,"medium":0,"low":0,"findings":[]}
    data = load_json(filename)
    if not data:
        return result

    meta = data.get("metadata", {}).get("vulnerabilities", {})
    result["critical"] = meta.get("critical", 0)
    result["high"]     = meta.get("high", 0)
    result["medium"]   = meta.get("moderate", meta.get("medium", 0))
    result["low"]      = meta.get("low", 0)
    result["total"]    = meta.get("total", 0) or sum(
        [result["critical"], result["high"], result["medium"], result["low"]]
    )

    # npm v7+ format: vulnerabilities{}
    vulns = data.get("vulnerabilities", {})
    if vulns:
        for pkg, details in vulns.items():
            sev  = details.get("severity", "unknown").upper()
            via  = details.get("via", [])
            cves = [v.get("cve","") for v in via if isinstance(v, dict) and v.get("cve")]
            url  = next((v.get("url","") for v in via if isinstance(v, dict) and v.get("url")), "")
            fix_info = details.get("fixAvailable", "Manual update required")
            if isinstance(fix_info, dict):
                fix_str = f"Update {fix_info.get('name','')} to {fix_info.get('version','latest')}"
            else:
                fix_str = str(fix_info)
            result["findings"].append({
                "package": pkg, "severity": sev,
                "cves": cves, "url": url, "fix": fix_str,
            })

    # npm v6 format: advisories{}
    advisories = data.get("advisories", {})
    if advisories and not vulns:
        for adv_id, details in advisories.items():
            sev  = details.get("severity", "unknown").upper()
            cves = details.get("cves", [])
            result["findings"].append({
                "package":  details.get("module_name", "unknown"),
                "severity": sev,
                "cves":     cves,
                "url":      details.get("url", ""),
                "fix":      details.get("recommendation", "Update package"),
            })

    sev_order = ["CRITICAL","HIGH","MODERATE","MEDIUM","LOW","UNKNOWN"]
    result["findings"].sort(
        key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 99
    )
    return result

# ─────────────────────────────────────────────────────────────────────────────
# FIX: OWASP Dependency-Check JSON parser (uses installed SonarQube plugin)
# Parses dependency-check-report.json written by OWASP DC
# ─────────────────────────────────────────────────────────────────────────────
def parse_dependency_check(filename="dependency-check-report.json"):
    result = {"total":0,"critical":0,"high":0,"medium":0,"low":0,"findings":[]}
    data = load_json(filename)
    if not data:
        return result

    dependencies = data.get("dependencies", [])
    for dep in dependencies:
        vulns = dep.get("vulnerabilities", [])
        for v in vulns:
            sev_raw = v.get("severity", "").upper()
            # DC uses cvssv3 severity or cvssv2
            if not sev_raw:
                score = v.get("cvssv3", {}).get("baseScore", 0) or v.get("cvssv2", {}).get("score", 0)
                if score >= 9.0:   sev_raw = "CRITICAL"
                elif score >= 7.0: sev_raw = "HIGH"
                elif score >= 4.0: sev_raw = "MEDIUM"
                else:              sev_raw = "LOW"

            sev = sev_raw
            result["total"] += 1
            if sev == "CRITICAL": result["critical"] += 1
            elif sev == "HIGH":   result["high"] += 1
            elif sev == "MEDIUM": result["medium"] += 1
            else:                 result["low"] += 1

            cves   = [v.get("name","")]
            cwe_id = ""
            cwes   = v.get("cwes", [])
            if cwes:
                cwe_id = str(cwes[0]).replace("CWE-","")

            pkg_name = dep.get("fileName", dep.get("filePath", "unknown"))
            if "/" in pkg_name: pkg_name = pkg_name.split("/")[-1]

            result["findings"].append({
                "package":  pkg_name,
                "severity": sev,
                "cves":     cves,
                "url":      f"https://nvd.nist.gov/vuln/detail/{cves[0]}" if cves and cves[0].startswith("CVE") else "",
                "fix":      v.get("description","Update dependency to patch CVE.")[:200],
                "cweid":    cwe_id,
            })

    result["findings"].sort(
        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"])
            if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99
    )
    return result

# ─────────────────────────────────────────────────────────────────────────────
# FIX: ZAP — handles both {site:[{alerts:[]}]} and flat {alerts:[]} formats
# ─────────────────────────────────────────────────────────────────────────────
def parse_zap(filename="zap-report.json"):
    result = {"total":0,"high":0,"medium":0,"low":0,"informational":0,"findings":[]}
    data = load_json(filename)
    if not data:
        return result

    # Collect all alerts regardless of format
    all_alerts = []
    sites = data.get("site", [])
    if sites:
        for site in sites:
            alerts = site.get("alerts", [])
            all_alerts.extend(alerts)
    else:
        # flat format: top-level "alerts" key
        all_alerts = data.get("alerts", [])

    for alert in all_alerts:
        # riskdesc can be "High (3)" or just "High"
        riskdesc = alert.get("riskdesc", alert.get("risk", "")).strip()
        risk = riskdesc.split(" ")[0].strip() if riskdesc else "Informational"

        # Normalise
        if risk.lower() == "informational" or risk == "0": risk = "Informational"
        elif risk in ("1","Low"):      risk = "Low"
        elif risk in ("2","Medium"):   risk = "Medium"
        elif risk in ("3","High"):     risk = "High"

        result["total"] += 1
        if risk == "High":         result["high"] += 1
        elif risk == "Medium":     result["medium"] += 1
        elif risk == "Low":        result["low"] += 1
        else:                      result["informational"] += 1

        instances = [i.get("uri","") for i in alert.get("instances",[])[:5]]
        cweid = str(alert.get("cweid", alert.get("cweId", "")))

        result["findings"].append({
            "name":      alert.get("alert", alert.get("name","N/A")),
            "risk":      risk,
            "solution":  alert.get("solution","N/A"),
            "instances": instances,
            "cweid":     cweid,
            "desc":      alert.get("desc", alert.get("description",""))[:200],
        })

    result["findings"].sort(
        key=lambda x: {"High":0,"Medium":1,"Low":2,"Informational":3}.get(x["risk"],4)
    )
    return result

# ─────────────────────────────────────────────────────────────────────────────
# FIX: JMeter — handles elapsed/t and success/s column name variants
# ─────────────────────────────────────────────────────────────────────────────
def parse_jmeter(filename="jmeter-results.jtl"):
    result = {"samples":0,"errors":0,"avg_rt":0,"p95_rt":0,"p99_rt":0,"max_rt":0,"throughput":0,"endpoints":{}}
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        return result
    try:
        rows = []
        with open(path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        if not rows:
            return result

        all_rt, ep_data = [], {}
        for row in rows:
            # Support both column name variants
            label   = row.get("label") or row.get("s") or "unknown"
            elapsed = int(row.get("elapsed") or row.get("t") or 0)
            suc_raw = str(row.get("success") or row.get("s") or "true").lower()
            success = suc_raw in ("true","1","yes")

            result["samples"] += 1
            all_rt.append(elapsed)
            if not success:
                result["errors"] += 1

            if label not in ep_data:
                ep_data[label] = {"times":[],"errors":0}
            ep_data[label]["times"].append(elapsed)
            if not success:
                ep_data[label]["errors"] += 1

        n = len(all_rt)
        all_rt_s = sorted(all_rt)
        result["avg_rt"]     = round(sum(all_rt)/n, 1)
        result["max_rt"]     = all_rt_s[-1]
        result["p95_rt"]     = all_rt_s[min(int(n*0.95), n-1)]
        result["p99_rt"]     = all_rt_s[min(int(n*0.99), n-1)]
        duration_s           = max(result["max_rt"]/1000, 1)
        result["throughput"] = round(n/duration_s, 2)

        for lbl, d in ep_data.items():
            ts  = sorted(d["times"])
            cnt = len(ts)
            result["endpoints"][lbl] = {
                "count":      cnt,
                "avg":        round(sum(ts)/cnt, 1),
                "p95":        ts[min(int(cnt*0.95), cnt-1)],
                "max":        ts[-1],
                "errors":     d["errors"],
                "error_rate": round(d["errors"]/cnt*100, 2),
            }
    except Exception as e:
        print(f"  [WARN] jmeter parse: {e}")
    return result

# ─────────────────────────────────────────────────────────────────────────────
# FIX: SonarQube summary parser — correctly counts major + critical separately
# ─────────────────────────────────────────────────────────────────────────────
def parse_sonar_summary(filename="sonar-summary.json"):
    data = load_json(filename)
    if not data:
        return {"critical":0,"major":0,"minor":0,"info":0,"total":0}
    # Support both flat {"critical":N,"major":M} and nested {"issues":{...}} formats
    if "issues" in data and isinstance(data["issues"], dict):
        iss = data["issues"]
        return {
            "critical": iss.get("CRITICAL",0) + iss.get("BLOCKER",0),
            "major":    iss.get("MAJOR",0),
            "minor":    iss.get("MINOR",0),
            "info":     iss.get("INFO",0),
            "total":    sum(iss.values()),
        }
    crit = data.get("critical",0) + data.get("blocker",0)
    maj  = data.get("major",0)
    return {
        "critical": crit,
        "major":    maj,
        "minor":    data.get("minor",0),
        "info":     data.get("info",0),
        "total":    crit + maj + data.get("minor",0) + data.get("info",0),
    }

# ─────────────────────────────────────────────────────────────────────────────
# FREE AI ENGINE — Expert System
# ─────────────────────────────────────────────────────────────────────────────
class SecurityAI:
    def __init__(self, sca, depcheck, zap, perf, sonar_summary, sonar_issues):
        self.sca      = sca
        self.depcheck = depcheck   # NEW: OWASP Dependency-Check results
        self.zap      = zap
        self.perf     = perf
        self.sonar    = sonar_summary
        self.issues   = sonar_issues.get("issues", [])
        self.owasp_hits   = {}
        self.remediations = []
        self._analyse()

    def _analyse(self):
        self._map_sca_to_owasp()
        self._map_depcheck_to_owasp()
        self._map_zap_to_owasp()
        self._map_sonar_to_owasp()
        self._map_perf_risks()
        self._build_remediations()

    def _add_hit(self, owasp_id, source, finding):
        if owasp_id not in self.owasp_hits:
            self.owasp_hits[owasp_id] = []
        self.owasp_hits[owasp_id].append({"source": source, **finding})

    def _map_sca_to_owasp(self):
        for f in self.sca.get("findings", []):
            pkg   = f["package"].lower()
            sev   = f["severity"]
            rule  = next((CVE_RULES[k] for k in CVE_RULES if k in pkg), None)
            owasp = rule["owasp"] if rule else "A06"
            self._add_hit(owasp, "SCA", {
                "title":    f"Vulnerable: {f['package']} ({sev})",
                "detail":   rule["desc"] if rule else f"CVE in {f['package']}",
                "fix":      rule["fix"] if rule else f.get("fix","npm audit fix"),
                "severity": sev,
                "cves":     f.get("cves", []),
            })

    def _map_depcheck_to_owasp(self):
        for f in self.depcheck.get("findings", []):
            pkg   = f["package"].lower()
            sev   = f["severity"]
            cweid = str(f.get("cweid",""))
            owasp = CWE_TO_OWASP.get(cweid)
            if not owasp:
                rule  = next((CVE_RULES[k] for k in CVE_RULES if k in pkg), None)
                owasp = rule["owasp"] if rule else "A06"
            self._add_hit(owasp, "DepCheck", {
                "title":    f"Dependency CVE: {f['package']} ({sev})",
                "detail":   f.get("fix","")[:150],
                "fix":      f"Update {f['package']} — see NVD for patch version.",
                "severity": sev,
                "cves":     f.get("cves",[]),
            })

    def _map_zap_to_owasp(self):
        for f in self.zap.get("findings", []):
            name  = f["name"].lower()
            cweid = str(f.get("cweid",""))
            owasp = CWE_TO_OWASP.get(cweid)
            if not owasp:
                owasp = next((v for k,v in ZAP_NAME_TO_OWASP.items() if k in name), "A05")
            self._add_hit(owasp, "DAST", {
                "title":    f["name"],
                "detail":   f.get("desc","")[:150],
                "fix":      f.get("solution","Review and patch")[:150],
                "severity": f["risk"],
                "urls":     f.get("instances",[])[:3],
            })

    def _map_sonar_to_owasp(self):
        for issue in self.issues:
            rule  = issue.get("rule","")
            owasp = SONAR_RULE_OWASP.get(rule)
            if not owasp:
                # Fallback: check if rule ID contains a known CWE
                owasp = "A04"
            sev = issue.get("severity","MAJOR")
            self._add_hit(owasp, "SAST", {
                "title":    issue.get("message","Code issue")[:100],
                "detail":   f"File: {issue.get('component','').split(':')[-1]}  Line: {issue.get('line','')}",
                "fix":      "Fix flagged code pattern — see SonarQube for exact rule guidance.",
                "severity": sev,
            })

    def _map_perf_risks(self):
        p95      = self.perf.get("p95_rt", 0)
        err      = self.perf.get("errors", 0)
        samples  = max(self.perf.get("samples", 1), 1)
        err_rate = err / samples * 100
        if p95 > 3000:
            self._add_hit("A05","Perf",{
                "title":    f"High P95 latency: {p95}ms under load",
                "detail":   "Slow responses can indicate DoS vulnerability or resource exhaustion.",
                "fix":      "Profile slow endpoints; add rate limiting and response caching.",
                "severity": "HIGH",
            })
        if err_rate > 5:
            self._add_hit("A05","Perf",{
                "title":    f"High error rate under load: {err_rate:.1f}%",
                "detail":   "Errors above 5% suggest instability and potential DoS exposure.",
                "fix":      "Investigate error responses; enforce circuit-breaker patterns.",
                "severity": "MEDIUM",
            })

    # Combined critical/high counts from BOTH SCA and DepCheck
    def _sca_critical(self):
        return self.sca.get("critical",0) + self.depcheck.get("critical",0)
    def _sca_high(self):
        return self.sca.get("high",0) + self.depcheck.get("high",0)

    def score(self):
        s = 100
        s -= self._sca_critical() * 12
        s -= self._sca_high()     * 6
        s -= (self.sca.get("medium",0) + self.depcheck.get("medium",0)) * 2
        s -= self.sonar.get("critical",0) * 10
        s -= self.sonar.get("major",0)    * 3
        s -= self.zap.get("high",0)   * 15
        s -= self.zap.get("medium",0) * 5
        s -= self.zap.get("low",0)    * 1
        if self.perf.get("p95_rt",0) > 3000: s -= 5
        err = self.perf.get("errors",0)/max(self.perf.get("samples",1),1)*100
        if err > 5: s -= 5
        return max(0, min(100, s))

    def grade(self):
        sc = self.score()
        if sc >= 90: return "A","#10b981"
        if sc >= 75: return "B","#84cc16"
        if sc >= 55: return "C","#f59e0b"
        if sc >= 35: return "D","#f97316"
        return "F","#ef4444"

    def risk_level(self):
        sc = self.score()
        if sc >= 75: return "Low",     "#10b981"
        if sc >= 55: return "Medium",  "#f59e0b"
        if sc >= 35: return "High",    "#f97316"
        return "Critical","#ef4444"

    def build_decision(self):
        if self._sca_critical() > 0:           return "FAIL","Critical CVEs in dependencies"
        if self._sca_high() > 0:               return "FAIL","High-severity CVEs in dependencies"
        if self.zap.get("high",0) > 0:         return "FAIL","High-risk DAST alerts"
        if self.sonar.get("critical",0) > 0:   return "FAIL","Critical SAST findings"
        return "PASS","All thresholds met"

    def _build_remediations(self):
        seen, priority = set(), 1

        # SCA (npm audit) findings
        for f in self.sca.get("findings",[]):
            if f["severity"] in ("CRITICAL","HIGH") and f["package"] not in seen:
                seen.add(f["package"])
                rule = next((CVE_RULES[k] for k in CVE_RULES if k in f["package"].lower()), None)
                self.remediations.append({
                    "priority": priority, "tool":"SCA",
                    "owasp":    rule["owasp"] if rule else "A06",
                    "issue":    f"Vulnerable: {f['package']} ({f['severity']})",
                    "fix":      rule["fix"] if rule else f.get("fix","npm audit fix --force"),
                    "effort":"Low","impact":"Critical",
                })
                priority += 1

        # OWASP Dependency-Check findings
        for f in self.depcheck.get("findings",[]):
            if f["severity"] in ("CRITICAL","HIGH"):
                key = f"dc:{f['package']}"
                if key not in seen:
                    seen.add(key)
                    self.remediations.append({
                        "priority": priority, "tool":"DepCheck",
                        "owasp":    CWE_TO_OWASP.get(str(f.get("cweid","")),"A06"),
                        "issue":    f"DC CVE: {f['package']} ({f['severity']})",
                        "fix":      f"Update {f['package']}. CVEs: {', '.join(f.get('cves',[])[:2])}",
                        "effort":"Low","impact":"Critical",
                    })
                    priority += 1

        # ZAP findings
        for f in self.zap.get("findings",[]):
            if f["risk"] == "High" and f["name"] not in seen:
                seen.add(f["name"])
                self.remediations.append({
                    "priority": priority, "tool":"DAST",
                    "owasp":    CWE_TO_OWASP.get(str(f.get("cweid","")),"A05"),
                    "issue":    f["name"],
                    "fix":      f.get("solution","Review ZAP report for fix details.")[:200],
                    "effort":"Medium","impact":"High",
                })
                priority += 1

        # Sonar findings
        for issue in self.issues[:5]:
            msg = issue.get("message","")[:60]
            if msg not in seen:
                seen.add(msg)
                self.remediations.append({
                    "priority": priority, "tool":"SAST",
                    "owasp":    SONAR_RULE_OWASP.get(issue.get("rule",""),"A04"),
                    "issue":    msg,
                    "fix":      "Review SonarQube rule definition and apply recommended code fix.",
                    "effort":"Medium","impact":issue.get("severity","MAJOR"),
                })
                priority += 1

    def executive_summary(self):
        grade, _      = self.grade()
        risk,  _      = self.risk_level()
        decision, reason = self.build_decision()
        total_vulns = (
            self._sca_critical() +
            self.zap.get("high",0) +
            self.sonar.get("critical",0)
        )
        parts = []
        if total_vulns == 0:
            parts.append(
                f"Security posture is strong with a Grade {grade}. "
                f"No critical/high-severity findings detected across SAST, SCA, DepCheck, and DAST stages."
            )
        else:
            parts.append(
                f"Pipeline analysis detected {total_vulns} critical/high-severity finding(s), "
                f"resulting in Grade {grade} ({risk} risk). Build decision: {decision} — {reason}."
            )

        owasp_affected = [
            f"{k}: {OWASP_TOP10[k]['name']}"
            for k in sorted(self.owasp_hits.keys()) if k in OWASP_TOP10
        ]
        if owasp_affected:
            parts.append(f"OWASP Top 10 categories affected: {', '.join(owasp_affected[:4])}.")

        sca_crit = self._sca_critical()
        if sca_crit > 0:
            parts.append(
                f"Combined SCA (npm audit + Dependency-Check) found {sca_crit} critical CVE(s) "
                f"in third-party dependencies — immediate patching required before deployment."
            )
        if self.zap.get("high",0) > 0:
            parts.append(
                f"DAST (ZAP) identified {self.zap['high']} high-risk alert(s) in the running application, "
                f"confirming exploitable vulnerabilities under live conditions."
            )

        p95 = self.perf.get("p95_rt",0)
        parts.append(
            f"Performance testing recorded P95 latency of {p95}ms — "
            f"{'within acceptable limits' if p95 <= 2000 else 'exceeds 2s threshold, indicating instability risk'}."
        )
        return " ".join(parts)

    def compliance_notes(self):
        notes = []
        if self.zap.get("findings"):
            high_names = [f["name"].lower() for f in self.zap["findings"] if f["risk"]=="High"]
            all_names  = [f["name"].lower() for f in self.zap["findings"]]
            if any("sql" in n for n in high_names):
                notes.append("OWASP A03 (Injection) — SQL injection confirmed via DAST; PCI-DSS Req 6.3 applies.")
            if any("xss" in n or "cross site" in n for n in high_names):
                notes.append("OWASP A03 (Injection) — XSS confirmed; GDPR data exposure risk.")
            if any("csp" in n or "content security" in n for n in all_names):
                notes.append("OWASP A05 (Misconfiguration) — Missing CSP header; add Content-Security-Policy.")
            if any("cookie" in n or "session" in n for n in all_names):
                notes.append("OWASP A07 (Auth Failures) — Cookie/session misconfiguration detected.")
        if self._sca_critical() > 0:
            notes.append("OWASP A06 (Vulnerable Components) — Critical CVEs violate NIST SP 800-190 container guidance.")
        if self.sonar.get("critical",0) > 0:
            notes.append("OWASP A04 (Insecure Design) — Critical SAST findings indicate design-level security gaps.")
        if not notes:
            notes.append("No active compliance violations detected. Continue monitoring with each build.")
        return notes

    def ai_insights(self):
        insights = {}
        sca_total = self.sca.get("total",0) + self.depcheck.get("total",0)
        sca_crit  = self._sca_critical()
        sca_high  = self._sca_high()

        if sca_total > 0:
            insights["sca"] = (
                f"Combined SCA found {sca_total} vulnerabilities ({sca_crit} critical, {sca_high} high) "
                f"across npm audit and OWASP Dependency-Check. "
                f"{'Critical RCE-class CVEs detected — treat as P0 incident and patch immediately.' if sca_crit > 0 else 'No critical CVEs, but high-severity issues require sprint-level attention.'} "
                f"Run `npm audit fix` to auto-resolve fixable issues. "
                f"Pin vulnerable transitive dependencies using package.json overrides."
            )
        else:
            insights["sca"] = "No dependency vulnerabilities found. Maintain this by running `npm audit` on every PR and keeping OWASP Dependency-Check in the pipeline."

        if self.zap.get("total",0) > 0:
            insights["dast"] = (
                f"ZAP full scan produced {self.zap['total']} alerts "
                f"({self.zap['high']} high, {self.zap['medium']} medium). "
                f"High-risk findings represent confirmed exploitable paths in the live application. "
                f"Prioritise: SQL injection → parameterised queries; "
                f"XSS → output encoding + helmet.js; missing headers → helmet middleware."
            )
        else:
            insights["dast"] = "No active DAST alerts. Ensure ZAP ran against an authenticated session for full coverage."

        crit_sonar = self.sonar.get("critical",0)
        insights["sast"] = (
            f"SonarQube SAST identified {crit_sonar} critical and {self.sonar.get('major',0)} major issue(s). "
            f"{'Critical findings often indicate hardcoded secrets, injection vectors, or insecure crypto — review each before dismissing.' if crit_sonar > 0 else 'No critical SAST issues. Set coverage thresholds ≥80% to prevent regression.'} "
            f"Integrate SonarLint in your IDE for shift-left detection before commit."
        )

        p95      = self.perf.get("p95_rt",0)
        err      = self.perf.get("errors",0)
        samples  = max(self.perf.get("samples",1),1)
        err_rate = round(err/samples*100, 2)
        insights["perf"] = (
            f"Load test: {samples} requests, P95={p95}ms, error rate={err_rate}%. "
            f"{'Performance is acceptable.' if p95 <= 2000 and err_rate <= 5 else 'Latency or error rate exceeds safe thresholds — investigate before deploying under production load.'} "
            f"Consider express-rate-limit and Redis caching for endpoints with P95 > 1000ms."
        )
        return insights


# ─────────────────────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────────────────────
def sev_color(sev):
    s = str(sev).upper()
    if s in ("CRITICAL","BLOCKER"): return "#f87171"
    if s in ("HIGH",):              return "#fb923c"
    if s in ("MEDIUM","MODERATE","MAJOR"): return "#fbbf24"
    return "#94a3b8"

def risk_color(r):
    r = str(r).lower()
    if r == "high":   return "#f87171"
    if r == "medium": return "#fbbf24"
    if r == "low":    return "#34d399"
    return "#94a3b8"

def owasp_badge_html(owasp_id):
    info = OWASP_TOP10.get(owasp_id, {"name":"Unknown","color":"#475569"})
    c = info["color"]
    return f'<span class="owasp-badge" style="--bc:{c}">{owasp_id} {info["name"]}</span>'

def sev_chip(sev):
    c = sev_color(sev)
    icons = {"CRITICAL":"⬟","BLOCKER":"⬟","HIGH":"▲","MEDIUM":"◆",
             "MODERATE":"◆","MAJOR":"◆","LOW":"▼","MINOR":"▼"}
    icon = icons.get(str(sev).upper(),"◆")
    return f'<span class="sev-chip" style="--cc:{c}">{icon} {sev}</span>'

def make_table(headers, rows_html, empty_msg="No data available"):
    th = "".join(f'<th>{h}</th>' for h in headers)
    content = rows_html if rows_html else \
        f'<tr><td colspan="{len(headers)}" class="empty-cell">{empty_msg}</td></tr>'
    return f'<div class="table-wrap"><table><thead><tr>{th}</tr></thead><tbody>{content}</tbody></table></div>'

def td(content, cls=""):
    return f'<td class="{cls}">{content}</td>'


# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard generator
# ─────────────────────────────────────────────────────────────────────────────
def generate_dashboard():
    print("\n=== SHIVA AI v4.0 — Free Security Intelligence Engine ===")
    print("Loading scan reports...")

    sca           = parse_npm_audit()
    depcheck      = parse_dependency_check()
    zap           = parse_zap()
    perf          = parse_jmeter()
    sonar_summary = parse_sonar_summary()
    sonar_issues  = load_json("sonar-issues.json") or {"issues":[]}

    print(f"  npm audit : {sca['total']} vulns  ({sca['critical']} critical, {sca['high']} high)")
    print(f"  DepCheck  : {depcheck['total']} vulns  ({depcheck['critical']} critical, {depcheck['high']} high)")
    print(f"  DAST      : {zap['total']} alerts ({zap['high']} high)")
    print(f"  SAST      : {sonar_summary.get('critical',0)} critical, {sonar_summary.get('major',0)} major")
    print(f"  Perf      : {perf['samples']} samples, P95={perf['p95_rt']}ms")
    print("Running AI expert engine...")

    ai = SecurityAI(sca, depcheck, zap, perf, sonar_summary, sonar_issues)
    score             = ai.score()
    grade, gc         = ai.grade()
    risk,  rc         = ai.risk_level()
    decision, dreason = ai.build_decision()
    summary           = ai.executive_summary()
    insights          = ai.ai_insights()
    comp              = ai.compliance_notes()
    remeds            = ai.remediations[:10]
    now               = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    err_rate_val      = round(perf["errors"]/max(perf["samples"],1)*100, 1)
    owasp_hit_count   = len(ai.owasp_hits)

    print(f"  Score: {score}/100 | Grade: {grade} | Risk: {risk} | Build: {decision}")

    # Score ring
    R    = 54
    circ = 2 * 3.14159265 * R
    dash = circ * score / 100
    score_ring = f'''<svg class="score-ring" width="150" height="150" viewBox="0 0 150 150">
  <circle cx="75" cy="75" r="{R}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
  <circle cx="75" cy="75" r="{R}" fill="none" stroke="{gc}" stroke-width="10"
    stroke-dasharray="{dash:.2f} {circ:.2f}" stroke-linecap="round"
    transform="rotate(-90 75 75)" class="ring-arc"/>
  <text x="75" y="66" text-anchor="middle" fill="{gc}" font-size="30" font-weight="900"
    font-family="'Space Mono',monospace">{score}</text>
  <text x="75" y="82" text-anchor="middle" fill="rgba(255,255,255,0.4)" font-size="10"
    font-family="'Syne',sans-serif">out of 100</text>
  <text x="75" y="104" text-anchor="middle" fill="{gc}" font-size="16" font-weight="800"
    font-family="'Space Mono',monospace">Grade {grade}</text>
</svg>'''

    # OWASP cards
    owasp_cards_html = ""
    for oid, info in OWASP_TOP10.items():
        hits = ai.owasp_hits.get(oid, [])
        cnt  = len(hits)
        col  = info["color"] if cnt > 0 else "rgba(255,255,255,0.1)"
        hit_items = ""
        for h in hits[:3]:
            sc = sev_color(h.get("severity","LOW"))
            hit_items += f'''<div class="owasp-hit">
  <span class="hit-dot" style="background:{sc}"></span>
  <span><em>[{h["source"]}]</em> {h["title"][:60]}</span>
</div>'''
        remaining = cnt - 3
        more  = f'<div class="more-badge">+{remaining} more findings</div>' if remaining > 0 else ""
        empty = '<div class="no-findings">✓ No findings</div>' if not hit_items else ""
        owasp_cards_html += f'''<div class="owasp-card {'owasp-hit-card' if cnt>0 else ''}" style="--oc:{col}">
  <div class="owasp-card-header">
    <span class="owasp-id">{oid}</span>
    <span class="owasp-count {'hit-count' if cnt>0 else ''}">{cnt} hit{'s' if cnt!=1 else ''}</span>
  </div>
  <div class="owasp-name">{info["name"]}</div>
  <div class="owasp-findings">{hit_items}{more}{empty}</div>
</div>'''

    # Remediation rows — include DepCheck tool badge
    tool_cls = {"SCA":"tool-sca","DAST":"tool-dast","SAST":"tool-sast",
                "Perf":"tool-perf","DepCheck":"tool-depcheck"}
    remed_rows = ""
    for r in remeds:
        tc = tool_cls.get(r["tool"],"tool-sca")
        remed_rows += f'''<tr>
  {td(f'<span class="prio-badge">#{r["priority"]}</span>')}
  {td(f'<span class="tool-badge {tc}">{r["tool"]}</span>')}
  {td(owasp_badge_html(r.get("owasp","A04")))}
  {td(f'<span class="finding-text">{r["issue"][:70]}</span>')}
  {td(f'<span class="fix-text">{r["fix"][:140]}</span>')}
  {td(sev_chip(r["impact"]))}
</tr>'''

    # SCA rows (npm audit)
    sca_rows = ""
    for f in sca.get("findings",[])[:20]:
        pkg  = f["package"]
        rule = next((CVE_RULES[k] for k in CVE_RULES if k in pkg.lower()), None)
        cves = ", ".join(f.get("cves",[])) or "—"
        sca_rows += f'''<tr>
  {td(f'<code class="pkg-name">{pkg}</code>')}
  {td(sev_chip(f["severity"]))}
  {td(f'<code class="cve-text">{cves[:50]}</code>')}
  {td(owasp_badge_html(rule["owasp"] if rule else "A06"))}
  {td(f'<span class="fix-text">{str(f.get("fix","Manual update"))[:100]}</span>')}
</tr>'''

    # DepCheck rows
    dc_rows = ""
    for f in depcheck.get("findings",[])[:20]:
        cves = ", ".join(f.get("cves",[])) or "—"
        cweid = str(f.get("cweid",""))
        owasp_id = CWE_TO_OWASP.get(cweid,"A06")
        dc_rows += f'''<tr>
  {td(f'<code class="pkg-name">{f["package"]}</code>')}
  {td(sev_chip(f["severity"]))}
  {td(f'<code class="cve-text">{cves[:50]}</code>')}
  {td(f'<code class="cwe-text">CWE-{cweid}</code>' if cweid else '<span class="dim-text">—</span>')}
  {td(owasp_badge_html(owasp_id))}
</tr>'''

    # ZAP rows
    zap_rows = ""
    for f in zap.get("findings",[])[:20]:
        cw   = f.get("cweid","")
        ow_id = CWE_TO_OWASP.get(str(cw),
            next((v for k,v in ZAP_NAME_TO_OWASP.items() if k in f["name"].lower()), "A05"))
        urls_html = "".join(f'<div class="url-item">{u[:70]}</div>' for u in f.get("instances",[])[:2])
        zap_rows += f'''<tr>
  {td(f'<strong class="alert-name">{f["name"]}</strong>')}
  {td(sev_chip(f["risk"]))}
  {td(f'<code class="cwe-text">CWE-{cw}</code>')}
  {td(owasp_badge_html(ow_id))}
  {td(f'<span class="fix-text">{f.get("solution","")[:120]}</span>')}
  {td(urls_html or '<span class="dim-text">—</span>')}
</tr>'''

    # Sonar rows
    sonar_rows = ""
    for iss in sonar_issues.get("issues",[])[:20]:
        rule = iss.get("rule","")
        comp = iss.get("component","").split(":")[-1]
        sonar_rows += f'''<tr>
  {td(f'<span class="finding-text">{iss.get("message","")[:85]}</span>')}
  {td(sev_chip(iss.get("severity","MAJOR")))}
  {td(f'<code class="pkg-name">{comp[:40]}</code>')}
  {td(f'<code class="cwe-text">{rule}</code>')}
  {td(owasp_badge_html(SONAR_RULE_OWASP.get(rule,"A04")))}
</tr>'''

    # Perf rows
    perf_rows = ""
    for label, ep in perf.get("endpoints",{}).items():
        p95_col = "#f87171" if ep["p95"]>3000 else "#fbbf24" if ep["p95"]>1500 else "#34d399"
        err_col = "#f87171" if ep["error_rate"]>5 else "#34d399"
        pct     = min(100, int(ep["p95"]/30))
        perf_rows += f'''<tr>
  {td(f'<code class="pkg-name">{label}</code>')}
  {td(f'<span class="dim-text">{ep["count"]}</span>')}
  {td(f'<span class="dim-text">{round(ep["avg"])}ms</span>')}
  {td(f'''<div class="perf-bar-wrap">
    <span style="color:{p95_col};font-weight:700;min-width:60px;font-family:\'Space Mono\',monospace">{ep["p95"]}ms</span>
    <div class="perf-bar"><div class="perf-fill" style="width:{pct}%;background:{p95_col}"></div></div>
  </div>''')}
  {td(f'<span style="color:{err_col};font-weight:700;font-family:\'Space Mono\',monospace">{ep["error_rate"]}%</span>')}
  {td(f'<span class="dim-text">{ep["errors"]}</span>')}
</tr>'''

    # Compliance
    comp_html = "".join(
        f'<div class="compliance-item"><span class="comp-icon">⚠</span><span>{note}</span></div>'
        for note in comp
    ) or '<div class="compliance-item no-comp"><span class="comp-icon ok">✓</span><span>No active compliance violations detected.</span></div>'

    d_class = "pass" if decision == "PASS" else "fail"
    d_icon  = "✓" if decision == "PASS" else "✗"

    # Totals for dist bar
    combined_critical = sca["critical"] + depcheck.get("critical",0) + sonar_summary.get("critical",0)
    combined_high     = sca["high"] + depcheck.get("high",0) + zap["high"]
    combined_medium   = sca["medium"] + depcheck.get("medium",0) + zap["medium"]
    combined_low      = sca["low"] + depcheck.get("low",0) + zap["low"]

    # ─── CSS ──────────────────────────────────────────────────────────────────
    css = """
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#050811;--bg1:#080d18;--bg2:#0c1222;--bg3:#111827;--bg4:#162032;
  --border:#1e2d47;--border2:#2a3f5f;--text:#e2eaf6;--muted:#64748b;--dim:#334155;
  --cyan:#22d3ee;--cyan2:#06b6d4;--purple:#a78bfa;--green:#34d399;
  --amber:#fbbf24;--orange:#fb923c;--red:#f87171;
  --font-display:'Syne',sans-serif;
  --font-mono:'Space Mono','JetBrains Mono',monospace;
  --glow-cyan:0 0 20px rgba(34,211,238,.15),0 0 40px rgba(34,211,238,.08);
}
html{scroll-behavior:smooth}
body{background:var(--bg0);color:var(--text);font-family:var(--font-display);
     min-height:100vh;line-height:1.6;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(34,211,238,.015) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(34,211,238,.015) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0}

/* TOPBAR */
.topbar{position:sticky;top:0;z-index:100;background:rgba(5,8,17,.92);
  backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:0 32px;
  display:flex;align-items:center;justify-content:space-between;
  min-height:68px;flex-wrap:wrap;gap:12px}
.topbar-left{display:flex;align-items:center;gap:16px;padding:14px 0}
.logo-box{width:42px;height:42px;border-radius:12px;
  background:linear-gradient(135deg,rgba(34,211,238,.2),rgba(167,139,250,.1));
  border:1px solid rgba(34,211,238,.3);display:flex;align-items:center;
  justify-content:center;font-size:22px;box-shadow:var(--glow-cyan)}
.logo-title{font-size:1.1rem;font-weight:800;letter-spacing:-.02em;color:var(--text)}
.logo-title span{font-size:.65rem;font-weight:500;color:var(--muted);
  letter-spacing:.1em;text-transform:uppercase;margin-left:8px}
.logo-meta{font-size:.72rem;color:var(--dim);margin-top:2px;font-family:var(--font-mono)}
.logo-meta a{color:var(--cyan);text-decoration:none}
.logo-meta a:hover{text-decoration:underline}
.topbar-right{display:flex;align-items:center;gap:10px;padding:14px 0;flex-wrap:wrap}
.status-pill{background:rgba(255,255,255,.03);border:1px solid var(--border);
  border-radius:12px;padding:10px 18px;text-align:center;transition:border-color .2s}
.status-pill:hover{border-color:var(--border2)}
.status-pill .sp-label{font-size:.6rem;text-transform:uppercase;letter-spacing:.12em;
  color:var(--dim);margin-bottom:3px}
.status-pill .sp-value{font-size:1.05rem;font-weight:900;font-family:var(--font-mono)}
.status-pill.pass{border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.05)}
.status-pill.fail{border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.05)}

/* LAYOUT */
.layout{display:flex;min-height:calc(100vh - 68px);position:relative;z-index:1}

/* SIDEBAR */
.sidebar{width:240px;flex-shrink:0;background:rgba(8,13,24,.8);
  border-right:1px solid var(--border);padding:28px 14px;
  display:flex;flex-direction:column;gap:2px;
  position:sticky;top:68px;height:calc(100vh - 68px);overflow-y:auto}
.nav-label{font-size:.6rem;text-transform:uppercase;letter-spacing:.14em;
  color:var(--dim);padding:0 10px;margin-bottom:10px}
.nav-link{display:flex;align-items:center;gap:10px;color:var(--muted);
  text-decoration:none;padding:10px 12px;border-radius:10px;
  font-size:.85rem;font-weight:600;border:1px solid transparent;
  transition:all .18s;margin-bottom:2px}
.nav-link:hover{color:var(--text);background:rgba(34,211,238,.06);
  border-color:rgba(34,211,238,.15)}
.nav-link .nav-icon{font-size:13px;width:18px;text-align:center}
.sidebar-score{margin-top:auto;padding-top:24px;border-top:1px solid var(--border);text-align:center}
.sidebar-score-label{font-size:.6rem;text-transform:uppercase;letter-spacing:.12em;
  color:var(--dim);margin-bottom:12px}
.ring-arc{transition:stroke-dasharray 1s ease}
.sidebar-footer{text-align:center;padding:16px 6px 0;border-top:1px solid var(--border);
  font-size:.66rem;color:var(--dim);line-height:2;font-family:var(--font-mono)}

/* MAIN */
.main{flex:1;padding:40px 48px;overflow-x:hidden;max-width:1300px}
.section-header{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.section-bar{width:3px;height:30px;border-radius:2px}
.section-title{font-size:1.15rem;font-weight:800;color:var(--text);letter-spacing:-.02em}
.section{margin-bottom:60px;scroll-margin-top:28px}

/* STAT GRID */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));
  gap:14px;margin-bottom:16px}
.stat-card{background:var(--bg3);border:1px solid var(--border);border-radius:16px;
  padding:20px;border-top:2px solid var(--border);
  transition:transform .2s,border-color .2s;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--c,var(--cyan)),transparent);opacity:.5}
.stat-card:hover{transform:translateY(-2px)}
.stat-label{font-size:.63rem;text-transform:uppercase;letter-spacing:.12em;
  color:var(--muted);margin-bottom:10px;display:flex;align-items:center;justify-content:space-between}
.stat-value{font-size:2.1rem;font-weight:900;line-height:1;font-family:var(--font-mono)}
.stat-sub{font-size:.68rem;color:var(--dim);margin-top:6px}

/* DIST BAR */
.dist-card{background:var(--bg3);border:1px solid var(--border);border-radius:16px;padding:24px}
.dist-label-row{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:20px}
.dist-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:18px}
.dist-item-label{display:flex;justify-content:space-between;font-size:.8rem;margin-bottom:6px}
.dist-bar-track{background:var(--bg0);border-radius:4px;height:7px;overflow:hidden;border:1px solid var(--border)}
.dist-bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}

/* AI ANALYSIS */
.summary-card{background:var(--bg3);border:1px solid var(--border);border-radius:18px;padding:28px;margin-bottom:18px}
.summary-header{display:flex;align-items:center;gap:10px;margin-bottom:18px;flex-wrap:wrap}
.summary-title{font-weight:800;font-size:.95rem;color:var(--text)}
.summary-risk-badge{margin-left:auto;padding:4px 14px;border-radius:20px;
  font-size:.72rem;font-weight:700;border:1px solid}
.summary-body{font-size:.88rem;line-height:1.9;color:var(--muted);
  background:var(--bg4);padding:20px 22px;border-radius:12px;border-left:3px solid var(--cyan)}
.insight-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:16px}
.insight-card{background:var(--bg3);border:1px solid var(--border);border-radius:16px;
  padding:22px;border-left:3px solid var(--border);transition:transform .2s}
.insight-card:hover{transform:translateY(-2px)}
.insight-header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.insight-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.insight-title{font-weight:700;font-size:.9rem}
.insight-body{font-size:.83rem;line-height:1.8;color:var(--muted)}
.glow-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* OWASP GRID */
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(235px,1fr));gap:14px}
.owasp-card{background:var(--bg3);border:1px solid var(--border);border-radius:14px;
  padding:18px;border-top:3px solid var(--oc);transition:transform .2s,box-shadow .2s}
.owasp-hit-card{box-shadow:0 0 0 1px var(--oc,transparent)}
.owasp-card:hover{transform:translateY(-2px)}
.owasp-card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.owasp-id{font-size:.75rem;font-weight:800;letter-spacing:.06em;color:var(--oc);font-family:var(--font-mono)}
.owasp-count{font-size:.68rem;font-weight:700;padding:2px 9px;border-radius:20px;
  background:rgba(255,255,255,.05);color:var(--muted);border:1px solid var(--border)}
.owasp-count.hit-count{background:color-mix(in srgb,var(--oc) 15%,transparent);
  color:var(--oc);border-color:color-mix(in srgb,var(--oc) 35%,transparent)}
.owasp-name{font-size:.78rem;color:var(--muted);margin-bottom:12px;font-weight:500}
.owasp-hit{display:flex;align-items:flex-start;gap:8px;padding:7px 0;
  border-bottom:1px solid var(--border);font-size:.74rem;color:var(--text);line-height:1.5}
.owasp-hit:last-child{border-bottom:none}
.owasp-hit em{color:var(--muted);font-style:normal;text-transform:uppercase;
  font-size:.64rem;letter-spacing:.06em;margin-right:3px}
.hit-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;margin-top:5px}
.no-findings{font-size:.75rem;color:var(--dim);padding:6px 0}
.more-badge{font-size:.7rem;color:var(--muted);text-align:right;padding-top:6px}

/* TABLES */
.table-wrap{background:var(--bg3);border:1px solid var(--border);
  border-radius:18px;overflow:hidden;overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:600px}
thead{background:var(--bg0)}
th{padding:13px 16px;text-align:left;font-size:.68rem;text-transform:uppercase;
  letter-spacing:.1em;font-weight:700;color:var(--muted);white-space:nowrap;
  border-bottom:1px solid var(--border)}
td{padding:13px 16px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:nth-child(even){background:rgba(255,255,255,.015)}
tr:hover{background:rgba(34,211,238,.03)}
.empty-cell{text-align:center;color:var(--dim);font-size:.85rem;padding:28px}

/* BADGES & CHIPS */
.owasp-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;
  border-radius:20px;font-size:.68rem;font-weight:700;letter-spacing:.04em;
  background:color-mix(in srgb,var(--bc) 12%,transparent);color:var(--bc);
  border:1px solid color-mix(in srgb,var(--bc) 30%,transparent);white-space:nowrap}
.sev-chip{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;
  border-radius:20px;font-size:.7rem;font-weight:800;
  background:color-mix(in srgb,var(--cc) 12%,transparent);color:var(--cc);
  border:1px solid color-mix(in srgb,var(--cc) 30%,transparent);font-family:var(--font-mono)}
.prio-badge{display:inline-flex;align-items:center;justify-content:center;
  width:26px;height:26px;border-radius:50%;background:var(--bg4);
  border:1px solid var(--border2);color:var(--cyan);font-size:.72rem;font-weight:800;
  font-family:var(--font-mono)}
.tool-badge{display:inline-block;padding:3px 10px;border-radius:7px;
  font-size:.7rem;font-weight:800;letter-spacing:.04em;font-family:var(--font-mono)}
.tool-sca     {background:rgba(251,146,60,.15);color:#fb923c;border:1px solid rgba(251,146,60,.3)}
.tool-dast    {background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.3)}
.tool-sast    {background:rgba(167,139,250,.15);color:#a78bfa;border:1px solid rgba(167,139,250,.3)}
.tool-perf    {background:rgba(34,211,238,.15);color:#22d3ee;border:1px solid rgba(34,211,238,.3)}
.tool-depcheck{background:rgba(52,211,153,.15);color:#34d399;border:1px solid rgba(52,211,153,.3)}

/* TEXT TYPES */
.pkg-name    {font-family:var(--font-mono);font-size:.83rem;color:var(--cyan)}
.cve-text    {font-family:var(--font-mono);font-size:.76rem;color:var(--muted)}
.cwe-text    {font-family:var(--font-mono);font-size:.73rem;color:var(--dim)}
.fix-text    {font-size:.82rem;color:var(--muted);line-height:1.55}
.finding-text{font-size:.85rem;color:var(--text)}
.alert-name  {font-size:.85rem;color:var(--text);font-weight:700}
.dim-text    {color:var(--dim);font-size:.82rem}
.url-item    {font-size:.72rem;color:var(--cyan);word-break:break-all;padding:1px 0}

/* MINI STATS */
.mini-stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.mini-stat{background:var(--bg3);border:1px solid var(--border);border-radius:10px;
  padding:10px 16px;display:flex;align-items:center;gap:10px;font-size:.8rem;color:var(--muted)}
.mini-stat strong{font-family:var(--font-mono);font-size:.85rem}

/* PERF */
.perf-stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:18px}
.perf-stat{background:var(--bg4);border:1px solid var(--border);border-radius:13px;padding:18px}
.perf-stat-label{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:8px}
.perf-stat-value{font-size:1.6rem;font-weight:900;font-family:var(--font-mono)}
.perf-bar-wrap{display:flex;align-items:center;gap:10px}
.perf-bar{flex:1;min-width:60px;height:7px;background:var(--bg0);border-radius:4px;overflow:hidden;border:1px solid var(--border)}
.perf-fill{height:100%;border-radius:4px}

/* COMPLIANCE */
.compliance-card{background:var(--bg3);border:1px solid var(--border);border-radius:18px;padding:28px}
.comp-tags{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.comp-tag{background:rgba(251,191,36,.1);color:var(--amber);
  border:1px solid rgba(251,191,36,.3);padding:3px 12px;border-radius:20px;font-size:.7rem;font-weight:700}
.compliance-item{display:flex;align-items:flex-start;gap:14px;padding:14px 18px;
  background:var(--bg4);border-radius:10px;border-left:3px solid var(--amber);
  margin-bottom:10px;font-size:.87rem;color:var(--text);line-height:1.65}
.compliance-item.no-comp{border-left-color:var(--green)}
.comp-icon{color:var(--amber);font-size:15px;flex-shrink:0;margin-top:1px}
.comp-icon.ok{color:var(--green)}

/* FOOTER */
.footer{text-align:center;padding:32px 0;border-top:1px solid var(--border);
  font-size:.7rem;color:var(--dim);line-height:2.2;font-family:var(--font-mono)}

/* ANIMATIONS */
@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.section{animation:fadeUp .5s ease both}
.stat-card{animation:fadeUp .4s ease both}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.live-dot{animation:pulse 2s infinite}
"""

    # ─── HTML ─────────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SHIVA AI &bull; Build #{BUILD_NUMBER}</title>
<style>{css}</style>
</head>
<body>

<header class="topbar">
  <div class="topbar-left">
    <div class="logo-box">🛡️</div>
    <div>
      <div class="logo-title">SHIVA AI <span>Security Intelligence v4.0</span></div>
      <div class="logo-meta">
        {JOB_NAME} &bull; Build #{BUILD_NUMBER} &bull; {now} &bull;
        <a href="{BUILD_URL}">Jenkins ↗</a>
      </div>
    </div>
  </div>
  <div class="topbar-right">
    <div class="status-pill {d_class}">
      <div class="sp-label">Build</div>
      <div class="sp-value" style="color:{'var(--green)' if decision=='PASS' else 'var(--red)'}">{d_icon} {decision}</div>
    </div>
    <div class="status-pill">
      <div class="sp-label">Risk</div>
      <div class="sp-value" style="color:{rc}">{risk}</div>
    </div>
    <div class="status-pill">
      <div class="sp-label">Grade</div>
      <div class="sp-value" style="color:{gc}">{grade} <small style="font-size:.7rem;color:var(--muted)">({score}/100)</small></div>
    </div>
    <div class="status-pill">
      <div class="sp-label">OWASP Hits</div>
      <div class="sp-value" style="color:var(--amber)">{owasp_hit_count}/10</div>
    </div>
  </div>
</header>

<div class="layout">
  <nav class="sidebar">
    <div class="nav-label">Navigation</div>
    <a class="nav-link" href="#overview"><span class="nav-icon">◈</span>Overview</a>
    <a class="nav-link" href="#ai-analysis"><span class="nav-icon">◎</span>AI Analysis</a>
    <a class="nav-link" href="#owasp"><span class="nav-icon">⬡</span>OWASP Top 10</a>
    <a class="nav-link" href="#remediations"><span class="nav-icon">⬢</span>Remediations</a>
    <a class="nav-link" href="#sast"><span class="nav-icon">◉</span>SAST — Sonar</a>
    <a class="nav-link" href="#sca"><span class="nav-icon">◈</span>SCA — npm audit</a>
    <a class="nav-link" href="#depcheck"><span class="nav-icon">◈</span>SCA — DepCheck</a>
    <a class="nav-link" href="#dast"><span class="nav-icon">◎</span>DAST — ZAP</a>
    <a class="nav-link" href="#perf"><span class="nav-icon">⚡</span>Performance</a>
    <a class="nav-link" href="#compliance"><span class="nav-icon">⬢</span>Compliance</a>
    <div class="sidebar-score">
      <div class="sidebar-score-label">Security Score</div>
      {score_ring}
    </div>
    <div class="sidebar-footer">
      Free AI Engine v4.0<br>
      OWASP Top 10 (2021)<br>
      npm+DepCheck+ZAP+Sonar
    </div>
  </nav>

  <main class="main">

    <!-- OVERVIEW -->
    <section id="overview" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--cyan);box-shadow:0 0 10px rgba(34,211,238,.5)"></div>
        <span class="section-title">◈ Executive Overview</span>
      </div>
      <div class="stat-grid">
        <div class="stat-card" style="--c:{'var(--red)' if sonar_summary.get('critical',0)>0 else 'var(--green)'}">
          <div class="stat-label">SAST Criticals <span style="color:{'var(--red)' if sonar_summary.get('critical',0)>0 else 'var(--green)'}">{'▲' if sonar_summary.get('critical',0)>0 else '✓'}</span></div>
          <div class="stat-value" style="color:{'var(--red)' if sonar_summary.get('critical',0)>0 else 'var(--green)'}">{sonar_summary.get("critical",0)}</div>
          <div class="stat-sub">Gate = 0</div>
        </div>
        <div class="stat-card" style="--c:{'var(--red)' if ai._sca_critical()>0 else 'var(--green)'}">
          <div class="stat-label">SCA Critical <span style="color:{'var(--red)' if ai._sca_critical()>0 else 'var(--green)'}">{'▲' if ai._sca_critical()>0 else '✓'}</span></div>
          <div class="stat-value" style="color:{'var(--red)' if ai._sca_critical()>0 else 'var(--green)'}">{ai._sca_critical()}</div>
          <div class="stat-sub">{sca['total']+depcheck.get('total',0)} total (npm+DC)</div>
        </div>
        <div class="stat-card" style="--c:{'var(--orange)' if ai._sca_high()>0 else 'var(--green)'}">
          <div class="stat-label">SCA High <span style="color:{'var(--orange)' if ai._sca_high()>0 else 'var(--green)'}">{'▲' if ai._sca_high()>0 else '✓'}</span></div>
          <div class="stat-value" style="color:{'var(--orange)' if ai._sca_high()>0 else 'var(--green)'}">{ai._sca_high()}</div>
          <div class="stat-sub">{sca.get('medium',0)+depcheck.get('medium',0)} medium</div>
        </div>
        <div class="stat-card" style="--c:{'var(--red)' if zap['high']>0 else 'var(--green)'}">
          <div class="stat-label">DAST High <span style="color:{'var(--red)' if zap['high']>0 else 'var(--green)'}">{'▲' if zap['high']>0 else '✓'}</span></div>
          <div class="stat-value" style="color:{'var(--red)' if zap['high']>0 else 'var(--green)'}">{zap["high"]}</div>
          <div class="stat-sub">{zap["total"]} total alerts</div>
        </div>
        <div class="stat-card" style="--c:{'var(--red)' if perf['p95_rt']>2000 else 'var(--green)'}">
          <div class="stat-label">P95 Latency <span style="color:{'var(--red)' if perf['p95_rt']>2000 else 'var(--green)'}">{'▲' if perf['p95_rt']>2000 else '✓'}</span></div>
          <div class="stat-value" style="color:{'var(--red)' if perf['p95_rt']>2000 else 'var(--green)'};">{perf["p95_rt"]}ms</div>
          <div class="stat-sub">Gate ≤ 2000ms</div>
        </div>
        <div class="stat-card" style="--c:{'var(--red)' if err_rate_val>5 else 'var(--green)'}">
          <div class="stat-label">Error Rate <span style="color:{'var(--red)' if err_rate_val>5 else 'var(--green)'}">{'▲' if err_rate_val>5 else '✓'}</span></div>
          <div class="stat-value" style="color:{'var(--red)' if err_rate_val>5 else 'var(--green)'}">{err_rate_val}%</div>
          <div class="stat-sub">Gate ≤ 5%</div>
        </div>
      </div>
      <div class="dist-card">
        <div class="dist-label-row">Severity distribution across all tools (npm audit + DepCheck + ZAP + Sonar)</div>
        <div class="dist-grid">
          <div>
            <div class="dist-item-label">
              <span style="color:var(--red);font-weight:700">Critical</span>
              <span style="color:var(--text);font-family:var(--font-mono)">{combined_critical}</span>
            </div>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width:{min(100,combined_critical*8)}%;background:var(--red)"></div></div>
          </div>
          <div>
            <div class="dist-item-label">
              <span style="color:var(--orange);font-weight:700">High</span>
              <span style="color:var(--text);font-family:var(--font-mono)">{combined_high}</span>
            </div>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width:{min(100,combined_high*5)}%;background:var(--orange)"></div></div>
          </div>
          <div>
            <div class="dist-item-label">
              <span style="color:var(--amber);font-weight:700">Medium</span>
              <span style="color:var(--text);font-family:var(--font-mono)">{combined_medium}</span>
            </div>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width:{min(100,combined_medium*3)}%;background:var(--amber)"></div></div>
          </div>
          <div>
            <div class="dist-item-label">
              <span style="color:var(--green);font-weight:700">Low</span>
              <span style="color:var(--text);font-family:var(--font-mono)">{combined_low}</span>
            </div>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width:{min(100,combined_low*2)}%;background:var(--green)"></div></div>
          </div>
        </div>
      </div>
    </section>

    <!-- AI ANALYSIS -->
    <section id="ai-analysis" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--purple);box-shadow:0 0 10px rgba(167,139,250,.5)"></div>
        <span class="section-title">◎ AI Security Analysis — Expert Engine</span>
      </div>
      <div class="summary-card">
        <div class="summary-header">
          <span class="glow-dot live-dot" style="background:var(--cyan);box-shadow:0 0 8px var(--cyan)"></span>
          <span class="summary-title">Executive Summary</span>
          <span class="summary-risk-badge" style="color:{rc};border-color:{rc};background:color-mix(in srgb,{rc} 10%,transparent)">
            {risk} Risk &bull; {decision}
          </span>
        </div>
        <div class="summary-body">{summary}</div>
      </div>
      <div class="insight-grid">
        <div class="insight-card" style="border-left-color:var(--orange)">
          <div class="insight-header">
            <span class="insight-dot" style="background:var(--orange);box-shadow:0 0 8px var(--orange)"></span>
            <span class="insight-title" style="color:var(--orange)">📦 SCA Intelligence</span>
          </div>
          <div class="insight-body">{insights["sca"]}</div>
        </div>
        <div class="insight-card" style="border-left-color:var(--red)">
          <div class="insight-header">
            <span class="insight-dot" style="background:var(--red);box-shadow:0 0 8px var(--red)"></span>
            <span class="insight-title" style="color:var(--red)">🕷️ DAST Intelligence</span>
          </div>
          <div class="insight-body">{insights["dast"]}</div>
        </div>
        <div class="insight-card" style="border-left-color:var(--purple)">
          <div class="insight-header">
            <span class="insight-dot" style="background:var(--purple);box-shadow:0 0 8px var(--purple)"></span>
            <span class="insight-title" style="color:var(--purple)">🔍 SAST Intelligence</span>
          </div>
          <div class="insight-body">{insights["sast"]}</div>
        </div>
        <div class="insight-card" style="border-left-color:var(--cyan)">
          <div class="insight-header">
            <span class="insight-dot" style="background:var(--cyan);box-shadow:0 0 8px var(--cyan)"></span>
            <span class="insight-title" style="color:var(--cyan)">⚡ Perf Intelligence</span>
          </div>
          <div class="insight-body">{insights["perf"]}</div>
        </div>
      </div>
    </section>

    <!-- OWASP -->
    <section id="owasp" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--amber);box-shadow:0 0 10px rgba(251,191,36,.5)"></div>
        <span class="section-title">⬡ OWASP Top 10 (2021) Coverage Map</span>
      </div>
      <div class="owasp-grid">{owasp_cards_html}</div>
    </section>

    <!-- REMEDIATIONS -->
    <section id="remediations" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--green);box-shadow:0 0 10px rgba(52,211,153,.5)"></div>
        <span class="section-title">⬢ AI-Prioritised Remediation Plan</span>
      </div>
      {make_table(
        ["#","Tool","OWASP","Issue","Recommended Fix","Impact"],
        remed_rows,
        "No remediation items — excellent security posture!"
      )}
    </section>

    <!-- SAST -->
    <section id="sast" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--purple);box-shadow:0 0 10px rgba(167,139,250,.5)"></div>
        <span class="section-title">◉ SAST — SonarQube Findings</span>
      </div>
      <div class="mini-stats">
        <div class="mini-stat"><span class="glow-dot" style="background:var(--red)"></span>Critical/Blocker: <strong style="color:var(--red)">{sonar_summary.get("critical",0)}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--amber)"></span>Major: <strong style="color:var(--amber)">{sonar_summary.get("major",0)}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--cyan)"></span>Gate: <strong style="color:{'var(--green)' if sonar_summary.get('critical',0)==0 else 'var(--red)'}">{'OK' if sonar_summary.get('critical',0)==0 else 'FAILED'}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--muted)"></span>Issues shown: <strong style="color:var(--text)">{len(sonar_issues.get("issues",[]))}</strong></div>
      </div>
      {make_table(
        ["Message","Severity","File","Rule ID","OWASP"],
        sonar_rows,
        "No critical/major issues found — SonarQube gate passed"
      )}
    </section>

    <!-- SCA npm -->
    <section id="sca" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--orange);box-shadow:0 0 10px rgba(251,146,60,.5)"></div>
        <span class="section-title">◈ SCA — npm audit Results</span>
      </div>
      <div class="mini-stats">
        <div class="mini-stat"><span class="glow-dot" style="background:var(--red)"></span>Critical: <strong style="color:var(--red)">{sca["critical"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--orange)"></span>High: <strong style="color:var(--orange)">{sca["high"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--amber)"></span>Medium: <strong style="color:var(--amber)">{sca["medium"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--green)"></span>Low: <strong style="color:var(--green)">{sca["low"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--muted)"></span>Total: <strong style="color:var(--text)">{sca["total"]}</strong></div>
      </div>
      {make_table(
        ["Package","Severity","CVEs","OWASP","Fix"],
        sca_rows,
        "No npm audit vulnerabilities found"
      )}
    </section>

    <!-- DepCheck -->
    <section id="depcheck" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--green);box-shadow:0 0 10px rgba(52,211,153,.5)"></div>
        <span class="section-title">◈ SCA — OWASP Dependency-Check Results</span>
      </div>
      <div class="mini-stats">
        <div class="mini-stat"><span class="glow-dot" style="background:var(--red)"></span>Critical: <strong style="color:var(--red)">{depcheck["critical"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--orange)"></span>High: <strong style="color:var(--orange)">{depcheck["high"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--amber)"></span>Medium: <strong style="color:var(--amber)">{depcheck["medium"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--muted)"></span>Total: <strong style="color:var(--text)">{depcheck["total"]}</strong></div>
      </div>
      {make_table(
        ["File / Package","Severity","CVE(s)","CWE","OWASP"],
        dc_rows,
        "dependency-check-report.json not found — run OWASP Dependency-Check stage to populate"
      )}
    </section>

    <!-- DAST -->
    <section id="dast" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--red);box-shadow:0 0 10px rgba(248,113,113,.5)"></div>
        <span class="section-title">◎ DAST — OWASP ZAP Active Scan Results</span>
      </div>
      <div class="mini-stats">
        <div class="mini-stat"><span class="glow-dot" style="background:var(--red)"></span>High: <strong style="color:var(--red)">{zap["high"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--amber)"></span>Medium: <strong style="color:var(--amber)">{zap["medium"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--green)"></span>Low: <strong style="color:var(--green)">{zap["low"]}</strong></div>
        <div class="mini-stat"><span class="glow-dot" style="background:var(--muted)"></span>Total: <strong style="color:var(--text)">{zap["total"]}</strong></div>
      </div>
      {make_table(
        ["Alert","Risk","CWE","OWASP","Remediation","Affected URLs"],
        zap_rows,
        "No ZAP alerts found"
      )}
    </section>

    <!-- PERFORMANCE -->
    <section id="perf" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--cyan);box-shadow:0 0 10px rgba(34,211,238,.5)"></div>
        <span class="section-title">⚡ Performance — JMeter Load Test Results</span>
      </div>
      <div class="perf-stat-grid">
        <div class="perf-stat"><div class="perf-stat-label">Samples</div><div class="perf-stat-value" style="color:var(--text)">{perf["samples"]}</div></div>
        <div class="perf-stat"><div class="perf-stat-label">Avg RT</div><div class="perf-stat-value" style="color:var(--text)">{round(perf["avg_rt"])}ms</div></div>
        <div class="perf-stat" style="border-top:2px solid {'var(--red)' if perf['p95_rt']>2000 else 'var(--green)'}">
          <div class="perf-stat-label">P95</div>
          <div class="perf-stat-value" style="color:{'var(--red)' if perf['p95_rt']>2000 else 'var(--green)'}">{perf["p95_rt"]}ms</div>
        </div>
        <div class="perf-stat"><div class="perf-stat-label">P99</div><div class="perf-stat-value" style="color:var(--text)">{perf["p99_rt"]}ms</div></div>
        <div class="perf-stat"><div class="perf-stat-label">Throughput</div><div class="perf-stat-value" style="color:var(--cyan)">{perf["throughput"]}/s</div></div>
        <div class="perf-stat" style="border-top:2px solid {'var(--red)' if perf['errors']>0 else 'var(--green)'}">
          <div class="perf-stat-label">Errors</div>
          <div class="perf-stat-value" style="color:{'var(--red)' if perf['errors']>0 else 'var(--green)'}">{perf["errors"]}</div>
        </div>
      </div>
      {make_table(
        ["Endpoint","Samples","Avg RT","P95 + Bar","Error %","Errors"],
        perf_rows,
        "No JMeter data available"
      )}
    </section>

    <!-- COMPLIANCE -->
    <section id="compliance" class="section">
      <div class="section-header">
        <div class="section-bar" style="background:var(--amber);box-shadow:0 0 10px rgba(251,191,36,.5)"></div>
        <span class="section-title">⬢ Compliance &amp; Regulatory Notes</span>
      </div>
      <div class="compliance-card">
        <div class="comp-tags">
          {''.join(f'<span class="comp-tag">{t}</span>' for t in ["OWASP Top 10 (2021)","PCI-DSS","GDPR","NIST SP 800-190","CWE","DAST-Verified"])}
        </div>
        {comp_html}
      </div>
    </section>

    <footer class="footer">
      SHIVA AI Security Intelligence Suite v4.0 &bull;
      Free Expert Engine &bull; Build #{BUILD_NUMBER}<br>
      npm audit + OWASP DepCheck + ZAP + SonarQube &bull; Zero API cost
    </footer>
  </main>
</div>
</body>
</html>"""

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  Dashboard → {OUTPUT_FILE}")
    print(f"  Score: {score}/100 | Grade: {grade} | Build: {decision}")
    print("=== Done ===\n")


if __name__ == "__main__":
    generate_dashboard()
