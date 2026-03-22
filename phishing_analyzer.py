#!/usr/bin/env python3
"""
Phishing Email Analyzer
Analyzes .eml files or pasted email headers for phishing indicators.
MITRE ATT&CK: T1566.001, T1566.002, T1078
"""

import email
import os
import re
import sys
import requests
import dns.resolver
from email import policy
from datetime import datetime
from dotenv import load_dotenv

# Load API keys from .env file (never commit .env to version control)
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")


def load_email(source: str):
    """Load an email from a .eml file path or raw string."""
    try:
        with open(source, "r", errors="replace") as f:
            raw = f.read()
    except (FileNotFoundError, IsADirectoryError):
        raw = source
    return email.message_from_string(raw, policy=policy.default)


def analyze_headers(msg) -> dict:
    """Extract and flag suspicious header fields."""
    results = {}
    flags = []

    sender      = msg.get("From", "")
    reply_to    = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    received    = msg.get_all("Received") or []
    x_mailer    = msg.get("X-Mailer", msg.get("User-Agent", "Unknown"))

    results["from"]        = sender
    results["reply_to"]    = reply_to
    results["return_path"] = return_path
    results["x_mailer"]    = x_mailer
    results["hop_count"]   = len(received)

    sender_domain_match = re.search(r"@([w.-]+)", sender)
    results["sender_domain"] = sender_domain_match.group(1) if sender_domain_match else ""

    ip_match = re.search(r"[(d{1,3}(?:.d{1,3}){3})]", received[-1]) if received else None
    results["sender_ip"] = ip_match.group(1) if ip_match else ""

    if reply_to and reply_to not in sender:
        flags.append("Reply-To differs from From -- common phishing tactic")
    if return_path and results["sender_domain"] and results["sender_domain"] not in return_path:
        flags.append("Return-Path domain does not match sender domain")

    results["flags"] = flags
    return results


def check_dns(domain: str) -> dict:
    """Check SPF and DMARC DNS records."""
    results = {"domain": domain, "spf": None, "dmarc": None, "flags": []}

    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            txt = str(rdata)
            if "v=spf1" in txt:
                results["spf"] = txt
                if "~all" in txt:
                    results["flags"].append("SPF softfail (~all) -- weak policy")
                elif "+all" in txt:
                    results["flags"].append("SPF +all -- allows ANY sender, dangerous")
    except Exception:
        results["spf"] = "No SPF record found"
        results["flags"].append("Missing SPF record")

    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = str(rdata)
            if "v=DMARC1" in txt:
                results["dmarc"] = txt
                if "p=none" in txt:
                    results["flags"].append("DMARC p=none -- no enforcement")
    except Exception:
        results["dmarc"] = "No DMARC record found"
        results["flags"].append("Missing DMARC record")

    return results


def extract_urls(msg) -> list:
    """Extract all URLs from the email body."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                body += part.get_content() or ""
    else:
        body = msg.get_content() or ""
    return list(set(re.findall(r"https?://[^\s\"'<>]+", body)))


def check_url_virustotal(url: str) -> dict:
    """Check a URL against VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"url": url, "status": "API key not set (add VIRUSTOTAL_API_KEY to .env)", "malicious": 0, "suspicious": 0}
    hdrs = {"x-apikey": VIRUSTOTAL_API_KEY}
    resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=hdrs, data={"url": url}, timeout=10)
    if resp.status_code != 200:
        return {"url": url, "status": "VT error", "malicious": 0, "suspicious": 0}
    url_id = resp.json()["data"]["id"]
    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=hdrs, timeout=10)
    stats = analysis.json().get("data", {}).get("attributes", {}).get("stats", {})
    return {"url": url, "status": "checked",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)}


def check_ip_abuseipdb(ip: str) -> dict:
    """Check sender IP against AbuseIPDB."""
    if not ip:
        return {"ip": ip, "status": "No IP found"}
    if not ABUSEIPDB_API_KEY:
        return {"ip": ip, "status": "API key not set (add ABUSEIPDB_API_KEY to .env)"}
    hdrs   = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=hdrs, params=params, timeout=10)
    if resp.status_code != 200:
        return {"ip": ip, "status": "AbuseIPDB error"}
    data = resp.json().get("data", {})
    return {"ip": ip, "status": "checked",
            "abuse_score":   data.get("abuseConfidenceScore", 0),
            "country":       data.get("countryCode", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "is_tor":        data.get("isTor", False)}


def calculate_threat_score(header_results, dns_results, url_results, ip_results) -> dict:
    """Calculate overall threat score 0-100."""
    score = 0
    score += len(header_results.get("flags", [])) * 15
    score += len(dns_results.get("flags", []))    * 10

    malicious_urls  = [u for u in url_results if u.get("malicious", 0) > 0]
    suspicious_urls = [u for u in url_results if u.get("suspicious", 0) > 0]
    score += len(malicious_urls)  * 30
    score += len(suspicious_urls) * 10

    abuse = ip_results.get("abuse_score", 0)
    if abuse >= 75:   score += 30
    elif abuse >= 25: score += 15
    if ip_results.get("is_tor"): score += 20

    score = min(score, 100)
    verdict = "MALICIOUS" if score >= 60 else ("SUSPICIOUS" if score >= 30 else "SAFE")
    return {"score": score, "verdict": verdict,
            "malicious_urls": len(malicious_urls),
            "suspicious_urls": len(suspicious_urls)}


def generate_report(header_results, dns_results, url_results, ip_results, threat) -> str:
    """Generate a human-readable threat report."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "=" * 60,
        "       PHISHING EMAIL ANALYZER -- THREAT REPORT",
        f"       Generated: {ts}",
        "=" * 60, "",
        "[ HEADER ANALYSIS ]",
        f"  From:          {header_results['from']}",
        f"  Reply-To:      {header_results['reply_to']}",
        f"  Return-Path:   {header_results['return_path']}",
        f"  Sender IP:     {header_results['sender_ip']}",
        f"  Sender Domain: {header_results['sender_domain']}",
        f"  Mailer:        {header_results['x_mailer']}",
        f"  Hop Count:     {header_results['hop_count']}",
    ]
    for flag in header_results.get("flags", []):
        lines.append(f"  [!] {flag}")
    lines += ["", "[ DNS CHECKS ]",
              f"  SPF:   {dns_results.get('spf')}",
              f"  DMARC: {dns_results.get('dmarc')}"]
    for flag in dns_results.get("flags", []):
        lines.append(f"  [!] {flag}")
    lines += ["", "[ URL SCAN ]"]
    if url_results:
        for u in url_results:
            tag = "[MALICIOUS]" if u.get("malicious", 0) > 0 else ("[SUSPICIOUS]" if u.get("suspicious", 0) > 0 else "[CLEAN]")
            lines.append(f"  {tag} {u['url']}")
            lines.append(f"       Engines flagged -- malicious:{u.get('malicious',0)} suspicious:{u.get('suspicious',0)}")
    else:
        lines.append("  No URLs found in email body.")
    lines += ["", "[ IP REPUTATION ]",
              f"  IP:            {ip_results.get('ip', 'N/A')}",
              f"  Abuse Score:   {ip_results.get('abuse_score', 'N/A')}%",
              f"  Country:       {ip_results.get('country', 'N/A')}",
              f"  Total Reports: {ip_results.get('total_reports', 'N/A')}",
              f"  Tor Exit Node: {ip_results.get('is_tor', 'N/A')}",
              "", "[ THREAT VERDICT ]",
              f"  Score:   {threat['score']}/100",
              f"  Verdict: {threat['verdict']}",
              "", "=" * 60,
              "  MITRE ATT&CK: T1566.001 | T1566.002 | T1078",
              "=" * 60]
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python phishing_analyzer.py <email.eml>")
        sys.exit(1)

    source = sys.argv[1]
    print(f"[*] Loading: {source}")
    msg = load_email(source)

    print("[*] Analyzing headers...")
    header_results = analyze_headers(msg)

    print(f"[*] DNS check for: {header_results['sender_domain']}")
    dns_results = check_dns(header_results["sender_domain"]) if header_results["sender_domain"] else {"flags": []}

    print("[*] Scanning URLs...")
    url_results = [check_url_virustotal(u) for u in extract_urls(msg)]

    print(f"[*] IP reputation: {header_results['sender_ip']}")
    ip_results = check_ip_abuseipdb(header_results["sender_ip"])

    threat = calculate_threat_score(header_results, dns_results, url_results, ip_results)
    report = generate_report(header_results, dns_results, url_results, ip_results, threat)
    print("\n" + report)

    os.makedirs("reports", exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = f"reports/report_{ts}.txt"
    with open(path, "w") as f:
        f.write(report)
    print(f"\n[+] Saved: {path}")


if __name__ == "__main__":
    main()
