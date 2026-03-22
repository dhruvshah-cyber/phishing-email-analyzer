# Phishing Email Analyzer

A Python command-line tool that analyzes `.eml` files to detect phishing indicators and produce a structured threat report.

## Features

- **Header Analysis** — Extracts sender IP, domain, reply-to mismatches, and hop count
- **DNS Checks** — Validates SPF and DMARC records, flags weak or missing policies
- **URL Scanner** — Extracts all URLs and checks them against the VirusTotal API
- **IP Reputation** — Checks the sending IP against AbuseIPDB for known abuse history
- **Threat Score** — Calculates a 0-100 score with a SAFE / SUSPICIOUS / MALICIOUS verdict
- **Report Output** — Saves a clean `.txt` report to the `reports/` directory

## MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| Spearphishing Attachment | T1566.001 |
| Spearphishing Link | T1566.002 |
| Valid Accounts (credential harvesting) | T1078 |

## Project Structure

```
phishing-email-analyzer/
├── phishing_analyzer.py      # Main tool
├── sample_emails/
│   ├── phishing1.eml         # Sample: PayPal spoof
│   └── phishing2.eml         # Sample: IT helpdesk spoof
├── reports/
│   └── sample_report.txt     # Example output report
├── requirements.txt
└── README.md
```

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/dhruvshah-cyber/phishing-email-analyzer.git
cd phishing-email-analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API keys

Open `phishing_analyzer.py` and replace the placeholders at the top:

```python
VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY"
ABUSEIPDB_API_KEY  = "YOUR_ABUSEIPDB_KEY"
```

- Free VirusTotal key: https://www.virustotal.com/gui/join-us
- Free AbuseIPDB key: https://www.abuseipdb.com/register

## Usage

```bash
# Analyze a sample phishing email
python phishing_analyzer.py sample_emails/phishing1.eml

# Analyze another sample
python phishing_analyzer.py sample_emails/phishing2.eml
```

## Sample Output

```
============================================================
       PHISHING EMAIL ANALYZER -- THREAT REPORT
       Generated: 2026-03-21 08:05:00 UTC
============================================================

[ HEADER ANALYSIS ]
  From:          "PayPal Security" <security@paypa1-alert.com>
  Reply-To:      collect@evil-harvest.ru
  [!] Reply-To differs from From -- common phishing tactic
  [!] Return-Path domain does not match sender domain

[ DNS CHECKS ]
  [!] Missing SPF record
  [!] Missing DMARC record

[ URL SCAN ]
  [MALICIOUS] http://paypa1-alert.com/verify?token=abc123
  [MALICIOUS] http://bit.ly/3xFakeLink

[ THREAT VERDICT ]
  Score:   100/100
  Verdict: MALICIOUS
============================================================
```

## API Rate Limits

| API | Free Tier Limit |
|---|---|
| VirusTotal | 4 requests/minute, 500/day |
| AbuseIPDB | 1,000 requests/day |

## Disclaimer

This tool is for **educational and defensive security research only**. Only analyze emails you own or have explicit permission to analyze.
