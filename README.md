# InsPect (IP Investigator)

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/fredycibersec/InsPect)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-green.svg)](https://github.com/fredycibersec/InsPect)
[![GitHub last commit](https://img.shields.io/github/last-commit/fredycibersec/InsPect.svg)](https://github.com/fredycibersec/InsPect/commits/main)
[![Dependencies](https://img.shields.io/badge/dependencies-requests%2C%20rich-orange.svg)](requirements.txt)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/fredycibersec/InsPect)

> A comprehensive IP and domain intelligence tool that gathers threat data from multiple sources, performs risk analysis, and provides actionable security insights.

InsPect is a Python command-line tool designed for comprehensive investigation of IP addresses and domain names. It aggregates data from multiple public and commercial intelligence sources, performs correlations, calculates a risk score, and presents findings in a clear, user-friendly format, optionally enhanced with rich terminal output.

## Overview

InsPect streamlines the process of gathering intelligence on a target (IP or domain) by automating lookups across various services:

1.  **Input Handling:** Accepts either an IP address or a domain name. If a domain is provided, it attempts to resolve it to an IP address using system DNS and fallback public DNS servers (`dig`/`host` via subprocess).
2.  **Blacklist Checking:** Queries the IP against a curated list of DNS blacklists (DNSBLs). It uses a quick subset by default or a comprehensive list (~70 sources) with the `-f` flag. Results are categorized (Spam, Security, Proxy, etc.) and contribute to a blacklist trust score.
3.  **IP Intelligence Gathering:** Fetches geolocation, ASN, ISP, organization details, and flags for mobile, proxy, or hosting status. It primarily uses the free [ip-api.com](http://ip-api.com/) service and enhances data with [ipinfo.io](https://ipinfo.io/) and [ipdata.co](https://ipdata.co/) if API keys are provided.
4.  **Threat Intelligence:** Leverages specialized threat APIs (requires API keys):
    *   **AbuseIPDB:** Retrieves IP reputation, abuse reports, reported attack categories, and the Abuse Confidence Score.
    *   **ThreatFox:** Checks if the IP (or IP:Port) is a known Indicator of Compromise (IOC), providing associated malware families, IOC types, and sample hashes.
    *   **PhishTank:** Checks if the domain (if provided as input) is listed as a known phishing URL.
5.  **Data Correlation:** Intelligently combines data from all sources to determine confidence levels for detections like Proxy, VPN, Tor usage, and overall malicious activity.
6.  **Risk Assessment:** Calculates a final Risk Score (0-100) based on weighted factors including blacklist presence, abuse reports, anonymity service usage, ThreatFox IOC detection, and whether the IP belongs to a known legitimate service. Assigns a clear Risk Level (Low, Medium, High).
7.  **MITRE ATT&CK Mapping:** For malware families identified via ThreatFox, it displays relevant MITRE ATT&CK tactics, techniques, infection vectors, and post-compromise activities based on an internal mapping.
8.  **Output & Reporting:**
    *   Presents a detailed report in the terminal, using the `rich` library for enhanced formatting if installed.
    *   Includes an **Executive Summary** highlighting key findings and providing a clear recommendation (e.g., Safe, Monitor, Block).
    *   Optionally outputs the full raw results to a JSON file for programmatic use or archival.

## Features

*   **Supports both IP Address and Domain Name inputs.**
*   **Multi-Source Intelligence:**
    *   Geolocation & Network Info: `ip-api.com` (free), `ipinfo.io` (key optional), `ipdata.co` (key required).
    *   DNS Blacklists: Quick set or ~70+ sources (optional).
    *   Abuse Reports & Reputation: `AbuseIPDB` (key required).
    *   IOC / Malware Association: `ThreatFox` (key required).
    *   Phishing URL Check: `PhishTank` (key optional).
*   **Advanced Analysis:**
    *   Anonymity Detection (Proxy, VPN, Tor) with confidence scoring.
    *   Malicious Activity Correlation across sources.
    *   Weighted Risk Score calculation (0-100) and Level (Low, Medium, High).
    *   Identification of known legitimate services (e.g., Google DNS, Cloudflare).
*   **Reporting:**
    *   Clear Executive Summary with actionable recommendations.
    *   Detailed breakdown of findings per source.
    *   MITRE ATT&CK context for detected malware.
    *   Enhanced terminal output (requires `rich`) or basic text.
    *   JSON file output option (`-o json`).
*   **Configurable:** Network timeout (`-t`), full blacklist check (`-f`).

## Requirements

*   Python 3.x
*   `requests` library (installed via `requirements.txt`)
*   `rich` library (optional, for enhanced terminal output, installed via `requirements.txt`)
*   External tools `dig` and `host` (usually pre-installed on Linux/macOS) for fallback DNS resolution.
*   API Keys for enhanced functionality (see Setup).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/fredycibersec/InsPect.git
    cd InsPect
    ```

2.  **(Recommended) Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Installs `requests` and optionally `rich`)*

## Setup: API Keys (Optional but Recommended)

For full functionality, InsPect uses several third-party APIs. Obtain API keys from the respective services and make them available as environment variables.

*   **AbuseIPDB:** ([abuseipdb.com/account/api](https://abuseipdb.com/account/api)) - For IP reputation and abuse reports.
    ```bash
    export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
    ```
*   **IPinfo:** ([ipinfo.io/signup](https://ipinfo.io/signup)) - For enhanced geolocation and ASN details. (Free tier available)
    ```bash
    export IPINFO_API_KEY="YOUR_IPINFO_KEY"
    ```
*   **IPdata:** ([ipdata.co/registration.html](https://ipdata.co/registration.html)) - For advanced threat intelligence (proxy/VPN/Tor detection). (Requires key)
    ```bash
    export IPDATA_API_KEY="YOUR_IPDATA_KEY"
    ```
*   **ThreatFox:** ([threatfox.abuse.ch/api/](https://threatfox.abuse.ch/api/)) - For IOC and malware checks. (Requires key)
    ```bash
    export THREATFOX_API_KEY="YOUR_THREATFOX_KEY"
    ```
*   **PhishTank:** ([phishtank.org/developer_info.php](https://www.phishtank.com/developer_info.php)) - For checking domains against known phishing URLs. (Key provides higher limits)
    ```bash
    export PHISHTANK_API_KEY="YOUR_PHISHTANK_APP_KEY" # Note: PhishTank calls this 'app_key'
    ```

**Tip:** You can place these `export` commands in your `~/.bashrc`, `~/.zshrc`, or create a `.env` file in the project directory (make sure to add `.env` to your `.gitignore`!) and use a tool like `python-dotenv` if you prefer (though the script doesn't automatically load `.env` files).

## Usage

**Basic Scan:**
```bash
python ip_investigator.py <ip_address_or_domain>
```
*Examples:*
```bash
python ip_investigator.py 8.8.8.8
python ip_investigator.py example.com
```

**Command-Line Options:**

*   `-t <seconds>`, `--timeout <seconds>`: Set network request timeout (default: 10).
    ```bash
    python ip_investigator.py 1.1.1.1 -t 15
    ```
*   `-f`, `--full`: Use the comprehensive set of ~70 blacklists (slower). Default uses a smaller, faster subset.
    ```bash
    python ip_investigator.py 192.168.1.1 -f
    ```
*   `-o json`, `--output json`: Output results in JSON format to stdout instead of the terminal display.
    ```bash
    python ip_investigator.py example.com -o json
    ```
*   `-j <filename>`, `--json-file <filename>`: Save JSON output to a specific file. Use with `-o json`. (Default: `ip_report_<target>_<timestamp>.json`)
    ```bash
    python ip_investigator.py 8.8.8.8 -o json -j report_google_dns.json
    ```

## Contributing

Contributions, issues, and feature requests are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
