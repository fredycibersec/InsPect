#!/usr/bin/env python3
"""
IP Investigator - A tool for IP and domain analysis

This tool combines IP blacklist checking and basic intelligence gathering
with enhanced visualization.

Usage:
  python ip_investigator.py <ip_address or domain>
  python ip_investigator.py --help
"""

import sys
import os
import socket
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import requests
import json
import subprocess
from datetime import datetime
# Import banner module components
from banner import ascii_banner, print_banner
# Try importing rich for enhanced display
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Rich library not available. Install with: pip install rich")
    print("Running with basic formatting...\n")
    console = None

# MITRE ATT&CK Framework Mapping for common malware families
MITRE_MAPPINGS = {
    "Emotet": {
        "description": "A sophisticated, modular banking Trojan that primarily functions as a downloader or dropper of other banking Trojans. It uses multiple methods for maintaining persistence and evasion techniques.",
        "tactics": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration"],
        "techniques": ["T1566.001 (Phishing: Spearphishing Attachment)", "T1204.002 (User Execution: Malicious File)", "T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)", "T1055 (Process Injection)", "T1027 (Obfuscated Files or Information)", "T1056.001 (Input Capture: Keylogging)", "T1082 (System Information Discovery)", "T1570 (Lateral Tool Transfer)", "T1560 (Archive Collected Data)", "T1571 (Non-Standard Port)"],
        "infection_vectors": ["Phishing emails with malicious Office documents", "Malicious macro-enabled attachments", "Exploit kits", "Drive-by downloads"],
        "post_compromise": ["Credential theft", "Banking information theft", "Installation of additional malware", "Email harvesting", "Ransomware delivery"]
    },
    "Cobalt Strike": {
        "description": "A commercial, full-featured penetration testing tool that is widely used by red teams and increasingly by threat actors for post-exploitation activities.",
        "tactics": ["Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"],
        "techniques": ["T1059 (Command and Scripting Interpreter)", "T1547 (Boot or Logon Autostart Execution)", "T1134 (Access Token Manipulation)", "T1140 (Deobfuscate/Decode Files or Information)", "T1056 (Input Capture)", "T1087 (Account Discovery)", "T1021 (Remote Services)", "T1560 (Archive Collected Data)", "T1573 (Encrypted Channel)", "T1041 (Exfiltration Over C2 Channel)"],
        "infection_vectors": ["Spear phishing", "Exploitation of vulnerable services", "Strategic web compromises", "Prior compromise by other malware"],
        "post_compromise": ["C2 communication", "Data exfiltration", "Lateral movement", "Keylogging", "Screenshot capture", "Mimikatz deployment"]
    },
    "Trickbot": {
        "description": "A sophisticated banking Trojan and information stealer that has evolved into a modular malware platform. It is often used to enable ransomware attacks.",
        "tactics": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration"],
        "techniques": ["T1566 (Phishing)", "T1204 (User Execution)", "T1547 (Boot or Logon Autostart Execution)", "T1055 (Process Injection)", "T1027 (Obfuscated Files or Information)", "T1056 (Input Capture)", "T1082 (System Information Discovery)", "T1570 (Lateral Tool Transfer)", "T1560 (Archive Collected Data)", "T1571 (Non-Standard Port)"],
        "infection_vectors": ["Phishing emails", "Malspam campaigns", "Exploit kits", "Secondary payload from other malware"],
        "post_compromise": ["Banking credential theft", "System information gathering", "Cookie theft", "Ransomware deployment", "Network propagation"]
    },
    "QakBot": {
        "description": "A sophisticated banking Trojan focused on stealing financial data. It has advanced persistence and spreading capabilities.",
        "tactics": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control"],
        "techniques": ["T1566 (Phishing)", "T1204 (User Execution)", "T1547 (Boot or Logon Autostart Execution)", "T1055 (Process Injection)", "T1555 (Credentials from Password Stores)", "T1087 (Account Discovery)", "T1534 (Internal Spearphishing)", "T1113 (Screen Capture)", "T1104 (Multi-Stage Channels)"],
        "infection_vectors": ["Email thread hijacking", "Malicious document attachments", "Exploit kits"],
        "post_compromise": ["Banking credential theft", "Email harvesting", "Business email compromise", "Lateral movement", "Ransomware delivery"]
    },
    "ZLoader": {
        "description": "A banking Trojan derived from the Zeus malware family, designed to steal credentials and financial information.",
        "tactics": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Collection", "Command and Control"],
        "techniques": ["T1566 (Phishing)", "T1204 (User Execution)", "T1547 (Boot or Logon Autostart Execution)", "T1027 (Obfuscated Files or Information)", "T1056 (Input Capture)", "T1560 (Archive Collected Data)", "T1102 (Web Service)"],
        "infection_vectors": ["Phishing emails", "Drive-by downloads", "SEO poisoning", "Malicious ads"],
        "post_compromise": ["Banking credential theft", "Cookie theft", "Keylogging", "Form grabbing", "Screenshot capture"]
    },
    "AsyncRAT": {
        "description": "An open-source remote access trojan (RAT) with capabilities for remote control, keylogging, and credential theft.",
        "tactics": ["Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Collection", "Command and Control"],
        "techniques": ["T1204 (User Execution)", "T1547 (Boot or Logon Autostart Execution)", "T1068 (Exploitation for Privilege Escalation)", "T1027 (Obfuscated Files or Information)", "T1056 (Input Capture)", "T1082 (System Information Discovery)", "T1113 (Screen Capture)", "T1573 (Encrypted Channel)"],
        "infection_vectors": ["Phishing emails", "Malicious attachments", "Software vulnerabilities"],
        "post_compromise": ["Keylogging", "Screenshot capture", "File management", "Remote command execution", "Credential theft"]
    }
}

# ASN Reputation Database
ASN_REPUTATION = {
    "AS16509": {"name": "Amazon AWS", "category": "Cloud Provider", "reputation": "Generally legitimate, but frequently abused for malicious activities"},
    "AS14618": {"name": "Amazon AES", "category": "Cloud Provider", "reputation": "Generally legitimate, but frequently abused for malicious activities"},
    "AS15169": {"name": "Google", "category": "Cloud Provider", "reputation": "Generally legitimate with strong security measures"},
    "AS8075": {"name": "Microsoft", "category": "Cloud Provider", "reputation": "Generally legitimate with strong security measures"},
    "AS13335": {"name": "Cloudflare", "category": "CDN/Security", "reputation": "Generally legitimate, provides security services"},
    "AS4837": {"name": "China Unicom", "category": "ISP", "reputation": "Often associated with malicious activity"},
    "AS4134": {"name": "Chinanet", "category": "ISP", "reputation": "Often associated with malicious activity"},
    "AS9009": {"name": "M247", "category": "Hosting", "reputation": "Frequently associated with malicious activity"},
    "AS9299": {"name": "Philippine Long Distance Telephone", "category": "ISP", "reputation": "Often associated with malicious activity"},
    "AS55990": {"name": "Huawei Cloud", "category": "Cloud Provider", "reputation": "Mixed, with some security concerns"},
    "AS44477": {"name": "Stark Industries Solutions", "category": "Hosting", "reputation": "Frequently associated with malicious activity"},
    "AS58061": {"name": "Rezolve", "category": "Hosting", "reputation": "Frequently associated with malicious activity"},
    "AS49981": {"name": "WorldStream", "category": "Hosting", "reputation": "Known for lax abuse controls"},
    "AS63949": {"name": "Akamai/Linode", "category": "Cloud Provider", "reputation": "Generally legitimate but can be abused"},
    "AS20473": {"name": "The Constant/Vultr", "category": "Hosting", "reputation": "Often used for both legitimate and malicious purposes"},
    "AS396982": {"name": "Google Cloud", "category": "Cloud Provider", "reputation": "Generally legitimate, used widely, some abuse"},
    "AS209242": {"name": "DataCamp Limited", "category": "Hosting", "reputation": "Frequently associated with malicious/proxy activity"},
    "AS206248": {"name": "Brett Roberts", "category": "Hosting", "reputation": "Frequently associated with malicious/proxy activity"}
}

# Country Threat Intelligence
COUNTRY_THREAT_INTEL = {
    "RU": {"name": "Russia", "threat_level": "High", "common_threats": ["State-sponsored activity", "Cybercrime", "Ransomware operations"], 
           "note": "Many cybercrime groups operate from Russia with limited law enforcement action."},
    "CN": {"name": "China", "threat_level": "High", "common_threats": ["APT groups", "Intellectual property theft", "Espionage"], 
           "note": "Strong government ties to cyber operations targeting intellectual property and strategic intelligence."},
    "KP": {"name": "North Korea", "threat_level": "High", "common_threats": ["Financial theft", "Cryptocurrency attacks", "Destructive malware"], 
           "note": "State-sponsored activities focused on financial gain to circumvent sanctions."},
    "IR": {"name": "Iran", "threat_level": "High", "common_threats": ["Destructive attacks", "Espionage", "Information operations"], 
           "note": "Growing cyber capabilities with focus on regional adversaries and critical infrastructure."},
    "NL": {"name": "Netherlands", "threat_level": "Medium", "common_threats": ["Bulletproof hosting", "Botnet infrastructure", "Anonymization services"],
           "note": "Strong infrastructure and connectivity sometimes abused for hosting malicious services."},
    "UA": {"name": "Ukraine", "threat_level": "Medium", "common_threats": ["Cybercrime", "Spam operations", "Carding forums"],
           "note": "Active cybercriminal ecosystem, but also frequently targeted by state actors."},
    "RO": {"name": "Romania", "threat_level": "Medium", "common_threats": ["Financial fraud", "Cybercrime", "Scam operations"],
           "note": "Historical association with financial fraud and scam operations."},
    "HK": {"name": "Hong Kong", "threat_level": "Medium", "common_threats": ["APT infrastructure", "Bulletproof hosting", "Banking malware"],
           "note": "Often used as infrastructure for China-based operations."},
    "US": {"name": "United States", "threat_level": "Medium", "common_threats": ["Bulletproof hosting", "Botnet infrastructure", "Cloud-based attacks"],
           "note": "Extensive cloud infrastructure that can be abused, but generally good security practices."},
    "CH": {"name": "Switzerland", "threat_level": "Low", "common_threats": ["Banking malware", "Phishing infrastructure"],
           "note": "Strong privacy laws sometimes exploited by threat actors for anonymity."},
    "GB": {"name": "United Kingdom", "threat_level": "Low", "common_threats": ["Phishing infrastructure", "Financial fraud"],
           "note": "Strong cyber defense capabilities and active law enforcement."},
    "DE": {"name": "Germany", "threat_level": "Low", "common_threats": ["Bulletproof hosting", "Botnet infrastructure"],
           "note": "Strong infrastructure with some abuse, but active security community."},
    "FR": {"name": "France", "threat_level": "Low", "common_threats": ["Phishing infrastructure", "Cybercrime"],
           "note": "Active security posture with strong national capabilities."},
    "JP": {"name": "Japan", "threat_level": "Low", "common_threats": ["Banking malware targeting local institutions"],
           "note": "Strong security practices but frequently targeted by regional threat actors."},
    "IN": {"name": "India", "threat_level": "Medium", "common_threats": ["Tech support scams", "Phishing", "Mobile malware"], "note": "Large volume of scam operations, growing cybercrime."},
    "BR": {"name": "Brazil", "threat_level": "Medium", "common_threats": ["Banking malware", "Financial fraud", "POS malware"], "note": "Significant focus on local financial institutions."},
    "NG": {"name": "Nigeria", "threat_level": "Medium", "common_threats": ["Business Email Compromise (BEC)", "Advance-fee fraud (419 scams)"], "note": "Globally known for social engineering and fraud schemes."}
}

# Terminal colors for non-rich output
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"

# Logging functions
def log_info(message):
    if RICH_AVAILABLE:
        console.print(f"[cyan][INFO][/] {message}")
    else:
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} {message}")

def log_success(message):
    if RICH_AVAILABLE:
        console.print(f"[green][SUCCESS][/] {message}")
    else:
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} {message}")

def log_warning(message):
    if RICH_AVAILABLE:
        console.print(f"[yellow][WARNING][/] {message}")
    else:
        print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} {message}")

def log_error(message):
    if RICH_AVAILABLE:
        console.print(f"[red][ERROR][/] {message}")
    else:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {message}")

class BlacklistChecker:
    """Checks IP addresses against common blacklists"""
    
    def __init__(self, max_workers=20, check_all=False):
        self.max_workers = max_workers
        self.check_all = check_all
        
        # Define blacklists organized by category (comprehensive set of 70+ blacklists)
        self.blacklists = {
            "Spam Blacklists": [
                "dnsbl-0.uceprotect.net",
                "dnsbl-1.uceprotect.net",
                "dnsbl-2.uceprotect.net",
                "dnsbl-3.uceprotect.net",
                "rbl.abuse.ro",
                "spam.dnsbl.anonmails.de",
                "ips.backscatterer.org",
                "b.barracudacentral.org",
                "bl.blocklist.de",
                "bsb.empty.us",
                "bsb.spamlookup.net",
                "spamsources.fabel.dk",
                "bl.spamcop.net",
                "zen.spamhaus.org",
                "bl.spameatingmonkey.net",
                "backscatter.spameatingmonkey.net",
                "dyna.spamrats.com",
                "noptr.spamrats.com",
                "spam.spamrats.com",
                "bl.mailspike.net",
                "z.mailspike.net",
                "spamguard.leadmon.net",
                "rbl.interserver.net",
                "rbl.schulte.org",
                "cbl.abuseat.org",
                "dnsbl.spfbl.net",
                "bl.suomispam.net",
            ],
            "Security/Malware Blacklists": [
                "dnsbl.dronebl.org",
                "phishing.rbl.msrbl.net",
                "spam.rbl.msrbl.net",
                "dnsbl.kempt.net",
                "mail-abuse.blacklist.jippg.org",
                "wormrbl.imp.ch",
                "spamrbl.imp.ch",
                "dnsrbl.swinog.ch",
                "truncate.gbudb.net",
                "db.wpbl.info",
                "dnsbl.zapbl.net",
                "rhsbl.zapbl.net",
                "rbl2.triumf.ca",
                "blacklist.woody.ch",
            ],
            "Tor/Proxy Blacklists": [
                "torexit.dan.me.uk",
                "exitnodes.tor.dnsbl.sectoor.de",
                "ix.dnsbl.manitu.net",
            ],
            "SORBS Blacklists": [
                "spam.dnsbl.sorbs.net",
                "aspews.ext.sorbs.net",
                "l1.bbfh.ext.sorbs.net",
                "l2.bbfh.ext.sorbs.net",
                "l3.bbfh.ext.sorbs.net",
                "l4.bbfh.ext.sorbs.net",
                "dnsbl.sorbs.net",
                "http.dnsbl.sorbs.net",
                "misc.dnsbl.sorbs.net",
                "smtp.dnsbl.sorbs.net",
                "socks.dnsbl.sorbs.net",
                "zombie.dnsbl.sorbs.net",
                "dul.dnsbl.sorbs.net",
                "block.dnsbl.sorbs.net",
            ],
            "Policy/Bogon Blacklists": [
                "bogons.cymru.com",
                "all.rbl.jp",
                "psbl.surriel.com",
                "cbl.anti-spam.org.cn",
                "cdl.anti-spam.org.cn",
                "bl.drmx.org",
                "bl.konstant.no",
                "orvedb.aupads.org",
                "rsbl.aupads.org",
                "dnsbl.calivent.com.pe",
                "hil.habeas.com",
                "dnsbl.inps.de",
                "relays.nether.net",
                "unsure.nether.net",
            ],
        }
        
        # Define a smaller subset for quicker checks when check_all is False
        self.quick_blacklists = {
            "Spam Blacklists": ["zen.spamhaus.org", "bl.spamcop.net"],
            "Security/Malware Blacklists": ["dnsbl.sorbs.net", "dnsbl.dronebl.org"],
            "Tor/Proxy Blacklists": ["torexit.dan.me.uk"],
            "SORBS Blacklists": ["dnsbl.sorbs.net"],
            "Policy/Bogon Blacklists": ["bogons.cymru.com"]
        }
    
    def reverse_ip(self, ip):
        """Reverse an IP address for DNS lookups"""
        return '.'.join(reversed(ip.split('.')))
    
    def check_single_blacklist(self, ip, blacklist, category):
        """Check if an IP is listed on a specific blacklist"""
        reversed_ip = self.reverse_ip(ip)
        lookup = f"{reversed_ip}.{blacklist}"
        
        try:
            socket.gethostbyname(lookup)
            return (blacklist, category, True)
        except (socket.gaierror, socket.herror):
            return (blacklist, category, False)
    
    def check_ip(self, ip, progress_callback=None):
        """Check an IP against all blacklists"""
        # Prepare list of blacklists to check
        check_list = []
        # Use either comprehensive list or quick list based on check_all flag
        blacklist_set = self.blacklists if self.check_all else self.quick_blacklists
        
        for category, blacklist_list in blacklist_set.items():
            for blacklist in blacklist_list:
                check_list.append((blacklist, category))
        results = {
            "ip": ip,
            "total": len(check_list),
            "listed": 0,
            "details": [],
            "categories": {}
        }
        
        # Initialize category counts
        for category in self.blacklists.keys():
            results["categories"][category] = {"total": 0, "listed": 0}
        
        # Use ThreadPoolExecutor for concurrent checks
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for blacklist, category in check_list:
                future = executor.submit(self.check_single_blacklist, ip, blacklist, category)
                futures.append(future)
            
            completed = 0
            for future in futures:
                blacklist, category, is_listed = future.result()
                
                # Update category counts
                results["categories"][category]["total"] += 1
                if is_listed:
                    results["listed"] += 1
                    results["categories"][category]["listed"] += 1
                
                # Save detailed result
                results["details"].append({
                    "blacklist": blacklist,
                    "category": category,
                    "listed": is_listed
                })
                
                # Update progress if callback provided
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(check_list))
        
        # Calculate trust score (enhanced version)
        if results["listed"] == 0:
            results["trust_score"] = 100
            results["trust_level"] = "Trusted"
            results["trust_color"] = "green"
        elif results["listed"] == 1:
            results["trust_score"] = 80
            results["trust_level"] = "Moderate"
            results["trust_color"] = "yellow"
        elif results["listed"] <= 3:
            results["trust_score"] = 60
            results["trust_level"] = "Suspicious"
            results["trust_color"] = "yellow"
        elif results["listed"] <= 5:
            results["trust_score"] = 40
            results["trust_level"] = "Questionable"
            results["trust_color"] = "red"
        elif results["listed"] <= 8:
            results["trust_score"] = 20
            results["trust_level"] = "Untrusted"
            results["trust_color"] = "red"
        else:
            results["trust_score"] = 0
            results["trust_level"] = "Malicious"
            results["trust_color"] = "red"
        
        return results

class IPInfoProvider:
    """Provider for ipinfo.io API (IP geolocation and info)"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.api_key = os.environ.get("IPINFO_API_KEY")
    
    def get_ip_info(self, ip):
        """Get IP geolocation information from ipinfo.io"""
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            else:
                log_warning(f"IPInfo API returned status code {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            log_error(f"Error accessing IPInfo API: {e}")
            return None


class IPDataProvider:
    """Provider for ipdata.co API (detailed IP intelligence)"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.api_key = os.environ.get("IPDATA_API_KEY")
    
    def get_ip_info(self, ip):
        """Get detailed IP information from ipdata.co"""
        if not self.api_key:
            log_warning("IPDATA API key not found in environment variables (IPDATA_API_KEY)")
            return None
            
        url = f"https://api.ipdata.co/{ip}?api-key={self.api_key}"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            else:
                log_warning(f"IPDATA API returned status code {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            log_error(f"Error accessing IPDATA API: {e}")
            return None


class AbuseIPDBProvider:
    """Provider for AbuseIPDB API (IP reputation and abuse reports)"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY")
    
    def get_ip_info(self, ip):
        """Get IP abuse information from AbuseIPDB"""
        if not self.api_key:
            log_warning("AbuseIPDB API key not found in environment variables (ABUSEIPDB_API_KEY)")
            return None
            
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            # --- Debug print (commented out) ---
            # print(f"[DEBUG] AbuseIPDB API Response Status: {response.status_code}") 
            if response.status_code == 200:
                # --- Debug print (commented out) ---
                # print(f"[DEBUG] AbuseIPDB API Response JSON (first 200 chars): {response.text[:200]}") 
                return response.json()
            else:
                log_warning(f"AbuseIPDB API returned status code {response.status_code}")
                # --- Debug print (commented out) ---
                # print(f"[DEBUG] AbuseIPDB API Error Response: {response.text}") 
                return None
        except requests.exceptions.RequestException as e:
            log_error(f"Error accessing AbuseIPDB API: {e}")
            return None


class ThreatFoxProvider:
    """Provider for ThreatFox API (IOC database by abuse.ch)"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.api_key = os.environ.get("THREATFOX_API_KEY")
        self.api_url = "https://threatfox-api.abuse.ch/api/v1/"
        
    def search_ioc(self, ip):
        """Search for an IP address in ThreatFox to check if it's a known IOC"""
        if not self.api_key:
            log_warning("ThreatFox API key not found in environment variables (THREATFOX_API_KEY)")
            return None
        
        # First try exact match with just the IP
        result = self._query_threatfox(ip, True)
        
        # If no results found, try common IP:port combinations
        if result and result.get("query_status") == "no_result" and self.api_key:
            ### common_ports = ["80", "443", "8080", "8443", "4443", "3389"]
            common_ports = [
                "25",    # SMTP (correo electrónico)
                "80",    # HTTP (web)
                "123",   # NTP (sincronización horaria)
                "161",   # SNMP (gestión de red)
                "443",   # HTTPS (web segura)
                "554",   # RTSP (streaming de vídeo)
                "8080",  # HTTP alternativo
                "8443",  # HTTPS alternativo
                "4443",  # HTTPS alternativo
                "3389",  # RDP (escritorio remoto)
                "1883",  # MQTT (protocolo de mensajería IoT)
                "8883",  # MQTT sobre TLS (seguro)
                "5683",  # CoAP (protocolo IoT)
                "5353",  # mDNS (descubrimiento de servicios)
                "5000",  # Usado en plataformas IoT y APIs
                # Rango de puertos común en IoT para servicios personalizados
                "6000", "6001", "6002", "6003", "6004", "6005", "6006", "6007", "6008", "6009", "6010",
                "7000"   # Fin del rango sugerido
            ]

            log_info(f"No exact IP match found, checking common ports: {', '.join(common_ports)}") # Log once before loop
            for port in common_ports:
                ip_port = f"{ip}:{port}"
                # log_info(f"No exact IP match found, trying {ip_port} in ThreatFox") # Remove per-port log
                port_result = self._query_threatfox(ip_port, True, log_no_result=False) # Don't log no_result for ports
                
                # If we found a match with the port, return those results
                if port_result and port_result.get("query_status") == "ok" and port_result.get("data"):
                    log_info(f"Found match for {ip_port} in ThreatFox")
                    return port_result
        
        return result
    
    def _query_threatfox(self, search_term, exact_match=True, log_no_result=True): # Add log_no_result flag
        """Helper method to query ThreatFox API"""
        # Prepare the request data
        # Prepare the request data
        data = {
            "query": "search_ioc",
            "search_term": search_term,
            "exact_match": exact_match
        }
        # Headers need to be defined *before* the try block
        headers = {
            "Auth-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        try:
            # Make the POST request to ThreatFox API
            response = requests.post(
                self.api_url,
                headers=headers,
                json=data,
                timeout=self.timeout
            )
            # Uncomment for debugging ThreatFox API responses
            # print(f"[DEBUG] ThreatFox API response for {search_term}: {response.status_code}, {response.text[:200]}")
            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    return result # Correctly indented
                elif result.get("query_status") == "no_result": # Correctly indented
                    # No results found, but query was successful
                    if log_no_result: # Indented under elif
                        log_info(f"No ThreatFox results found for: {search_term}")
                    return {"query_status": "no_result", "data": []}
                elif result.get("query_status") == "wrong_auth_key": # Correctly indented (Removed duplicate)
                    log_warning(f"ThreatFox API authentication failed. Please check your API key.")
                    return None
                else: # Correctly indented
                    error_msg = result.get('data')
                    log_warning(f"ThreatFox API returned error: {error_msg}")
                    # Uncomment for debugging ThreatFox API responses
                    # print(f"[DEBUG] Full ThreatFox API response: {result}")
                    return None
            else:
                log_warning(f"ThreatFox API returned status code {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            log_error(f"Error accessing ThreatFox API: {e}")
            return None

class PhishTankProvider:
    """Provider for PhishTank API (checks URLs against phishing database)"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.api_key = os.environ.get("PHISHTANK_API_KEY")
        self.api_url = "http://checkurl.phishtank.com/checkurl/"
        if not self.api_key:
            log_warning("PhishTank API key (app_key) not found in environment variables (PHISHTANK_API_KEY). Anonymous access has limitations.")
            
    def check_url(self, url_to_check):
        """Check a URL against the PhishTank database"""
        payload = {
            "url": url_to_check,
            "format": "json"
        }
        if self.api_key:
            payload["app_key"] = self.api_key
            
        headers = {
            'User-Agent': 'IPInvestigatorScript/1.0' # PhishTank requires a User-Agent
        }

        try:
            response = requests.post(self.api_url, data=payload, headers=headers, timeout=self.timeout)
            
            # PhishTank might return non-standard status codes or content types on errors
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check for API errors within the JSON response
                    if data.get("meta", {}).get("status") == "success":
                        return data.get("results", {})
                    else:
                        error_message = data.get("errortext", "Unknown PhishTank API error")
                        log_warning(f"PhishTank API returned error: {error_message}")
                        return None
                except json.JSONDecodeError:
                    log_warning(f"PhishTank API returned non-JSON response (Status: {response.status_code})")
                    return None
            elif response.status_code == 509: # Bandwidth Limit Exceeded (common without API key)
                 log_warning("PhishTank API request failed: Bandwidth Limit Exceeded (509). Consider using an API key.")
                 return None
            else:
                log_warning(f"PhishTank API returned status code {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            log_error(f"Error accessing PhishTank API: {e}")
            return None


class IPIntelligence:
    """Gathers intelligence information about an IP address"""
    
    def __init__(self, timeout=10, check_all_blacklists=False):
        self.timeout = timeout
        self.blacklist_checker = BlacklistChecker(check_all=check_all_blacklists)
        self.ip_api_provider = None  # Basic free API
        self.ipinfo_provider = IPInfoProvider(timeout=timeout)
        self.ipdata_provider = IPDataProvider(timeout=timeout)
        self.abuseipdb_provider = AbuseIPDBProvider(timeout=timeout)
        self.threatfox_provider = ThreatFoxProvider(timeout=timeout)
        self.phishtank_provider = PhishTankProvider(timeout=timeout) # <-- Added this line
    
    def is_valid_ip(self, ip):
        """Check if a string is a valid IPv4 address"""
        try:
            socket.inet_aton(ip)
            return ip.count('.') == 3
        except socket.error:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for an IP if available"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    def get_basic_ip_info(self, ip):
        """Get basic IP info from ip-api.com (free API, no key required)"""
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
            return None
        except Exception as e:
            log_error(f"Error accessing IP-API: {e}")
            return None
    
    def resolve_domain(self, domain):
        """Resolve a domain to its IP address using multiple methods and DNS servers"""
        # Try the standard socket.gethostbyname first (uses system DNS)
        try:
            ip = socket.gethostbyname(domain)
            if ip:
                return ip
        except socket.gaierror:
            log_info("Standard DNS resolution failed, trying alternative methods...")
        
        # Try using external DNS servers via subprocess (dig)
        try:
            for dns_server in ["8.8.8.8", "1.1.1.1"]:  # Google DNS, Cloudflare DNS
                log_info(f"Trying DNS server {dns_server}...")
                cmd = f"dig +short {domain} @{dns_server} | head -n1"
                result = subprocess.check_output(cmd, shell=True, text=True).strip()
                if result and self.is_valid_ip(result):
                    log_info(f"Resolved using {dns_server}: {result}")
                    return result
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            pass # Handle or log error if needed

        # Try using host command via subprocess
        try:
            cmd = f"host {domain} 8.8.8.8 | grep 'has address' | head -n1 | awk '{{print $NF}}'"
            result = subprocess.check_output(cmd, shell=True, text=True).strip()
            if result and self.is_valid_ip(result):
                log_info(f"Resolved using host command: {result}")
                return result
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            log_warning(f"Host command resolution failed: {e}")
        
        # If we got here, all resolution methods failed
        log_error(f"Could not resolve domain {domain} using multiple resolution methods")
        log_info("Suggestion: If you know the IP address, you can analyze it directly")
        return None
    

    def check_target(self, target):
        """Check a target IP or domain and gather comprehensive intelligence"""
        log_info("Gathering IP intelligence...")
        
        # Determine if target is IP or domain
        domain = None
        ip = target
        
        if not self.is_valid_ip(target):
            log_info(f"Resolving domain {target}...")
            ip = self.resolve_domain(target)
            if not ip:
                log_error(f"Could not resolve domain {target}")
                return None
            domain = target
            log_info(f"Domain {domain} resolved to {ip}")
        
        # Start gathering results
        result = { 
            "target": target,
            "ip": ip,
            "domain": domain,
            "timestamp": time.time()
        }

        # Get hostname 
        result["hostname"] = self.get_hostname(ip)

        # --- MOVE Blacklist Check Here ---
        # Check blacklists
        if RICH_AVAILABLE:
            with Progress( 
                SpinnerColumn(),
                TextColumn("[bold cyan]Checking blacklists..."),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
                transient=True 
            ) as progress:
                task = progress.add_task("Checking", total=100)
                def update_progress(completed, total):
                    progress.update(task, completed=int(completed / total * 100))
                result["blacklist"] = self.blacklist_checker.check_ip(ip, update_progress)
        else:
            print("Checking blacklists...")
            result["blacklist"] = self.blacklist_checker.check_ip(ip)
        # --- End Blacklist Check ---
        
        # Get IP intelligence from multiple sources (Moved log message slightly)
        # log_info("Gathering IP intelligence...") # Already logged at start of function
        
        # Initialize threat data structure (Now after blacklist check)
        result["threat"] = {
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_datacenter": False,
            "is_mobile": False,
            "is_malicious": False,
            "is_spammer": False,
            "threat_types": [],
            "attack_types": [],
            "abuse_confidence_score": None,
            "reports_count": None,
            "last_reported_at": None # Removed duplicate line after this
        }

        # --- Add PhishTank Check if target was a domain ---
        phishtank_result = None
        if domain: # Only check if the original target was a domain
            url_to_check = f"http://{domain}" # Check basic http version
            log_info(f"Checking {url_to_check} against PhishTank...")
            phishtank_result = self.phishtank_provider.check_url(url_to_check)
            if phishtank_result:
                result["phishtank_info"] = phishtank_result
                # Add to threat types if it's a valid phish
                if phishtank_result.get("valid") and phishtank_result.get("verified"):
                    if "Phishing URL" not in result["threat"]["threat_types"]:
                         result["threat"]["threat_types"].append("Phishing URL")
                    # Also mark as malicious if verified phish
                    result["threat"]["is_malicious"] = True 
        # --- End PhishTank Check ---
        
        # Initialize unified intelligence structure for correlated data
        result["unified_intel"] = {
            # Proxy/VPN/Tor detection with confidence and sources
            "anonymity": {
                "is_proxy": {"detected": False, "confidence": 0, "sources": []},
                "is_vpn": {"detected": False, "confidence": 0, "sources": []},
                "is_tor": {"detected": False, "confidence": 0, "sources": []},
                "is_datacenter": {"detected": False, "confidence": 0, "sources": []},
                "is_anonymous": {"detected": False, "confidence": 0, "sources": []}
            },
            
            # Malicious activity detection with confidence and sources
            "malicious_activity": {
                "is_malicious": {"detected": False, "confidence": 0, "sources": []},
                "is_spammer": {"detected": False, "confidence": 0, "sources": []},
                "is_attacker": {"detected": False, "confidence": 0, "sources": []},
                "blacklisted": {"detected": False, "confidence": 0, "sources": []}
            },
            
            # Network information with reliability and source
            "network_info": {
                "geolocation": {"reliability": 0, "source": None},
                "asn_info": {"reliability": 0, "source": None},
                "organization": {"reliability": 0, "source": None}
            },
            
            # Consolidated threat types from all sources with confidence
            "threat_types": [],  # List of {type, confidence, sources}
            
            # ThreatFox IOC information
            "threatfox": {
                "detected": False,
                "malware_families": [],
                "first_seen": None,
                "ioc_types": [],
                "confidence": 0
            },
            
            # Overall confidence in the data
            "overall_confidence": 0,
            
            # Sources available for this analysis
            "sources_available": []
        }
        # 1. Basic IP geolocation (free, no API key required)
        basic_ip_data = self.get_basic_ip_info(ip)
        if basic_ip_data:
            result["intelligence"] = basic_ip_data
            
            # Extract basic threat info
            is_proxy = basic_ip_data.get("proxy", False)
            is_hosting = basic_ip_data.get("hosting", False)
            is_mobile = basic_ip_data.get("mobile", False)
            
            if is_proxy:
                result["threat"]["is_proxy"] = True
                if "Proxy" not in result["threat"]["threat_types"]:
                    result["threat"]["threat_types"].append("Proxy")
            
            if is_hosting:
                result["threat"]["is_datacenter"] = True
                if "Datacenter/Hosting" not in result["threat"]["threat_types"]:
                    result["threat"]["threat_types"].append("Datacenter/Hosting")
            
            if is_mobile:
                result["threat"]["is_mobile"] = True
                if "Mobile Network" not in result["threat"]["threat_types"]:
                    result["threat"]["threat_types"].append("Mobile Network")
        
        # 2. IPInfo data (if API key available)
        ipinfo_data = self.ipinfo_provider.get_ip_info(ip)
        if ipinfo_data:
            result["ipinfo_intelligence"] = ipinfo_data
            
            # Extract additional location/network data
            # This typically provides better ASN/organization data
            if ipinfo_data.get("org") and "AS" in ipinfo_data.get("org", ""):
                org_parts = ipinfo_data["org"].split(" ", 1)
                if len(org_parts) > 0 and org_parts[0].startswith("AS"):
                    if not result.get("asn"):
                        result["asn"] = org_parts[0]
                    if len(org_parts) > 1 and not result.get("as_name"):
                        result["as_name"] = org_parts[1]
            
            # Check for Anycast networks (potential indicator of CDN/infrastructure)
            if ipinfo_data.get("anycast", False):
                if "Anycast Network" not in result["threat"]["threat_types"]:
                    result["threat"]["threat_types"].append("Anycast Network")
        
        # 3. IPData for advanced threat intelligence (if API key available)
        ipdata_info = self.ipdata_provider.get_ip_info(ip)
        if ipdata_info:
            result["ipdata_intelligence"] = ipdata_info
            
            # Process threat data (most comprehensive threat source)
            threat_data = ipdata_info.get("threat", {})
            if threat_data:
                # Process Tor data
                if threat_data.get("is_tor", False):
                    result["threat"]["is_tor"] = True
                    if "Tor" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Tor")
                
                # Process proxy data
                if threat_data.get("is_proxy", False):
                    result["threat"]["is_proxy"] = True
                    if "Proxy" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Proxy")
                
                # Process VPN data
                if threat_data.get("is_vpn", False):
                    result["threat"]["is_vpn"] = True
                    if "VPN" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("VPN")
                
                # Process attack data
                if threat_data.get("is_known_attacker", False):
                    result["threat"]["is_malicious"] = True
                    if "Known Attacker" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Known Attacker")
                
                # Process Spammer data
                if threat_data.get("is_spammer", False):
                    result["threat"]["is_spammer"] = True
                    result["threat"]["is_malicious"] = True
                    if "Spammer" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Spammer")
                
                # Process bogon data (invalid IP space)
                if threat_data.get("is_bogon", False):
                    if "Bogon Network" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Bogon Network")
                        
                # Process datacenter data
                if threat_data.get("is_datacenter", False):
                    result["threat"]["is_datacenter"] = True
                    if "Datacenter/Hosting" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Datacenter/Hosting")
                        
                # Process blacklist data
                if threat_data.get("blocklists", []):
                    blocklists = threat_data.get("blocklists", [])
                    if "Blacklisted" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append(f"Blacklisted ({len(blocklists)} lists)")
        # 4. AbuseIPDB for abuse reports and confidence scores (if API key available)
        abuseipdb_data = self.abuseipdb_provider.get_ip_info(ip)
        if abuseipdb_data:
            # Process AbuseIPDB data here
            report_data = abuseipdb_data.get("data", {})
            if report_data:
                result["abuseipdb_intelligence"] = report_data
                
                # Get abuse confidence score and report counts
                result["threat"]["abuse_confidence_score"] = report_data.get("abuseConfidenceScore")
                result["threat"]["reports_count"] = report_data.get("totalReports")
                result["threat"]["last_reported_at"] = report_data.get("lastReportedAt")
                
                # If confidence score is high, mark as potentially malicious
                if result["threat"]["abuse_confidence_score"] and result["threat"]["abuse_confidence_score"] > 50:
                    result["threat"]["is_malicious"] = True
                    if "Reported Abuse" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("Reported Abuse")
                
                # Process categories from usage type
                usageType = report_data.get("usageType")
                # Uncomment for debugging usageType value
                # print(f"[DEBUG] usageType value: {usageType}, type: {type(usageType)}")
                usage_type = report_data.get("usageType")
                categories = usage_type.lower() if usage_type is not None else ""
                if "vpn" in categories and not result["threat"]["is_vpn"]:
                    result["threat"]["is_vpn"] = True
                    if "VPN" not in result["threat"]["threat_types"]:
                        result["threat"]["threat_types"].append("VPN")

                # Process attack categories from reports
                category_names = {
                    1: "DNS Compromise",
                    2: "DNS Poisoning",
                    3: "Fraud Orders",
                    4: "DDoS Attack",
                    5: "FTP Brute-Force",
                    6: "Ping of Death",
                    7: "Phishing",
                    8: "Fraud VoIP",
                    9: "Open Proxy",
                    10: "Web Spam",
                    11: "Email Spam",
                    12: "Blog Spam",
                    13: "VPN IP",
                    14: "Port Scan",
                    15: "Hacking",
                    16: "SQL Injection",
                    17: "Spoofing",
                    18: "Brute-Force",
                    19: "Bad Web Bot",
                    20: "Exploited Host",
                }
                # Extract and process detailed reports if available
                if report_data.get("reports"):
                    # Store reports for later use
                    result["threat"]["abuse_reports"] = report_data.get("reports")
                    
                    # Process report categories
                    category_counts = {}
                    
                    for report in report_data.get("reports"):
                        # Process categories
                        if report.get("categories"):
                            for cat_id in report.get("categories"):
                                cat_id = int(cat_id)
                                cat_name = category_names.get(cat_id, f"Category {cat_id}")
                                category_counts[cat_name] = category_counts.get(cat_name, 0) + 1
                    
                    if category_counts:
                        # Store category counts
                        result["threat"]["abuse_categories"] = category_counts
                        # Add top categories to attack types
                        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                            result["threat"]["attack_types"].append(f"{cat} ({count})")

# 5. ThreatFox for IOC detection (if API key available)
        threatfox_data = self.threatfox_provider.search_ioc(ip)
        if threatfox_data and threatfox_data.get("query_status") == "ok":
            result["threatfox_intelligence"] = threatfox_data
            
            # Process ThreatFox data
            ioc_data = threatfox_data.get("data", [])
            if ioc_data:
                # Mark as detected in unified intel
                result["unified_intel"]["threatfox"]["detected"] = True
                
                # Extract malware families (ensure uniqueness)
                malware_families = []
                ioc_types = []
                first_seen = None
                
                for ioc in ioc_data:
                    # Extract malware family
                    if ioc.get("malware_printable") and ioc.get("malware_printable") not in malware_families:
                        malware_families.append(ioc.get("malware_printable"))
                    
                    # Extract IOC types
                    if ioc.get("ioc_type") and ioc.get("ioc_type") not in ioc_types:
                        ioc_types.append(ioc.get("ioc_type"))
                    
                    # Track earliest first_seen date
                    if ioc.get("first_seen"):
                        if not first_seen or ioc.get("first_seen") < first_seen:
                            first_seen = ioc.get("first_seen")
                
                # Store in unified intel
                result["unified_intel"]["threatfox"]["malware_families"] = malware_families
                result["unified_intel"]["threatfox"]["ioc_types"] = ioc_types
                result["unified_intel"]["threatfox"]["first_seen"] = first_seen
                # --- Add malware samples extraction ---
                malware_samples = []
                for ioc in ioc_data:
                    if ioc.get("malware_samples"):
                        malware_samples.extend(ioc.get("malware_samples"))
                result["unified_intel"]["threatfox"]["malware_samples"] = malware_samples[:5] # Store up to 5 samples
                # --- End sample extraction ---
                
                # Set confidence based on number of detections (more detections = higher confidence)
                confidence = min(90, 50 + (len(ioc_data) * 10))
                result["unified_intel"]["threatfox"]["confidence"] = confidence
                
                # If ThreatFox detects the IP as IOC, mark it as malicious
                if not result["unified_intel"]["malicious_activity"]["is_malicious"]["detected"]:
                    result["unified_intel"]["malicious_activity"]["is_malicious"] = {
                        "detected": True,
                        "confidence": confidence,
                        "sources": ["threatfox"]
                    }
                else:
                    # Update existing detection
                    result["unified_intel"]["malicious_activity"]["is_malicious"]["confidence"] = max(
                        result["unified_intel"]["malicious_activity"]["is_malicious"]["confidence"],
                        confidence
                    )
                    if "threatfox" not in result["unified_intel"]["malicious_activity"]["is_malicious"]["sources"]:
                        result["unified_intel"]["malicious_activity"]["is_malicious"]["sources"].append("threatfox")

                # Add threat types from ThreatFox
                # Add threat types from ThreatFox
                for family in malware_families:
                    malware_threat_type = f"Malware: {family}"
                    
                    # Check if this threat type already exists in the unified_intel threat_types
                    existing_threats = [t for t in result["unified_intel"]["threat_types"] if t["type"] == malware_threat_type]
                    
                    if not existing_threats:
                        result["unified_intel"]["threat_types"].append({
                            "type": malware_threat_type,
                            "confidence": confidence,
                            "sources": ["threatfox"]
                        })
                        
                    # Add to global threat types list if not already there
                        result["threat"]["threat_types"].append(malware_threat_type)

        # Check for known legitimate services
        known_legitimate_services = ["google", "cloudflare", "microsoft", "amazon", "facebook", "akamai", "fastly"]
        known_ips = {
            "8.8.8.8": ("Google DNS", "high"), "8.8.4.4": ("Google DNS", "high"),
            "1.1.1.1": ("Cloudflare DNS", "high"), "1.0.0.1": ("Cloudflare DNS", "high"),
        } 
        is_legitimate_service = False # Flag
        
        # Check well-known IPs first
        if ip in known_ips:
            is_legitimate_service = True
            service_name, trust_level = known_ips[ip]
            # --- Store data INSIDE this block ---
            result["unified_intel"]["is_legitimate_service"] = {
                "detected": True,
                "service": service_name,
                "trust_level": trust_level,
                "source": "well_known_ip"
            }
        
        # Check hostname if not already found and hostname exists
        elif not is_legitimate_service and result.get("hostname"):
            try:
                hostname_lower = result.get("hostname", "").lower()
                for service in known_legitimate_services:
                    if service in hostname_lower:
                        is_legitimate_service = True
                        service_name = service.title()
                        trust_level = "standard" # Default trust level for hostname matches
                        # --- Store data INSIDE this block ---
                        result["unified_intel"]["is_legitimate_service"] = {
                            "detected": True,
                            "service": service_name,
                            "trust_level": trust_level,
                            "source": "hostname"
                        }
                        break # Stop checking once a match is found
            except Exception as e:
                # Debug print is commented out, keep it that way unless needed
                # print(f"[DEBUG ERROR] Exception in hostname processing: {str(e)}")
                pass
        
        # Check domain if not already found and domain exists
        elif not is_legitimate_service and result.get("domain"):
            try:
                domain_lower = result.get("domain", "").lower()
                for service in known_legitimate_services:
                    if service in domain_lower:
                        is_legitimate_service = True
                        service_name = service.title()
                        trust_level = "standard" # Default trust level for domain matches
                        # --- Store data INSIDE this block ---
                        result["unified_intel"]["is_legitimate_service"] = {
                            "detected": True,
                            "service": service_name,
                            "trust_level": trust_level,
                            "source": "domain"
                        }
                        break # Stop checking once a match is found
            except Exception as e:
                # Debug print is commented out, keep it that way unless needed
                # print(f"[DEBUG ERROR] Exception in domain processing: {str(e)}")
                pass

        # Track which intelligence sources are available
        sources_available = []
        if result.get("ipinfo_intelligence"):
            sources_available.append("ipinfo")
        if result.get("ipdata_intelligence"):
            sources_available.append("ipdata")
        if result.get("abuseipdb_intelligence"):
            sources_available.append("abuseipdb")
        if result.get("threatfox_intelligence"):
            sources_available.append("threatfox")
            
        # Store available sources
        result["unified_intel"]["sources_available"] = sources_available
        
        # 1. CORRELATE PROXY/VPN/TOR DETECTION
        # ----------------------------------
        # IPData is considered most reliable for proxy/VPN/Tor detection
        # Cross-reference with other sources to increase confidence
        
        # Check for proxy detection across sources
        proxy_sources = []
        if result.get("intelligence", {}).get("proxy", False):
            proxy_sources.append("ip-api")
        if result.get("ipdata_intelligence", {}).get("threat", {}).get("is_proxy", False):
            proxy_sources.append("ipdata")
        if "Proxy" in result["threat"]["threat_types"]:
            if "abuseipdb" in sources_available:
                proxy_sources.append("abuseipdb")
                
        # Calculate confidence based on number of sources (IPData is weighted higher)
        proxy_confidence = 0
        if proxy_sources:
            if "ipdata" in proxy_sources:
                proxy_confidence = 70  # Base confidence when IPData detects it
            else:
                proxy_confidence = 50  # Lower confidence with other sources
                
            # Increase confidence based on corroboration
            proxy_confidence += (len(proxy_sources) - 1) * 15
            proxy_confidence = min(proxy_confidence, 100)
            
            # Update unified intelligence
            result["unified_intel"]["anonymity"]["is_proxy"] = {
                "detected": True,
                "confidence": proxy_confidence,
                "sources": proxy_sources
            }
            
        # Check for VPN detection
        vpn_sources = []
        if result.get("ipdata_intelligence", {}).get("threat", {}).get("is_vpn", False):
            vpn_sources.append("ipdata")
        if "VPN" in result["threat"]["threat_types"]:
            if "abuseipdb" in sources_available:
                vpn_sources.append("abuseipdb")
                
        # Calculate VPN confidence
        vpn_confidence = 0
        if vpn_sources:
            if "ipdata" in vpn_sources:
                vpn_confidence = 70  # IPData is most reliable for VPN detection
            else:
                vpn_confidence = 50
                
            vpn_confidence += (len(vpn_sources) - 1) * 15
            vpn_confidence = min(vpn_confidence, 100)
            
            # Update unified intelligence
            result["unified_intel"]["anonymity"]["is_vpn"] = {
                "detected": True,
                "confidence": vpn_confidence,
                "sources": vpn_sources
            }
            
        # Check for Tor detection
        tor_sources = []
        blacklist_contradiction = False

        # Check if the IP is listed on Tor blacklists
        if result.get("blacklist") and result.get("blacklist").get("details"):
            for bl_entry in result["blacklist"]["details"]:
                if bl_entry["blacklist"] == "torexit.dan.me.uk" or bl_entry["blacklist"] == "exitnodes.tor.dnsbl.sectoor.de":
                    if bl_entry["listed"]:
                        tor_sources.append("blacklists")
                    else:
                        # If blacklists specifically checked and found clean, note the contradiction
                        blacklist_contradiction = True

        # Check if IPData thinks it's a Tor node
        if result.get("ipdata_intelligence", {}).get("threat", {}).get("is_tor", False):
            tor_sources.append("ipdata")

        # Check if AbuseIPDB thinks it's a Tor node
        if "Tor" in result["threat"]["threat_types"]:
            if "abuseipdb" in sources_available:
                tor_sources.append("abuseipdb")
                
        # Calculate Tor confidence
        tor_confidence = 0
        if tor_sources:
            # Base confidence depending on source reliability
            if "blacklists" in tor_sources:
                tor_confidence = 90  # Blacklists are very reliable for Tor detection
            elif "ipdata" in tor_sources:
                tor_confidence = 80  # IPData is very reliable for Tor detection
            else:
                tor_confidence = 60  # Other sources less reliable
                
            # Increase confidence when multiple sources agree
            tor_confidence += (len(tor_sources) - 1) * 15
            
            # If blacklists contradict other sources, reduce confidence
            if blacklist_contradiction and "blacklists" not in tor_sources:
                tor_confidence = max(60, tor_confidence - 20)  # Cap reduction but still above 50%
                
            tor_confidence = min(tor_confidence, 100)
            
            # Update unified intelligence
            result["unified_intel"]["anonymity"]["is_tor"] = {
                "detected": True,
                "confidence": tor_confidence,
                "sources": tor_sources
            }
            
        # Check for datacenter detection
        datacenter_sources = []
        if result.get("intelligence", {}).get("hosting", False):
            datacenter_sources.append("ip-api")
        if result.get("ipdata_intelligence", {}).get("threat", {}).get("is_datacenter", False):
            datacenter_sources.append("ipdata")
        if "Datacenter/Hosting" in result["threat"]["threat_types"]:
            if "abuseipdb" in sources_available:
                datacenter_sources.append("abuseipdb")
                
        # Calculate datacenter confidence
        datacenter_confidence = 0
        if datacenter_sources:
            # Base confidence
            datacenter_confidence = 50 + (len(datacenter_sources) * 15)
            datacenter_confidence = min(datacenter_confidence, 100)
            
            # Update unified intelligence
            result["unified_intel"]["anonymity"]["is_datacenter"] = {
                "detected": True,
                "confidence": datacenter_confidence,
                "sources": datacenter_sources
            }
            
        # Overall anonymity service detection
        if any([
            result["unified_intel"]["anonymity"]["is_proxy"]["detected"],
            result["unified_intel"]["anonymity"]["is_vpn"]["detected"],
            result["unified_intel"]["anonymity"]["is_tor"]["detected"]
        ]):
            # Calculate max confidence from the various anonymity services
            anon_confidences = [
                result["unified_intel"]["anonymity"]["is_proxy"]["confidence"] if result["unified_intel"]["anonymity"]["is_proxy"]["detected"] else 0,
                result["unified_intel"]["anonymity"]["is_vpn"]["confidence"] if result["unified_intel"]["anonymity"]["is_vpn"]["detected"] else 0,
                result["unified_intel"]["anonymity"]["is_tor"]["confidence"] if result["unified_intel"]["anonymity"]["is_tor"]["detected"] else 0
            ]
            max_confidence = max(anon_confidences)
            
            # Find sources that contributed to anonymity detection
            anon_sources = set()
            for service in ["is_proxy", "is_vpn", "is_tor"]:
                if result["unified_intel"]["anonymity"][service]["detected"]:
                    anon_sources.update(result["unified_intel"]["anonymity"][service]["sources"])
                    
            result["unified_intel"]["anonymity"]["is_anonymous"] = {
                "detected": True,
                "confidence": max_confidence,
                "sources": list(anon_sources)
            }
        
        # 2. CORRELATE MALICIOUS ACTIVITY DETECTION
        # -------------------------------------
        # AbuseIPDB is considered most reliable for malicious reputation
        # Cross-reference with other sources to increase confidence
        
        # Malicious activity detection
        malicious_sources = []
        malicious_confidence = 0
        
        # AbuseIPDB confidence score is a direct indicator
        if result["threat"]["abuse_confidence_score"] is not None:
            abuse_score = result["threat"]["abuse_confidence_score"]
            if abuse_score > 0:
                malicious_sources.append("abuseipdb")
                malicious_confidence = abuse_score  # Direct mapping of confidence
        
        # IPData malicious activity detection
        if result.get("ipdata_intelligence", {}).get("threat", {}).get("is_known_attacker", False):
            malicious_sources.append("ipdata")
            # If not already set by AbuseIPDB, use a default high confidence
            if malicious_confidence == 0:
                malicious_confidence = 75
        
        # Blacklist presence
        if result["blacklist"]["listed"] > 0:
            malicious_sources.append("blacklists")
            # Adjust confidence based on number of blacklists
            blacklist_confidence = min(result["blacklist"]["listed"] * 20, 100)
            # Take the higher of the confidences
            malicious_confidence = max(malicious_confidence, blacklist_confidence)
            
            # Add blacklist specific information
            result["unified_intel"]["malicious_activity"]["blacklisted"] = {
                "detected": True,
                "confidence": blacklist_confidence,
                "sources": ["blacklists"],
                "details": f"Listed on {result['blacklist']['listed']} blacklists"
            }
        
        # If any source indicates maliciousness, record it
        # If any source indicates maliciousness, record it
        if malicious_sources:
            result["unified_intel"]["malicious_activity"]["is_malicious"] = {
                "detected": True,
                "confidence": malicious_confidence,
                "sources": malicious_sources
            }
            
        # 3. CORRELATE GEOLOCATION AND NETWORK INFORMATION
        # ---------------------------------------
        # Determine which source provides the most reliable geolocation data
        # Generally, IPInfo and IPData provide more reliable geolocation than free IP-API
        # Geolocation data
        if result.get("ipinfo_intelligence"):
            result["unified_intel"]["network_info"]["geolocation"] = {
                "reliability": 80,
                "source": "ipinfo"
            }
        elif result.get("ipdata_intelligence"):
            result["unified_intel"]["network_info"]["geolocation"] = {
                "reliability": 75,
                "source": "ipdata"
            }
        elif result.get("intelligence"):
            result["unified_intel"]["network_info"]["geolocation"] = {
                "reliability": 60,
                "source": "ip-api"
            }
        # ASN information
        if result.get("ipinfo_intelligence") and result.get("ipinfo_intelligence").get("org"):
            result["unified_intel"]["network_info"]["asn_info"] = {
                "reliability": 85,
                "source": "ipinfo"
            }
        elif result.get("ipdata_intelligence") and result.get("ipdata_intelligence").get("asn"):
            result["unified_intel"]["network_info"]["asn_info"] = {
                "reliability": 80,
                "source": "ipdata"
            }
        elif result.get("intelligence") and result.get("intelligence").get("as"):
            result["unified_intel"]["network_info"]["asn_info"] = {
                "reliability": 70,
                "source": "ip-api"
            }
        
        # 4. CALCULATE OVERALL CONFIDENCE IN THE DATA
        # -----------------------------------------
        # More available sources = higher confidence in the assessment
        sources_count = len(result["unified_intel"]["sources_available"])
        base_confidence = 50  # Start with moderate confidence
        
        # Add confidence based on quality of sources
        if "ipdata" in result["unified_intel"]["sources_available"]:
            base_confidence += 15  # IPData provides higher quality threat data
        if "abuseipdb" in result["unified_intel"]["sources_available"]:
            base_confidence += 15  # AbuseIPDB provides high quality reputation data
        if "ipinfo" in result["unified_intel"]["sources_available"]:
            base_confidence += 10  # IPInfo provides good geolocation and network data
            
        # Add confidence based on agreement between sources
        if sources_count > 1:
            # Calculate confidence boost based on how many sources agree on key points
            agreement_factor = 0
            
            # Check anonymity service detection agreement
            if result["unified_intel"]["anonymity"]["is_proxy"]["detected"] or result["unified_intel"]["anonymity"]["is_vpn"]["detected"] or result["unified_intel"]["anonymity"]["is_tor"]["detected"]:
                if len(result["unified_intel"]["anonymity"]["is_anonymous"].get("sources", [])) > 1:
                    agreement_factor += 5 * (len(result["unified_intel"]["anonymity"]["is_anonymous"].get("sources", [])) - 1)
            
            # Check malicious activity agreement
            if result["unified_intel"]["malicious_activity"]["is_malicious"].get("detected", False):
                if len(result["unified_intel"]["malicious_activity"]["is_malicious"].get("sources", [])) > 1:
                    agreement_factor += 7 * (len(result["unified_intel"]["malicious_activity"]["is_malicious"].get("sources", [])) - 1)
            
            base_confidence += min(25, agreement_factor)  # Cap the agreement bonus

        result["unified_intel"]["overall_confidence"] = min(100, base_confidence)

        # Calculate risk assessment
        risk_score = 0
        risk_factors = []
        
        # Factor 1: Legitimacy Check - significant influence on all other factors
        is_legitimate = result["unified_intel"].get("is_legitimate_service", {}).get("detected", False)
        legitimate_service_name = result["unified_intel"].get("is_legitimate_service", {}).get("service", "")
        trust_level = result["unified_intel"].get("is_legitimate_service", {}).get("trust_level", "standard")
        
        # Check for special high-trust IPs like Google DNS
        special_trust_ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]
        is_special_service = result["ip"] in special_trust_ips
        
        # Add a significant negative weight for legitimate services
        if is_legitimate:
            # High trust services get more reduction - especially DNS services
            if is_special_service or trust_level == "high":
                service_reduction = -150  # Stronger reduction for high-trust services
                risk_factors.append((f"[TRUSTED] Known High-Trust Service ({legitimate_service_name})", service_reduction))
            else:
                service_reduction = -80  # Significant reduction for normal legitimate services
                risk_factors.append((f"Known Legitimate Service ({legitimate_service_name})", service_reduction))
            
            risk_score += service_reduction
            
        # Factor 2: Blacklist presence
        if result.get("blacklist", {}).get("listed", 0) > 0:
            listed_count = result["blacklist"]["listed"]
            
            # Apply progressive penalty: first listing is bad, each additional is worse
            if is_legitimate:
                blacklist_score = min(50, 10 + (listed_count * 10))
            else:
                blacklist_score = min(80, 20 + (listed_count * 15))
                
            # Apply confidence adjustment based on unified intelligence
            if result["unified_intel"]["malicious_activity"].get("blacklisted", {}).get("detected", False):
                blacklist_confidence = result["unified_intel"]["malicious_activity"]["blacklisted"]["confidence"] / 100
                blacklist_score = int(blacklist_score * blacklist_confidence)
            
            risk_score += blacklist_score
            risk_factors.append((f"Blacklist Presence ({listed_count} blacklists)", blacklist_score))
            
        # Factor 3: Anonymity services detection
        if result["unified_intel"]["anonymity"]["is_tor"]["detected"]:
            # Tor Exit Node with confidence-based weighting
            base_score = 40 if is_legitimate else 70
            confidence_factor = result["unified_intel"]["anonymity"]["is_tor"]["confidence"] / 100
            score = int(base_score * confidence_factor)
            risk_score += score
            risk_factors.append((f"Tor Exit Node ({int(confidence_factor * 100)}% confidence)", score))
            
        # Factor: ThreatFox IOC Detection
        if result["unified_intel"]["threatfox"]["detected"]:
            # ThreatFox detection is a strong indicator of maliciousness
            base_score = 50 if is_legitimate else 90
            confidence_factor = result["unified_intel"]["threatfox"]["confidence"] / 100
            score = int(base_score * confidence_factor)
            risk_score += score
            
            # Add separate risk factors for each malware family
            for malware in result["unified_intel"]["threatfox"]["malware_families"]:
                risk_factors.append((f"ThreatFox Detection: {malware}", score // len(result["unified_intel"]["threatfox"]["malware_families"])))
            
            # If no malware families were extracted, add a generic risk factor
            if not result["unified_intel"]["threatfox"]["malware_families"]:
                risk_factors.append((f"ThreatFox IOC Detection ({int(confidence_factor * 100)}% confidence)", score))
            
        if result["unified_intel"]["anonymity"]["is_vpn"]["detected"]:
            # VPN with confidence-based weighting
            base_score = 15 if is_legitimate else 30
            confidence_factor = result["unified_intel"]["anonymity"]["is_vpn"]["confidence"] / 100
            score = int(base_score * confidence_factor)
            risk_score += score
            risk_factors.append((f"VPN Service ({int(confidence_factor * 100)}% confidence)", score))
        
        # Factor 4: Reported abuse (from AbuseIPDB)
        if result["threat"]["abuse_confidence_score"] is not None:
            confidence = result["threat"]["abuse_confidence_score"]
            
            # Skip entirely for 0% confidence score
            if confidence == 0:
                abuse_score = 0
            # Special handling for well-known services with reports (likely false positives)
            elif is_legitimate:
                # Even high confidence scores have significantly reduced impact for legitimate services
                if trust_level == "high" and result["ip"] in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]:
                    # Special case for highly-reported legitimate DNS services
                    abuse_score = 0  # Ignore abuse scores for these services
                elif confidence > 90:
                    abuse_score = 15  # Significantly reduced from 80
                elif confidence > 70:
                    abuse_score = 10  # Significantly reduced from 60
                elif confidence > 40:
                    abuse_score = 5   # Significantly reduced from 40
                else:
                    abuse_score = 0   # No points for low confidence scores on legitimate services
            else:
                # Normal weighting - higher confidence means higher risk
                if confidence > 90:
                    abuse_score = 80  # Very high confidence
                elif confidence > 70:
                    abuse_score = 60  # High confidence
                elif confidence > 40:
                    abuse_score = 40  # Medium confidence
                elif confidence > 20:
                    abuse_score = 20  # Low confidence
                else:
                    abuse_score = 0   # No points for very low confidence
            
            # Only add to risk factors if score is non-zero
            if abuse_score > 0:
                risk_score += abuse_score
                risk_factors.append((f"Abuse Confidence Score ({confidence}%)", abuse_score))
                
        # Factor 5: Attack types reported
        if result["threat"]["attack_types"]:
            attack_count = len(result["threat"]["attack_types"])
            
            # More severe attack types get higher weights
            high_severity_attacks = [
                "SQL Injection", "Hacking", "DDoS Attack", "Web App Attack", 
                "FTP Brute-Force", "Brute-Force", "Spoofing", "Phishing"
            ]
            
            high_severity_count = sum(1 for attack in result["threat"]["attack_types"] 
                                     if any(high in attack for high in high_severity_attacks))
            
            # Special case: Google DNS and other high-trust services often get false positives
            if is_special_service or (is_legitimate and trust_level == "high" and result["ip"] in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]):
                # For special trusted services like public DNS, almost completely disregard attack reports
                attack_score = 0  # Ignore attack reports for these special cases - they're nearly always false positives
                risk_factors.append((f"Ignored Reported Attacks (High-Trust Service)", 0))
            elif is_legitimate:
                # Significantly reduce the impact for legitimate services
                attack_score = min(10, 2 + (high_severity_count * 1) + (attack_count * 1))
            else:
                # Normal impact for unknown services
                attack_score = min(75, 15 + (high_severity_count * 15) + (attack_count * 5))
            
            # Only add to risk score if non-zero
            if attack_score > 0:
                risk_score += attack_score
                risk_factors.append((f"Reported Attack Types ({attack_count})", attack_score))
            
        # Factor 6: Spammer detection
        if result["threat"]["is_spammer"]:
            score = 30 if is_legitimate else 60
            risk_score += score
            risk_factors.append(("Spammer Detection", score))
            
        # Factor 7: Datacenter/hosting (slight risk increase)
        if result["threat"]["is_datacenter"]:
            if is_legitimate:
                # No risk added for legitimate datacenter IPs
                score = 0
            else:
                # Minor risk increase for unknown datacenter IPs
                score = 10
                risk_score += score
                risk_factors.append(("Datacenter/Hosting IP", score))
            
        # Ensure risk score is within bounds (0-100)
        risk_score = max(0, min(100, risk_score))
        
        # Determine risk level based on score
        if risk_score < 20:
            risk_level = "Low"
            risk_color = "green"
        elif risk_score < 60:
            risk_level = "Medium"
            risk_color = "yellow"
        else:
            risk_level = "High"
            risk_color = "red"
        
        # Create risk assessment structure
        result["risk"] = {
            "score": risk_score,
            "level": risk_level,
            "color": risk_color,
            "factors": risk_factors
        }

        return result

def generate_threat_summary(result):
    """Generate an executive threat summary with actionable recommendations"""
    risk_level = result.get("risk", {}).get("level", "Low")
    risk_score = result.get("risk", {}).get("score", 0)
    is_legitimate = result["unified_intel"].get("is_legitimate_service", {}).get("detected", False)
    threat_types = result.get("threat", {}).get("threat_types", [])
    malware_detected = [t.replace("Malware: ", "") for t in threat_types if t.startswith("Malware:")]
    is_anon = result["unified_intel"]["anonymity"]["is_anonymous"]["detected"]
    is_tor = result["unified_intel"]["anonymity"]["is_tor"]["detected"]
    # Use the simple blacklist count for summary, not the potentially complex unified_intel one
    blacklist_count = result.get("blacklist", {}).get("listed", 0) 
    abuse_score = result["threat"].get("abuse_confidence_score", 0) if result["threat"].get("abuse_confidence_score") is not None else 0 # Handle None

    summary = f"Overall Assessment: [bold {result.get('risk', {}).get('color', 'green')}]{risk_level} Risk[/] (Score: {risk_score}%)"

    key_findings = []
    if is_legitimate:
        key_findings.append("[green]Identified as a known legitimate service[/]")
    if malware_detected:
        key_findings.append(f"[bold red]Associated Malware:[/bold red] {', '.join(malware_detected)}")
    if is_tor:
        key_findings.append("[bold red]Detected as Tor Exit Node[/]")
    elif is_anon:
         key_findings.append("[yellow]Detected as Anonymity Service (Proxy/VPN)[/]")
    if blacklist_count > 0:
         key_findings.append(f"[yellow]Listed on {blacklist_count} blacklists[/]")
    if abuse_score >= 80 and not is_legitimate:
         key_findings.append("[red]High Abuse Confidence Score[/]")
    elif abuse_score >= 40 and not is_legitimate:
         key_findings.append("[yellow]Moderate Abuse Confidence Score[/]")

    if key_findings:
        summary += "\n\n[bold]Key Findings:[/]"
        for finding in key_findings:
            summary += f"\n  • {finding}"
    else:
         summary += "\n\n[bold green]No significant threats detected.[/]"

    # Recommendation
    if is_legitimate and risk_level == "Low":
        recommendation = "[green]Recommendation: Likely Safe (Known Service)[/]"
    elif risk_level == "High":
         recommendation = "[bold red]Recommendation: High Risk - Investigate/Block[/]"
    elif risk_level == "Medium":
         recommendation = "[yellow]Recommendation: Moderate Risk - Monitor/Investigate[/]"
    else: # Low risk, not legitimate
         recommendation = "[green]Recommendation: Low Risk - Monitor if necessary[/]"
    summary += f"\n\n{recommendation}"

    return summary

def display_results(result):
    """Display the results of IP investigation in the terminal"""
    if not result:
        return

    if RICH_AVAILABLE:
        # --- Add Executive Summary Panel ---
        summary_text = generate_threat_summary(result)
        summary_panel = Panel(summary_text, title="Executive Summary", border_style="green" if result.get("risk", {}).get("level", "Low") == "Low" else "yellow" if result.get("risk", {}).get("level", "Medium") == "Medium" else "red", expand=False)
        console.print(summary_panel)
        # --- End Summary Panel ---
        
        # Create header panel 
        header_panel = Panel(
            f"Target: [bold]{result['target']}[/bold]\n"
            f"IP: [cyan]{result['ip']}[/cyan]"
            + (f"\nHostname: {result.get('hostname', 'N/A')}" if result.get('hostname') else "")
            + (f"\nDomain: {result.get('domain')}" if result.get('domain') else ""),
            title="IP Investigation Results",
            border_style="blue"
        )
        console.print(header_panel)
        
        # Display location and network info if available
        if result.get("intelligence"):
            intel = result["intelligence"]
            location_table = Table(show_header=True, header_style="bold magenta")
            location_table.add_column("Property")
            location_table.add_column("Value")
            # Add TRUSTED SERVICE row when a legitimate service is detected
            is_legitimate = result["unified_intel"].get("is_legitimate_service", {}).get("detected", False)
            service_name = result["unified_intel"].get("is_legitimate_service", {}).get("service", "")
            trust_level = result["unified_intel"].get("is_legitimate_service", {}).get("trust_level", "standard")
            
            if is_legitimate:
                if trust_level == "high":
                    location_table.add_row("[bold]TRUSTED SERVICE[/bold]", f"[bold green]{service_name} (High-Trust)[/bold green]")
                else:
                    location_table.add_row("[bold]LEGITIMATE SERVICE[/bold]", f"[green]{service_name}[/green]")
            location = []
            if intel.get("city"):
                location.append(intel["city"])
            if intel.get("regionName"):
                location.append(intel["regionName"])
            if intel.get("country"):
                location.append(intel["country"])
            
            location_table.add_row("Location", ", ".join(location) if location else "Unknown")
            location_table.add_row("ISP", intel.get("isp", "Unknown"))
            location_table.add_row("Organization", intel.get("org", "Unknown"))
            location_table.add_row("AS", intel.get("as", "Unknown"))
            
            console.print(Panel(location_table, title="Location and Network Information", border_style="cyan"))
        
        # Display Unified Intelligence information
        if result.get("unified_intel"):
            unified_intel = result["unified_intel"]
            
            # Display overall confidence
            overall_confidence = unified_intel.get("overall_confidence", 0)
            confidence_color = "green" if overall_confidence >= 80 else "yellow" if overall_confidence >= 50 else "red"
            
            console.print(Panel(
                f"Overall Confidence: [{confidence_color}]{overall_confidence}%[/{confidence_color}]\n" +
                f"Sources Available: {', '.join(unified_intel.get('sources_available', []))}",
                title="Analysis Confidence",
                border_style="blue"
            ))
            
            # Display anonymity services information
            if any([
                unified_intel["anonymity"]["is_proxy"]["detected"],
                unified_intel["anonymity"]["is_vpn"]["detected"],
                unified_intel["anonymity"]["is_tor"]["detected"],
                unified_intel["anonymity"]["is_datacenter"]["detected"]
            ]):
                anonymity_table = Table(show_header=True, header_style="bold magenta")
                anonymity_table.add_column("Service")
                anonymity_table.add_column("Detected")
                anonymity_table.add_column("Confidence")
                anonymity_table.add_column("Sources")
                
                for service_type in ["is_proxy", "is_vpn", "is_tor", "is_datacenter"]:
                    service_info = unified_intel["anonymity"][service_type]
                    if service_info["detected"]:
                        service_name = service_type.replace("is_", "").title()
                        confidence = service_info["confidence"]
                        conf_color = "red" if confidence >= 80 else "yellow" if confidence >= 50 else "green"
                        sources = ", ".join(service_info["sources"])
                        
                        anonymity_table.add_row(
                            service_name,
                            "[red]Yes[/red]",
                            f"[{conf_color}]{confidence}%[/{conf_color}]",
                            sources
                        )
                    
                if unified_intel["anonymity"]["is_anonymous"]["detected"]:
                    confidence = unified_intel["anonymity"]["is_anonymous"]["confidence"]
                    conf_color = "red" if confidence >= 80 else "yellow" if confidence >= 50 else "green"
                    sources = ", ".join(unified_intel["anonymity"]["is_anonymous"]["sources"])
                    
                    anonymity_table.add_row(
                        "[bold]Overall Anonymity[/bold]",
                        "[bold red]Yes[/bold red]",
                        f"[bold {conf_color}]{confidence}%[/bold {conf_color}]",
                        sources
                    )
                
                console.print(Panel(anonymity_table, title="Anonymity Services Detection", border_style="yellow"))
            
            # Display malicious activity information
            if any([
                unified_intel["malicious_activity"]["is_malicious"]["detected"],
                unified_intel["malicious_activity"]["is_spammer"]["detected"],
                unified_intel["malicious_activity"]["is_attacker"]["detected"],
                unified_intel["malicious_activity"]["blacklisted"]["detected"]
            ]):
                malicious_table = Table(show_header=True, header_style="bold magenta")
                malicious_table.add_column("Type")
                malicious_table.add_column("Detected")
                malicious_table.add_column("Confidence")
                malicious_table.add_column("Sources")
                
                for activity_type in ["is_malicious", "is_spammer", "is_attacker", "blacklisted"]:
                    activity_info = unified_intel["malicious_activity"][activity_type]
                    if activity_info["detected"]:
                        activity_name = activity_type.replace("is_", "").title()
                        confidence = activity_info["confidence"]
                        conf_color = "red" if confidence >= 80 else "yellow" if confidence >= 50 else "green"
                        sources = ", ".join(activity_info["sources"])
                        
                        malicious_table.add_row(
                            activity_name,
                            "[red]Yes[/red]",
                            f"[{conf_color}]{confidence}%[/{conf_color}]",
                            sources
                        )
                
                console.print(Panel(malicious_table, title="Malicious Activity Detection", border_style="red"))
            
            # Display threat types with confidence
            if unified_intel.get("threat_types"):
                threat_table = Table(show_header=True, header_style="bold magenta")
                threat_table.add_column("Threat Type")
                threat_table.add_column("Confidence")
                threat_table.add_column("Sources")
                
                for threat in unified_intel["threat_types"]:
                    threat_type = threat["type"]
                    confidence = threat["confidence"]
                    conf_color = "red" if confidence >= 80 else "yellow" if confidence >= 50 else "green"
                    sources = ", ".join(threat["sources"])
                    
                    threat_table.add_row(
                        threat_type,
                        f"[{conf_color}]{confidence}%[/{conf_color}]",
                        sources
                    )
                
                console.print(Panel(threat_table, title="Detected Threat Types", border_style="red"))

        # Display ThreatFox information if available
        if result["unified_intel"].get("threatfox", {}).get("detected", False):
            threatfox_data = result["unified_intel"]["threatfox"]
            
            # Create ThreatFox table
            threatfox_table = Table(show_header=True, header_style="bold magenta")
            threatfox_table.add_column("Information")
            threatfox_table.add_column("Value")
            
            # Add malware families
            if threatfox_data.get("malware_families"):
                threatfox_table.add_row(
                    "Malware Families", 
                    "[bold red]" + ", ".join(threatfox_data["malware_families"]) + "[/bold red]"
                )
            
            # Add IOC types
            if threatfox_data.get("ioc_types"):
                threatfox_table.add_row(
                    "IOC Types",
                    ", ".join(threatfox_data["ioc_types"])
                )
            
            # Add first seen date
            if threatfox_data.get("first_seen"):
                threatfox_table.add_row(
                    "First Seen",
                    threatfox_data["first_seen"]
                )
            
            # Display confidence
            # Display confidence
            if threatfox_data.get("confidence"):
                confidence = threatfox_data["confidence"]
                conf_color = "red" if confidence >= 80 else "yellow" if confidence >= 50 else "green"
                threatfox_table.add_row(
                    "Confidence",
                    f"[{conf_color}]{confidence}%[/{conf_color}]"
                )
            
            # --- Add Malware Samples Row ---
            if threatfox_data.get("malware_samples"):
                samples_text = []
                for sample in threatfox_data["malware_samples"]:
                    sha256 = sample.get('sha256_hash')
                    link = sample.get('malware_bazaar')
                    if sha256:
                        display_text = f"{sha256[:12]}..."
                        if link:
                           samples_text.append(f"[link={link}]{display_text}[/link]")
                        else:
                           samples_text.append(display_text)
                if samples_text:
                     threatfox_table.add_row("Malware Samples", "\n".join(samples_text))
            # --- End Malware Samples Row ---

            # Display the ThreatFox panel
            console.print(Panel(threatfox_table, title="ThreatFox IOC Intelligence", border_style="red"))

        # --- Add MITRE ATT&CK Information Display ---
            detected_malware = result["unified_intel"]["threatfox"].get("malware_families", [])
            for malware_name in detected_malware:
                if malware_name in MITRE_MAPPINGS:
                    mapping = MITRE_MAPPINGS[malware_name]
                    mitre_table = Table(show_header=False, box=None, padding=(0, 1))
                    mitre_table.add_column("Field", style="bold cyan")
                    mitre_table.add_column("Details")

                    mitre_table.add_row("Description", mapping.get("description", "N/A"))
                    mitre_table.add_row("Tactics", ", ".join(mapping.get("tactics", [])))
                    mitre_table.add_row("Techniques", ", ".join(mapping.get("techniques", [])))
                    mitre_table.add_row("Infection Vectors", ", ".join(mapping.get("infection_vectors", [])))
                    mitre_table.add_row("Post-Compromise", ", ".join(mapping.get("post_compromise", [])))

                    console.print(Panel(
                        mitre_table,
                        title=f"MITRE ATT&CK Info for {malware_name}",
                        border_style="yellow",
                        expand=False
                    ))
        # --- End of MITRE ATT&CK Display ---
            
        # Display AbuseIPDB information if available
        if result.get("abuseipdb_intelligence"):
            abuse_data = result["abuseipdb_intelligence"]
            
            # Create AbuseIPDB table
            abuse_table = Table(show_header=True, header_style="bold magenta")
            abuse_table.add_column("Information")
            
            # Add basic abuse information
            confidence_score = abuse_data.get("abuseConfidenceScore", 0)
            reports_count = abuse_data.get("totalReports", 0)
            
            # Create visual confidence meter
            meter_length = 20
            if confidence_score > 0:
                filled_blocks = min(meter_length, int((confidence_score / 100) * meter_length))
                if confidence_score >= 80:
                    meter = f"[red]{'█' * filled_blocks}{'░' * (meter_length - filled_blocks)}[/red]"
                elif confidence_score >= 40:
                    meter = f"[yellow]{'█' * filled_blocks}{'░' * (meter_length - filled_blocks)}[/yellow]"
                else:
                    meter = f"[green]{'█' * filled_blocks}{'░' * (meter_length - filled_blocks)}[/green]"
                confidence_str = f"{confidence_score}% {meter}"
            else:
                confidence_str = "0% (No reports)"
            
            abuse_table.add_row("Abuse Confidence Score", confidence_str)
            abuse_table.add_row("Total Reports", str(reports_count))
            
            # Add last reported date if available
            if abuse_data.get("lastReportedAt"):
                try:
                    last_reported = datetime.fromisoformat(abuse_data["lastReportedAt"].replace('Z', '+00:00'))
                    last_reported_str = last_reported.strftime("%Y-%m-%d %H:%M:%S UTC")
                    abuse_table.add_row("Last Reported", last_reported_str)
                except ValueError:
                    abuse_table.add_row("Last Reported", abuse_data["lastReportedAt"])
            
            # Add attack types if available
            if result["threat"]["attack_types"]:
                attack_types_str = ", ".join(result["threat"]["attack_types"])
                abuse_table.add_row("Reported Attack Types", attack_types_str)
                
                # Add details for high severity attacks
                high_severity_attacks = ["SQL Injection", "Hacking", "DDoS Attack", "Web App Attack", 
                                        "FTP Brute-Force", "Brute-Force", "Spoofing", "Phishing"]
                high_severity = [attack for attack in result["threat"]["attack_types"] 
                                 if any(high in attack for high in high_severity_attacks)]
                if high_severity:
                    abuse_table.add_row("High Severity Attacks", "[bold red]" + ", ".join(high_severity) + "[/bold red]")
            
            # Display IP usage type if available
            if abuse_data.get("usageType"):
                abuse_table.add_row("Usage Type", abuse_data["usageType"])
                
            # Show domain if available
            if abuse_data.get("domain"):
                abuse_table.add_row("Domain", abuse_data["domain"])
                
            # Display the AbuseIPDB panel
            console.print(Panel(abuse_table, title="AbuseIPDB Intelligence", border_style="red"))
        
        # Display blacklist results
        if result.get("blacklist"):
            bl_results = result["blacklist"]
            
            blacklist_table = Table(show_header=True, header_style="bold magenta")
            blacklist_table.add_column("Blacklist")
            blacklist_table.add_column("Category")
            blacklist_table.add_column("Status")
            
            for item in bl_results["details"]:
                status_text = f"[red]LISTED[/red]" if item["listed"] else f"[green]CLEAN[/green]"
                blacklist_table.add_row(
                    item["blacklist"],
                    item["category"],
                    status_text
                )
            
            trust_color = bl_results["trust_color"]
            trust_text = f"[{trust_color}]{bl_results['trust_level']}[/{trust_color}] (Score: {bl_results['trust_score']}%)"
            
            # First print the summary panel
            console.print(Panel(
                f"Listed on [bold red]{bl_results['listed']}[/bold red] out of {bl_results['total']} blacklists\n"
                f"Trust Assessment: {trust_text}",
                title="Blacklist Results",
                border_style="yellow"
            ))
            
            # Then print the blacklist table separately
            console.print(blacklist_table)
        
        # Display risk assessment
        if result.get("risk"):
            risk = result["risk"]
            risk_color = risk["color"]
            
            risk_table = Table(show_header=True, header_style="bold")
            risk_table.add_column("Risk Factor")
            risk_table.add_column("Weight")
            
            for factor, weight in risk.get("factors", []):
                risk_table.add_row(factor, str(weight))
            
            # First print the risk level panel
            console.print(Panel(
                f"Risk Level: [{risk_color}]{risk['level']}[/{risk_color}] (Score: {risk['score']}%)",
                title="Risk Assessment",
                border_style=risk_color
            ))
            
            # Then print either the risk table or "No specific risk factors" message
            if risk.get("factors"):
                console.print(risk_table)
            else:
                console.print("No specific risk factors identified.")
    else: # Paired with if RICH_AVAILABLE
        # Non-rich display using ANSI colors
        # --- Add Executive Summary (Non-Rich) ---
        summary_text_plain = generate_threat_summary(result) 
        # Basic print, remove rich tags if necessary (simple approach here)
        summary_text_plain = summary_text_plain.replace("[bold]", Colors.BOLD).replace("[/bold]", Colors.RESET).replace("[/]", Colors.RESET)
        summary_text_plain = summary_text_plain.replace("[red]", Colors.RED).replace("[green]", Colors.GREEN).replace("[yellow]", Colors.YELLOW).replace("[cyan]", Colors.CYAN)
        
        risk_color = Colors.GREEN if result.get("risk", {}).get("level", "Low") == "Low" else Colors.YELLOW if result.get("risk", {}).get("level", "Medium") == "Medium" else Colors.RED
        print("\n" + "=" * 60)
        print(f"{Colors.BOLD}{risk_color}EXECUTIVE SUMMARY{Colors.RESET}")
        print("=" * 60)
        print(summary_text_plain)
        # --- End Summary ---

        print("\n" + "=" * 60) # Separator before main results
        print(f"{Colors.BOLD}IP INVESTIGATION RESULTS{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Target:{Colors.RESET} {result['target']}")
        print(f"{Colors.BOLD}IP:{Colors.RESET} {Colors.CYAN}{result['ip']}{Colors.RESET}")
        
        if result.get('hostname'):
            print(f"{Colors.BOLD}Hostname:{Colors.RESET} {result['hostname']}")
            
        if result.get('domain'):
            print(f"{Colors.BOLD}Domain:{Colors.RESET} {result['domain']}")
            
        # Display location and network info if available
        if result.get("intelligence"):
            intel = result["intelligence"]
            print("\n" + "-" * 60)
            print(f"{Colors.BOLD}{Colors.CYAN}LOCATION AND NETWORK INFORMATION{Colors.RESET}")
            print("-" * 60)
            
            location = []
            if intel.get("city"):
                location.append(intel["city"])
            if intel.get("regionName"):
                location.append(intel["regionName"])
            if intel.get("country"):
                location.append(intel["country"])
                
            # Display TRUSTED SERVICE when a legitimate service is detected
            is_legitimate = result["unified_intel"].get("is_legitimate_service", {}).get("detected", False)
            service_name = result["unified_intel"].get("is_legitimate_service", {}).get("service", "")
            trust_level = result["unified_intel"].get("is_legitimate_service", {}).get("trust_level", "standard")
            
            if is_legitimate:
                if trust_level == "high":
                    print(f"{Colors.BOLD}TRUSTED SERVICE:{Colors.RESET} {Colors.GREEN}{Colors.BOLD}{service_name} (High-Trust){Colors.RESET}")
                    print("-" * 60)
                else:
                    print(f"{Colors.BOLD}LEGITIMATE SERVICE:{Colors.RESET} {Colors.GREEN}{service_name}{Colors.RESET}")
                    print("-" * 60)
                
            print(f"{Colors.BOLD}Location:{Colors.RESET} {', '.join(location) if location else 'Unknown'}")
            print(f"{Colors.BOLD}ISP:{Colors.RESET} {intel.get('isp', 'Unknown')}")
            print(f"{Colors.BOLD}Organization:{Colors.RESET} {intel.get('org', 'Unknown')}")
            print(f"{Colors.BOLD}AS:{Colors.RESET} {intel.get('as', 'Unknown')}")

        # Display Unified Intelligence information
        if result.get("unified_intel"):
            unified_intel = result["unified_intel"]
            
            print("\n" + "-" * 60)
            print(f"{Colors.BOLD}{Colors.BLUE}ANALYSIS CONFIDENCE{Colors.RESET}")
            print("-" * 60)
            
            # Display overall confidence
            overall_confidence = unified_intel.get("overall_confidence", 0)
            if overall_confidence >= 80:
                conf_color = Colors.GREEN
            elif overall_confidence >= 50:
                conf_color = Colors.YELLOW
            else:
                conf_color = Colors.RED
                
            print(f"{Colors.BOLD}Overall Confidence:{Colors.RESET} {conf_color}{overall_confidence}%{Colors.RESET}")
            print(f"{Colors.BOLD}Sources Available:{Colors.RESET} {', '.join(unified_intel.get('sources_available', []))}")
            
            # Display anonymity services information
            if any([
                unified_intel["anonymity"]["is_proxy"]["detected"],
                unified_intel["anonymity"]["is_vpn"]["detected"],
                unified_intel["anonymity"]["is_tor"]["detected"],
                unified_intel["anonymity"]["is_datacenter"]["detected"]
            ]):
                print("\n" + "-" * 60)
                print(f"{Colors.BOLD}{Colors.YELLOW}ANONYMITY SERVICES DETECTION{Colors.RESET}")
                print("-" * 60)
                
                print(f"{'Service':<15} {'Detected':<10} {'Confidence':<15} {'Sources'}")
                print("-" * 60)
                
                for service_type in ["is_proxy", "is_vpn", "is_tor", "is_datacenter"]:
                    service_info = unified_intel["anonymity"][service_type]
                    if service_info["detected"]:
                        service_name = service_type.replace("is_", "").title()
                        confidence = service_info["confidence"]
                        if confidence >= 80:
                            conf_color = Colors.RED
                        elif confidence >= 50:
                            conf_color = Colors.YELLOW
                        else:
                            conf_color = Colors.GREEN
                            
                        sources = ", ".join(service_info["sources"])
                        
                        print(f"{service_name:<15} {Colors.RED}Yes{Colors.RESET:<5} {conf_color}{confidence}%{Colors.RESET:<9} {sources}")
                
                if unified_intel["anonymity"]["is_anonymous"]["detected"]:
                    confidence = unified_intel["anonymity"]["is_anonymous"]["confidence"]
                    if confidence >= 80:
                        conf_color = Colors.RED
                    elif confidence >= 50:
                        conf_color = Colors.YELLOW
                    else:
                        conf_color = Colors.GREEN
                        
                    sources = ", ".join(unified_intel["anonymity"]["is_anonymous"]["sources"])
                    
                    print(f"{Colors.BOLD}Overall Anonymity{Colors.RESET:<6} {Colors.RED}{Colors.BOLD}Yes{Colors.RESET:<5} {conf_color}{Colors.BOLD}{confidence}%{Colors.RESET:<9} {sources}")
            
            # Display malicious activity information
            if any([
                unified_intel["malicious_activity"]["is_malicious"]["detected"],
                unified_intel["malicious_activity"]["is_spammer"]["detected"],
                unified_intel["malicious_activity"]["is_attacker"]["detected"],
                unified_intel["malicious_activity"]["blacklisted"]["detected"]
            ]):
                print("\n" + "-" * 60)
                print(f"{Colors.BOLD}{Colors.RED}MALICIOUS ACTIVITY DETECTION{Colors.RESET}")
                print("-" * 60)
                
                print(f"{'Type':<15} {'Detected':<10} {'Confidence':<15} {'Sources'}")
                print("-" * 60)
                
                for activity_type in ["is_malicious", "is_spammer", "is_attacker", "blacklisted"]:
                    activity_info = unified_intel["malicious_activity"][activity_type]
                    if activity_info["detected"]:
                        activity_name = activity_type.replace("is_", "").title()
                        confidence = activity_info["confidence"]
                        if confidence >= 80:
                            conf_color = Colors.RED
                        elif confidence >= 50:
                            conf_color = Colors.YELLOW
                        else:
                            conf_color = Colors.GREEN
                            
                        sources = ", ".join(activity_info["sources"])
                        
                        print(f"{activity_name:<15} {Colors.RED}Yes{Colors.RESET:<5} {conf_color}{confidence}%{Colors.RESET:<9} {sources}")
            
            # Display threat types with confidence
            if unified_intel.get("threat_types"):
                print("\n" + "-" * 60)
                print(f"{Colors.BOLD}{Colors.RED}DETECTED THREAT TYPES{Colors.RESET}")
                print("-" * 60)
                
                print(f"{'Threat Type':<25} {'Confidence':<15} {'Sources'}")
                print("-" * 60)
                
                for threat in unified_intel["threat_types"]:
                    threat_type = threat["type"]
                    confidence = threat["confidence"]
                    if confidence >= 80:
                        conf_color = Colors.RED
                    elif confidence >= 50:
                        conf_color = Colors.YELLOW
                    else:
                        conf_color = Colors.GREEN
                        
                    sources = ", ".join(threat["sources"])
                    print(f"{threat_type:<25} {conf_color}{confidence}%{Colors.RESET:<9} {sources}")

        # Display ThreatFox Info (Non-Rich)
        if result["unified_intel"].get("threatfox", {}).get("detected", False):
            threatfox_data = result["unified_intel"]["threatfox"]
            print("\n" + "-" * 60)
            print(f"{Colors.BOLD}{Colors.RED}THREATFOX IOC INTELLIGENCE{Colors.RESET}")
            print("-" * 60)
            if threatfox_data.get("malware_families"):
                print(f"{Colors.BOLD}Malware Families:{Colors.RESET} {Colors.RED}{', '.join(threatfox_data['malware_families'])}{Colors.RESET}")
            if threatfox_data.get("ioc_types"):
                print(f"{Colors.BOLD}IOC Types:{Colors.RESET} {', '.join(threatfox_data['ioc_types'])}")
            if threatfox_data.get("first_seen"):
                print(f"{Colors.BOLD}First Seen:{Colors.RESET} {threatfox_data['first_seen']}")
            if threatfox_data.get("confidence"):
                confidence = threatfox_data["confidence"]
                conf_color = Colors.RED if confidence >= 80 else Colors.YELLOW if confidence >= 50 else Colors.GREEN
                print(f"{Colors.BOLD}Confidence:{Colors.RESET} {conf_color}{confidence}%{Colors.RESET}")
            
            # --- Add Malware Samples Row (Non-Rich) ---
            if threatfox_data.get("malware_samples"):
                print(f"{Colors.BOLD}Malware Samples:{Colors.RESET}")
                for sample in threatfox_data["malware_samples"]:
                    sha256 = sample.get('sha256_hash')
                    link = sample.get('malware_bazaar')
                    if sha256:
                        print(f"  • SHA256: {sha256}" + (f" (See: {link})" if link else ""))
            # --- End Malware Samples Row ---

        # --- Add MITRE ATT&CK Information Display (Non-Rich) ---
        if result["unified_intel"].get("threatfox", {}).get("detected", False):
            detected_malware = result["unified_intel"]["threatfox"].get("malware_families", [])
            for malware_name in detected_malware:
                if malware_name in MITRE_MAPPINGS:
                    mapping = MITRE_MAPPINGS[malware_name]
                    print("\n" + "-" * 60)
                    print(f"{Colors.BOLD}{Colors.YELLOW}MITRE ATT&CK Info for {malware_name}{Colors.RESET}")
                    print("-" * 60)
                    print(f"{Colors.BOLD}Description:{Colors.RESET} {mapping.get('description', 'N/A')}")
                    print(f"{Colors.BOLD}Tactics:{Colors.RESET} {', '.join(mapping.get('tactics', []))}")
                    print(f"{Colors.BOLD}Techniques:{Colors.RESET} {', '.join(mapping.get('techniques', []))}")
                    print(f"{Colors.BOLD}Infection Vectors:{Colors.RESET} {', '.join(mapping.get('infection_vectors', []))}")
                    print(f"{Colors.BOLD}Post-Compromise:{Colors.RESET} {', '.join(mapping.get('post_compromise', []))}")
        # --- End of MITRE ATT&CK Display ---

        # Display AbuseIPDB information if available
        if result.get("abuseipdb_intelligence") and result["threat"].get("abuse_confidence_score") is not None:
            print("\n" + "-" * 60)
            print(f"{Colors.BOLD}{Colors.RED}ABUSEIPDB INTELLIGENCE{Colors.RESET}")
            print("-" * 60)
            
            confidence_score = result["threat"]["abuse_confidence_score"]
            reports_count = result["threat"]["reports_count"] or 0
            
            # Display confidence score with a visual indicator
            if confidence_score > 80:
                score_color = Colors.RED
            elif confidence_score > 40:
                score_color = Colors.YELLOW
            else:
                score_color = Colors.GREEN
                
            print(f"{Colors.BOLD}Abuse Confidence Score:{Colors.RESET} {score_color}{confidence_score}%{Colors.RESET}")
            print(f"{Colors.BOLD}Total Reports:{Colors.RESET} {reports_count}")
            
            # Last reported date
            if result["threat"].get("last_reported_at"):
                try:
                    last_reported = datetime.fromisoformat(result["threat"]["last_reported_at"].replace('Z', '+00:00'))
                    last_reported_str = last_reported.strftime("%Y-%m-%d %H:%M:%S UTC")
                    print(f"{Colors.BOLD}Last Reported:{Colors.RESET} {last_reported_str}")
                except:
                    print(f"{Colors.BOLD}Last Reported:{Colors.RESET} {result['threat']['last_reported_at']}")
            
            # Attack types
            if result["threat"]["attack_types"]:
                print(f"\n{Colors.BOLD}Reported Attack Types:{Colors.RESET}")
                for attack in result["threat"]["attack_types"]:
                    # Highlight high severity attacks
                    high_severity = ["SQL Injection", "Hacking", "DDoS", "Brute-Force", "Phishing"]
                    if any(h in attack for h in high_severity):
                        print(f"  • {Colors.RED}{attack}{Colors.RESET}")
                    else:
                        print(f"  • {attack}")

        # Display blacklist results
        if result.get("blacklist"):
            bl_results = result["blacklist"]
            
            print("\n" + "-" * 60)
            print(f"{Colors.BOLD}{Colors.YELLOW}BLACKLIST RESULTS{Colors.RESET}")
            print("-" * 60)
            
            print(f"Listed on {Colors.RED}{bl_results['listed']}{Colors.RESET} out of {bl_results['total']} blacklists")
            
            if bl_results["trust_color"] == "green":
                trust_color = Colors.GREEN
            elif bl_results["trust_color"] == "yellow":
                trust_color = Colors.YELLOW
            else:
                trust_color = Colors.RED
                
            print(f"Trust Assessment: {trust_color}{bl_results['trust_level']}{Colors.RESET} (Score: {bl_results['trust_score']}%)")
            
            print("\n" + f"{'Blacklist':<25} {'Category':<15} {'Status':<10}")
            print("-" * 60)
            
            for item in bl_results["details"]:
                status_text = f"{Colors.RED}LISTED{Colors.RESET}" if item["listed"] else f"{Colors.GREEN}CLEAN{Colors.RESET}"
                print(f"{item['blacklist']:<25} {item['category']:<15} {status_text}")

        # Display risk assessment
        if result.get("risk"):
            risk = result["risk"]
            
            print("\n" + "-" * 60)
            print(f"{Colors.BOLD}RISK ASSESSMENT{Colors.RESET}")
            print("-" * 60)
            
            # Set risk color based on risk level
            if risk["color"] == "green":
                risk_color = Colors.GREEN
            elif risk["color"] == "yellow":
                risk_color = Colors.YELLOW
            else:
                risk_color = Colors.RED
                
            print(f"Risk Level: {risk_color}{risk['level']}{Colors.RESET} (Score: {risk['score']}%)")
            
            if risk.get("factors"):
                print("\n" + f"{'Risk Factor':<30} {'Weight':<10}")
                print("-" * 60)
                
                for factor, weight in risk["factors"]:
                    print(f"{factor:<30} {weight:<10}")
            else:
                print("\nNo specific risk factors identified.")
                
        print("\n" + "=" * 60 + "\n")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="IP/Domain Investigator - A tool for checking IPs and domains against blacklists and gathering intelligence"
    )
    parser.add_argument(
        "target", 
        help="IP address or domain to investigate"
    )
    parser.add_argument(
        "-t", "--timeout", 
        type=int, 
        default=10, 
        help="Timeout for network operations in seconds (default: 10)"
    )
    parser.add_argument(
        "-f", "--full", 
        action="store_true", 
        help="Check against the full set of 70+ blacklists (slower but more comprehensive)"
    )
    parser.add_argument(
        "-o", "--output", 
        choices=["terminal", "json"], 
        default="terminal", 
        help="Output format (default: terminal)"
    )
    parser.add_argument(
        "-j", "--json-file", 
        help="File to save JSON output (default: ip_report_<target>_<timestamp>.json)"
    )
    
    # Add API key information to help epilog
    parser.epilog = """
Environment Variables for API Integration:
  ABUSEIPDB_API_KEY    API key for AbuseIPDB (abuse reports and confidence scores)
  IPINFO_API_KEY       API key for IPInfo (enhanced geolocation data)
  IPDATA_API_KEY       API key for IPData (advanced threat intelligence)
  PHISHTANK_API_KEY    API key for PhishTank (URL phishing checks)

Note: The tool works without API keys but provides more detailed results when they are set.
"""
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    
    return parser.parse_args()
def main():
    """Main function to orchestrate the tool's operation"""
    args = parse_args()
    
    # Display the banner
    print_banner()
    
    # Configure the intelligence service with command-line arguments
    intel_service = IPIntelligence(
        timeout=args.timeout,
        check_all_blacklists=args.full
    )
    
    if args.full:
        log_info("Using full blacklist set (70+ blacklists)")
    
    try:
        # Check if target is an IP or domain
        result = intel_service.check_target(args.target)
        
        if not result:
            log_error(f"Failed to analyze target: {args.target}")
            return 1
        
        # Display or save results based on output format
        if args.output == "terminal":
            display_results(result)
        elif args.output == "json":
            # Generate filename if not provided
            if not args.json_file:
                timestamp = int(time.time())
                filename = f"ip_report_{args.target}_{timestamp}.json"
            else:
                filename = args.json_file
                
            # Save to JSON file
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
                log_success(f"Results saved to {filename}")
        
        # Return code based on risk level
        risk_level = result.get("risk", {}).get("level", "Low")
        if risk_level == "High":
            log_info("Returning exit code 2 (High Risk)")
            return 2  # High risk
        elif risk_level == "Medium":
            log_info("Returning exit code 1 (Medium Risk)")
            return 1  # Medium risk
        else:
            log_info("Returning exit code 0 (Low Risk)")
            return 0  # Low risk (success)
            
    except KeyboardInterrupt:
        log_warning("\nOperation cancelled by user")
        return 130
    except Exception as e:
        import traceback
        error_info = traceback.format_exc()
        print(f"[DEBUG ERROR] Full traceback: {error_info}")
        log_error(f"An unexpected error occurred: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
