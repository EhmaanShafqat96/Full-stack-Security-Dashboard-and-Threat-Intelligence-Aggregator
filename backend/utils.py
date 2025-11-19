import requests
import json
import time

# -----------------------------
# AbuseIPDB
# -----------------------------
def check_abuseipdb(ip, api_key):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key, 
            "Accept": "application/json",
            "User-Agent": "Security-Dashboard/1.0"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code != 200:
            return {
                "source": "AbuseIPDB",
                "value": ip,
                "severity": 0,
                "details": {
                    "error": f"API returned status code: {response.status_code}",
                    "totalReports": 0,
                    "country": "Unknown"
                }
            }
        
        data = response.json()
        
        if "data" not in data:
            return {
                "source": "AbuseIPDB", 
                "value": ip,
                "severity": 0,
                "details": {
                    "error": "No data in response",
                    "totalReports": 0,
                    "country": "Unknown"
                }
            }
            
        abuse_data = data["data"]
        
        # Extract information with proper error handling
        abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        total_reports = abuse_data.get("totalReports", 0)
        country = abuse_data.get("countryCode", "Unknown")
        last_reported = abuse_data.get("lastReportedAt", "Never")
        
        # Calculate severity based on abuse score
        if abuse_score >= 80:
            severity = 2  # High
        elif abuse_score >= 30:
            severity = 1  # Medium
        else:
            severity = 0  # Low
            
        return {
            "source": "AbuseIPDB",
            "value": ip,
            "severity": severity,
            "abuseConfidenceScore": abuse_score,
            "details": {
                "country": country,
                "totalReports": total_reports,
                "lastReported": last_reported,
                "domain": abuse_data.get("domain", "Unknown"),
                "isPublic": abuse_data.get("isPublic", False),
                "isWhitelisted": abuse_data.get("isWhitelisted", False),
                "usageType": abuse_data.get("usageType", "Unknown")
            }
        }
        
    except requests.exceptions.Timeout:
        return {
            "source": "AbuseIPDB",
            "value": ip,
            "severity": 0,
            "details": {
                "error": "Request timeout",
                "totalReports": 0,
                "country": "Unknown"
            }
        }
    except requests.exceptions.RequestException as e:
        return {
            "source": "AbuseIPDB",
            "value": ip,
            "severity": 0,
            "details": {
                "error": f"Request failed: {str(e)}",
                "totalReports": 0,
                "country": "Unknown"
            }
        }
    except Exception as e:
        return {
            "source": "AbuseIPDB",
            "value": ip,
            "severity": 0,
            "details": {
                "error": f"Unexpected error: {str(e)}",
                "totalReports": 0,
                "country": "Unknown"
            }
        }

# -----------------------------
# Shodan
# -----------------------------
def check_shodan(ip, api_key):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        headers = {
            "User-Agent": "Security-Dashboard/1.0"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            # IP not found in Shodan database
            return {
                "source": "Shodan",
                "value": ip,
                "status": "not_found",
                "message": "IP not found in Shodan database"
            }
        elif response.status_code != 200:
            return {
                "source": "Shodan",
                "value": ip,
                "status": "error",
                "error": f"API returned status code: {response.status_code}",
                "message": response.json().get('error', 'Unknown error')
            }
        
        data = response.json()
        
        # Extract relevant information
        open_ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        organization = data.get("org", "Unknown")
        operating_system = data.get("os", "Unknown")
        country = data.get("country_name", "Unknown")
        
        # Calculate Shodan severity based on open ports
        # Common risky ports: 22(SSH), 23(Telnet), 135, 139, 445(SMB), 3389(RDP)
        risky_ports = {21, 22, 23, 135, 139, 1433, 1434, 3306, 3389, 5432, 5900, 6379}
        found_risky_ports = [port for port in open_ports if port in risky_ports]
        
        if len(found_risky_ports) > 2:
            severity = 2  # High
        elif len(found_risky_ports) > 0:
            severity = 1  # Medium
        else:
            severity = 0  # Low
            
        return {
            "source": "Shodan",
            "value": ip,
            "severity": severity,
            "open_ports": open_ports,
            "risky_ports": found_risky_ports,
            "hostnames": hostnames,
            "organization": organization,
            "os": operating_system,
            "country": country,
            "last_update": data.get("last_update", "Unknown"),
            "vulns": data.get("vulns", [])
        }
        
    except requests.exceptions.Timeout:
        return {
            "source": "Shodan",
            "value": ip,
            "status": "timeout",
            "error": "Request timeout",
            "severity": 0
        }
    except requests.exceptions.RequestException as e:
        return {
            "source": "Shodan",
            "value": ip,
            "status": "error",
            "error": f"Request failed: {str(e)}",
            "severity": 0
        }
    except Exception as e:
        return {
            "source": "Shodan",
            "value": ip,
            "status": "error",
            "error": f"Unexpected error: {str(e)}",
            "severity": 0
        }

# -----------------------------
# VirusTotal API
# -----------------------------
def check_virustotal(ip, api_key):
    """
    Check IP reputation with VirusTotal
    """
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": api_key,
            "User-Agent": "Security-Dashboard/1.0"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded"}
        elif response.status_code == 404:
            return {"error": "IP not found in VirusTotal database"}
        elif response.status_code != 200:
            return {"error": f"VirusTotal API error: {response.status_code}"}
        
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        
        # Calculate threat score
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        total = sum(last_analysis_stats.values())
        
        threat_score = 0
        if total > 0:
            threat_score = min(100, ((malicious * 2) + suspicious) * 100 / total)
        
        return {
            "source": "VirusTotal",
            "value": ip,
            "threat_score": threat_score,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "details": {
                "country": attributes.get("country", "Unknown"),
                "as_owner": attributes.get("as_owner", "Unknown"),
                "reputation": attributes.get("reputation", 0),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "network": attributes.get("network", "Unknown")
            }
        }
        
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timeout"}
    except Exception as e:
        return {"error": f"VirusTotal error: {str(e)}"}

# -----------------------------
# AlienVault OTX API
# -----------------------------
def check_alienvault(ip, api_key):
    """
    Check IP reputation with AlienVault OTX
    """
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {
            "X-OTX-API-KEY": api_key,
            "User-Agent": "Security-Dashboard/1.0"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 429:
            return {"error": "AlienVault rate limit exceeded"}
        elif response.status_code == 404:
            return {"error": "IP not found in AlienVault database"}
        elif response.status_code != 200:
            return {"error": f"AlienVault API error: {response.status_code}"}
        
        data = response.json()
        
        # Calculate pulse count (threat indicators)
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        
        # Calculate threat level based on pulses
        if pulse_count > 20:
            severity = 2  # High
        elif pulse_count > 5:
            severity = 1  # Medium
        else:
            severity = 0  # Low
            
        return {
            "source": "AlienVault OTX",
            "value": ip,
            "severity": severity,
            "pulse_count": pulse_count,
            "details": {
                "country_name": data.get("country_name", "Unknown"),
                "asn": data.get("asn", "Unknown"),
                "reputation": data.get("reputation", 0),
                "pulses": [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
            }
        }
        
    except requests.exceptions.Timeout:
        return {"error": "AlienVault request timeout"}
    except Exception as e:
        return {"error": f"AlienVault error: {str(e)}"}

# -----------------------------
# Enhanced IP Check Function
# -----------------------------
def enhanced_ip_check(ip, abuseipdb_key, shodan_key, virustotal_key, alienvault_key):
    """
    Check IP against all threat intelligence sources
    """
    results = {}
    
    # Existing APIs
    results["abuseipdb"] = check_abuseipdb(ip, abuseipdb_key)
    results["shodan"] = check_shodan(ip, shodan_key)
    
    # New APIs
    if virustotal_key:
        results["virustotal"] = check_virustotal(ip, virustotal_key)
    
    if alienvault_key:
        results["alienvault"] = check_alienvault(ip, alienvault_key)
    
    # Calculate overall threat assessment
    threat_scores = []
    severities = []
    
    for source, result in results.items():
        if result and "error" not in result:
            if "threat_score" in result:
                threat_scores.append(result["threat_score"])
            if "severity" in result:
                severities.append(result["severity"])
            if "abuseConfidenceScore" in result:
                threat_scores.append(result["abuseConfidenceScore"])
    
    overall_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0
    overall_severity = max(severities) if severities else 0
    
    # Determine threat level
    if overall_threat_score >= 70 or overall_severity == 2:
        threat_level = "High"
    elif overall_threat_score >= 30 or overall_severity == 1:
        threat_level = "Medium"
    else:
        threat_level = "Low"
    
    results["summary"] = {
        "ip": ip,
        "overall_threat_score": round(overall_threat_score, 2),
        "overall_severity": overall_severity,
        "threat_level": threat_level,
        "sources_checked": list(results.keys()),
        "checked_at": time.time()
    }
    
    return results