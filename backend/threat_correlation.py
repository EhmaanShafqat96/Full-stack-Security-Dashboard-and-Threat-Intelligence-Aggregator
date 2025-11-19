from utils import check_abuseipdb, check_shodan

def correlate_logs(log_entries, abuseipdb_key, shodan_key):
    correlated = []

    for entry in log_entries:
        ip = entry.get("ip")
        result = entry.copy()
        result["threat_matches"] = []
        threat_sources = []

        if ip and ip != "N/A":
            # Check AbuseIPDB
            abuse_result = check_abuseipdb(ip, abuseipdb_key)
            if abuse_result and "error" not in abuse_result:
                result["threat_matches"].append({
                    "source": "AbuseIPDB",
                    "severity": abuse_result.get("severity", 0),
                    "abuseConfidenceScore": abuse_result.get("abuseConfidenceScore", 0),
                    "details": abuse_result.get("details", {})
                })
                threat_sources.append("AbuseIPDB")

            # Check Shodan
            shodan_result = check_shodan(ip, shodan_key)
            if shodan_result and "error" not in shodan_result:
                result["threat_matches"].append({
                    "source": "Shodan",
                    "severity": shodan_result.get("severity", 0),
                    "open_ports": shodan_result.get("open_ports", []),
                    "risky_ports": shodan_result.get("risky_ports", []),
                    "hostnames": shodan_result.get("hostnames", []),
                    "organization": shodan_result.get("organization", "Unknown"),
                    "os": shodan_result.get("os", "Unknown")
                })
                threat_sources.append("Shodan")

        # Calculate overall severity
        severity_scores = [match.get("severity", 0) for match in result["threat_matches"]]
        if severity_scores:
            result["overall_severity"] = max(severity_scores)
        else:
            result["overall_severity"] = 0

        # Add threat sources summary
        result["threat_sources"] = threat_sources

        correlated.append(result)
    
    return correlated