import re
from datetime import datetime

def extract_ip(text):
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    matches = re.findall(ip_pattern, text)
    return matches[0] if matches else None

def extract_url(text):
    url_pattern = r"(https?://[^\s]+|[^\s]+\.[^\s]+)"
    matches = re.findall(url_pattern, text)
    return matches[0] if matches else None

def extract_method(text):
    # Example: GET / POST / PUT / DELETE
    match = re.search(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b", text, re.IGNORECASE)
    return match.group(0).upper() if match else "UNKNOWN"

def extract_timestamp(log_line):
    # Try multiple timestamp formats
    
    # Apache format: [10/Oct/2000:13:55:36 -0700]
    apache_match = re.search(r"\[(.*?)\]", log_line)
    if apache_match:
        try:
            return datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except:
            pass
    
    # ISO format
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})", log_line)
    if iso_match:
        try:
            return datetime.fromisoformat(iso_match.group(1).replace(' ', 'T'))
        except:
            pass
    
    # Return the first date-like string found
    date_match = re.search(r"(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})", log_line)
    if date_match:
        return date_match.group(1)
    
    return "N/A"

def parse_logs(file_path):
    parsed_entries = []
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                    
                entry = {
                    "ip": extract_ip(line),
                    "url": extract_url(line),
                    "timestamp": extract_timestamp(line),
                    "method": extract_method(line),
                    "raw": line
                }
                
                parsed_entries.append(entry)
                
    except Exception as e:
        print(f"Error parsing log file: {e}")
        
    return parsed_entries