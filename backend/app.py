from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import os
import datetime
import jwt
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import your custom modules
from utils import check_abuseipdb, check_shodan, check_virustotal, check_alienvault, enhanced_ip_check
from log_parser import parse_logs
from threat_correlation import correlate_logs
from report_generator import generate_security_report, generate_ip_reputation_report

# WebSocket imports - make sure you have these files created
try:
    from websocket import socketio, send_threat_update, send_analysis_progress, start_demo_threat_feed
    websocket_available = True
except ImportError:
    print("WebSocket module not available - real-time features disabled")
    websocket_available = False

# ----------------------------
# Load Environment Variables
# ----------------------------
load_dotenv()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_KEY = os.getenv("SHODAN_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ALIENVAULT_KEY = os.getenv("ALIENVAULT_API_KEY")
SECRET_KEY = os.getenv("JWT_SECRET", "supersecretjwtkey")

if not ABUSEIPDB_KEY or not SHODAN_KEY:
    raise ValueError("Please set ABUSEIPDB_API_KEY and SHODAN_API_KEY in .env")

# ----------------------------
# Initialize Flask App
# ----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app)

# ----------------------------
# Initialize WebSocket if available
# ----------------------------
if websocket_available:
    socketio.init_app(app)

# ----------------------------
# Rate Limiting
# ----------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)

# ----------------------------
# File Upload Settings
# ----------------------------
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"log", "txt"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------------------
# JWT Auth Decorator
# ----------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except Exception as e:
            return jsonify({"error": f"Invalid or expired token: {str(e)}"}), 401
        return f(*args, **kwargs)
    return decorated

# ----------------------------
# Routes - ALL ROUTES MUST COME AFTER app IS DEFINED
# ----------------------------

@app.route('/')
def home():
    return jsonify({"message": "Security Dashboard Backend Running"})

# ----------------------------
# Dummy Login to Generate Token
# ----------------------------
@app.route('/api/login', methods=['POST', 'GET'])
@limiter.limit("10 per minute")
def login():
    token = jwt.encode(
        {
            "user": "admin",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        },
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )
    return jsonify({"token": token, "message": "Login successful"})

# ----------------------------
# Check IP Reputation
# ----------------------------
@app.route('/api/check-ip', methods=['POST'])
@token_required
@limiter.limit("30 per minute")
def check_ip():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ip_address = data.get("ip")
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    # Validate IP address format and filter out invalid IPs
    import re
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(ip_pattern, ip_address):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    # Filter out private, reserved, and special IPs
    if (ip_address == "0.0.0.0" or 
        ip_address.startswith("127.") or 
        ip_address.startswith("10.") or 
        ip_address.startswith("192.168.") or
        ip_address.startswith("172.") and 16 <= int(ip_address.split(".")[1]) <= 31):
        return jsonify({
            "error": f"IP address {ip_address} is private/reserved and cannot be checked for reputation"
        }), 400

    try:
        abuse_result = check_abuseipdb(ip_address, ABUSEIPDB_KEY)
        shodan_result = check_shodan(ip_address, SHODAN_KEY)

        # Calculate overall threat assessment
        abuse_severity = abuse_result.get("severity", 0) if abuse_result else 0
        shodan_severity = shodan_result.get("severity", 0) if shodan_result else 0
        overall_severity = max(abuse_severity, shodan_severity)
        
        # Calculate risk score (0-100)
        abuse_score = abuse_result.get("abuseConfidenceScore", 0) if abuse_result else 0
        risk_score = min(100, abuse_score)  # Use abuse score as base risk
        
        # Determine threat level and verdict
        threat_levels = {
            0: "Low",
            1: "Medium", 
            2: "High"
        }
        
        verdicts = {
            0: "Clean",
            1: "Suspicious",
            2: "Malicious"
        }

        # Build clean response structure
        response_data = {
            "ip": ip_address,
            "summary": {
                "threat_level": threat_levels.get(overall_severity, "Unknown"),
                "overall_severity": overall_severity,
                "risk_score": risk_score,
                "checked_at": datetime.datetime.utcnow().isoformat() + "Z",
                "sources_checked": ["AbuseIPDB", "Shodan"],
                "verdict": verdicts.get(overall_severity, "Unknown")
            },
            "abuseipdb": {
                "source": "AbuseIPDB",
                "abuse_confidence_score": abuse_result.get("abuseConfidenceScore", 0) if abuse_result else 0,
                "severity": abuse_severity,
                "reputation": "Clean" if abuse_severity == 0 else "Suspicious" if abuse_severity == 1 else "Malicious",
                "details": abuse_result.get("details", {}) if abuse_result else {}
            } if abuse_result else {
                "source": "AbuseIPDB",
                "error": "Data unavailable",
                "severity": 0
            },
            "shodan": {
                "source": "Shodan",
                "severity": shodan_severity,
                "status": "found" if shodan_result and "error" not in shodan_result else "not_found",
                "details": {
                    "open_ports": shodan_result.get("open_ports", []),
                    "risky_ports": shodan_result.get("risky_ports", []),
                    "hostnames": shodan_result.get("hostnames", []),
                    "organization": shodan_result.get("organization", "Unknown"),
                    "operating_system": shodan_result.get("os", "Unknown"),
                    "country": shodan_result.get("country", "Unknown")
                } if shodan_result and "error" not in shodan_result else {}
            } if shodan_result else {
                "source": "Shodan", 
                "error": "Data unavailable",
                "severity": 0
            }
        }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({
            "error": f"IP reputation check failed: {str(e)}",
            "ip": ip_address
        }), 500

# ----------------------------
# Enhanced IP Check Endpoint
# ----------------------------
@app.route('/api/enhanced-check-ip', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def enhanced_check_ip():
    data = request.get_json()
    ip_address = data.get("ip")
    
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    try:
        result = enhanced_ip_check(
            ip_address, 
            ABUSEIPDB_KEY, 
            SHODAN_KEY, 
            VIRUSTOTAL_KEY, 
            ALIENVAULT_KEY
        )
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": f"Enhanced IP check failed: {str(e)}"}), 500

# ----------------------------
# Upload Log and Analyze
# ----------------------------
@app.route('/api/analyze-logs', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def analyze_logs():
    try:
        print("Starting log analysis...")
        
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
            
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400

        # Save file
        import time
        start_time = time.time()
        
        filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        print(f"File saved: {time.time() - start_time:.2f}s")

        # Send progress updates if WebSocket is available
        if websocket_available:
            send_analysis_progress({"stage": "upload", "progress": 25})

        # Parse logs
        start_time = time.time()
        parsed_entries = parse_logs(filepath)
        print(f"Logs parsed: {time.time() - start_time:.2f}s")
        print(f"Found {len(parsed_entries)} entries")
        
        if websocket_available:
            send_analysis_progress({"stage": "parsing", "progress": 50})
        
        if not parsed_entries:
            return jsonify({"error": "No valid log entries found"}), 400

        # Correlate with threat intelligence
        start_time = time.time()
        correlated_entries = correlate_logs(parsed_entries, ABUSEIPDB_KEY, SHODAN_KEY)
        print(f"Threat correlation: {time.time() - start_time:.2f}s")

        if websocket_available:
            send_analysis_progress({"stage": "correlation", "progress": 75})

        # Convert timestamps
        for entry in correlated_entries:
            ts = entry.get("timestamp")
            if ts is None:
                entry["timestamp"] = "N/A"
            elif hasattr(ts, "isoformat"):
                entry["timestamp"] = ts.isoformat()

        if websocket_available:
            send_analysis_progress({"stage": "complete", "progress": 100})

        print(f"Total processing time: {time.time() - start_time:.2f}s")
        
        return jsonify({
            "status": "success", 
            "message": f"Processed {len(correlated_entries)} log entries",
            "correlated_entries": correlated_entries
        })

    except Exception as e:
        print(f"Error in analyze_logs: {str(e)}")
        if websocket_available:
            send_analysis_progress({"stage": "error", "progress": 0, "error": str(e)})
        return jsonify({"error": f"Log analysis failed: {str(e)}"}), 500

# ----------------------------
# PDF Report Endpoints
# ----------------------------
@app.route('/api/generate-security-report', methods=['POST'])
@token_required
def generate_security_report_endpoint():
    """Generate and download security analysis PDF report"""
    try:
        data = request.get_json()
        
        pdf_buffer = generate_security_report(
            analysis_data=data.get('analysis_data', {}),
            ip_reputation_data=data.get('ip_reputation_data', {})
        )
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

@app.route('/api/generate-ip-report', methods=['POST'])
@token_required
def generate_ip_report_endpoint():
    """Generate and download IP reputation PDF report"""
    try:
        data = request.get_json()
        
        pdf_buffer = generate_ip_reputation_report(
            ip_data=data.get('ip_data', {})
        )
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"ip_reputation_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({"error": f"IP report generation failed: {str(e)}"}), 500

# ----------------------------
# Health check endpoint
# ----------------------------
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "websocket_enabled": websocket_available
    })

# ----------------------------
# Startup Tasks
# ----------------------------
def startup_tasks():
    """Initialize background tasks when app starts"""
    if websocket_available:
        start_demo_threat_feed()
        print("WebSocket threat feed started")
    else:
        print("WebSocket features disabled - module not found")

# ----------------------------
# Run Server
# ----------------------------
if __name__ == '__main__':
    startup_tasks()
    
    if websocket_available:
        socketio.run(app, debug=True, port=5000)
    else:
        app.run(debug=True, port=5000)