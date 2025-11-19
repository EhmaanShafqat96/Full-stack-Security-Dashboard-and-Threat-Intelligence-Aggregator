# websocket.py - Minimal version if you don't have the full implementation
from flask_socketio import SocketIO, emit
from flask import request
import time
import threading

socketio = SocketIO(cors_allowed_origins="*")
connected_clients = []

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    connected_clients.append(request.sid)
    emit('connection_established', {'message': 'Connected to threat intelligence feed'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    if request.sid in connected_clients:
        connected_clients.remove(request.sid)

def send_threat_update(threat_data):
    socketio.emit('threat_update', threat_data)

def send_analysis_progress(progress_data):
    socketio.emit('analysis_progress', progress_data)

def start_demo_threat_feed():
    def threat_generator():
        demo_threats = [
            {"type": "malicious_ip", "ip": "192.168.1.100", "severity": "high", "source": "AbuseIPDB"},
            {"type": "suspicious_activity", "ip": "10.0.0.50", "severity": "medium", "source": "Internal Logs"},
        ]
        while True:
            for threat in demo_threats:
                if connected_clients:
                    threat['timestamp'] = time.time()
                    send_threat_update(threat)
                time.sleep(30)
    
    thread = threading.Thread(target=threat_generator, daemon=True)
    thread.start()