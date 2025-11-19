import axios from 'axios';
import io from 'socket.io-client';

const BASE_URL = "http://localhost:5000";

// ----------------------------
// Helper to get JWT token
// ----------------------------
const getToken = () => localStorage.getItem("token") || "";

// ----------------------------
// Basic API Functions
// ----------------------------
export const login = async () => {
  try {
    const res = await axios.post(`${BASE_URL}/api/login`);
    const token = res.data.token;
    localStorage.setItem("token", token);
    return token;
  } catch (error) {
    console.error("Login failed:", error);
    throw error;
  }
};

export const healthCheck = async () => {
  try {
    const res = await axios.get(`${BASE_URL}/api/health`);
    return res.data;
  } catch (error) {
    console.error("Health check failed:", error);
    throw error;
  }
};

export const uploadLogFile = async (file) => {
  try {
    const token = getToken();
    const formData = new FormData();
    formData.append("file", file);

    const res = await axios.post(`${BASE_URL}/api/analyze-logs`, formData, {
      headers: {
        "x-access-token": token,
        "Content-Type": "multipart/form-data"
      },
      timeout: 30000
    });

    return res.data;
  } catch (error) {
    console.error("Upload log failed:", error);
    throw error;
  }
};

export const checkIP = async (ip) => {
  try {
    const token = getToken();
    const res = await axios.post(
      `${BASE_URL}/api/check-ip`,
      { ip },
      {
        headers: { "x-access-token": token },
        timeout: 15000
      }
    );
    return res.data;
  } catch (error) {
    console.error("IP check failed:", error);
    throw error;
  }
};

// ----------------------------
// Report Generation Functions
// ----------------------------
export const generateSecurityReport = async (analysisData, ipReputationData) => {
  try {
    const token = getToken();
    const response = await axios.post(
      `${BASE_URL}/api/generate-security-report`,
      {
        analysis_data: analysisData,
        ip_reputation_data: ipReputationData
      },
      {
        headers: { "x-access-token": token },
        responseType: 'blob'
      }
    );
    
    // Create download link
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `security_report_${new Date().getTime()}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    
    return { success: true };
  } catch (error) {
    console.error('Report generation failed:', error);
    throw error;
  }
};

export const generateIPReport = async (ipData) => {
  try {
    const token = getToken();
    const response = await axios.post(
      `${BASE_URL}/api/generate-ip-report`,
      { ip_data: ipData },
      {
        headers: { "x-access-token": token },
        responseType: 'blob'
      }
    );
    
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `ip_reputation_report_${new Date().getTime()}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    
    return { success: true };
  } catch (error) {
    console.error('IP report generation failed:', error);
    throw error;
  }
};

// ----------------------------
// WebSocket Service
// ----------------------------
class WebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
  }

  connect() {
    this.socket = io(BASE_URL);
    
    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      this.isConnected = true;
      this.socket.emit('subscribe_threats');
    });

    this.socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      this.isConnected = false;
    });

    this.socket.on('connection_established', (data) => {
      console.log('WebSocket:', data.message);
    });

    return this.socket;
  }

  subscribeToThreats(callback) {
    if (this.socket) {
      this.socket.on('threat_update', callback);
    }
  }

  subscribeToProgress(callback) {
    if (this.socket) {
      this.socket.on('analysis_progress', callback);
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.isConnected = false;
    }
  }
}

export const webSocketService = new WebSocketService();