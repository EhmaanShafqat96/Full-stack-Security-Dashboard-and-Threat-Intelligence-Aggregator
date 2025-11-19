# Security Dashboard & Threat Intelligence Aggregator 🔒

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![React](https://img.shields.io/badge/react-18.0%2B-61dafb)
![Flask](https://img.shields.io/badge/flask-2.3%2B-green)
![License](https://img.shields.io/badge/license-MIT-success)
![WebSocket](https://img.shields.io/badge/websocket-real--time-orange)

A comprehensive full-stack security application that aggregates threat intelligence from multiple sources, analyzes security logs in real-time, and provides actionable insights through an interactive dashboard.

## ✨ Features

### 🔍 Threat Intelligence
- **Multi-Source Aggregation**: AbuseIPDB, Shodan, VirusTotal, and AlienVault OTX
- **IP Reputation Analysis**: Comprehensive threat scoring with confidence metrics
- **Real-time Correlation**: Automatic threat matching across intelligence sources
- **Unified Scoring**: Normalized threat assessment (0-100 scale)

### 📊 Security Analytics
- **Log Analysis Engine**: Multi-format log parsing (.log, .txt) with IP extraction
- **Interactive Dashboard**: Chart.js visualizations for threat severity distribution
- **Advanced Filtering**: Severity-based and search filtering capabilities
- **Real-time Monitoring**: Live threat feed with WebSocket updates

### 🛡️ Enterprise Features
- **JWT Authentication**: Secure token-based access control
- **Rate Limiting**: Intelligent API request throttling
- **PDF Reporting**: Professional security assessment reports
- **Responsive Design**: Mobile-friendly interface

## 🛠️ Technology Stack

**Frontend**: React.js, Chart.js, WebSocket, Axios, CSS3  
**Backend**: Flask, JWT, Flask-Limiter, Flask-SocketIO, ReportLab  
**APIs**: AbuseIPDB, Shodan, VirusTotal, AlienVault OTX

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 14+
- API keys from threat intelligence services

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/security-dashboard.git
cd security-dashboard
```


### Backend Setup

```bash
cd backend
python -m venv venv
```
### Activate Virtual Environment:
```bash
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```
### Install dependencies:
```bash
pip install -r requirements.txt
```
### Create environment file and add API keys:
```bash
cp .env.example .env
# Edit .env with your API keys
```
### Run backend:
```bash
python app.py
```
### Frontend Setup
```bash

cd ../frontend
npm install
npm start
```
### Access the application:

Frontend: http://localhost:3000

Backend API: http://localhost:5000

## ⚙️ Configuration
### Environment Variables (.env)

ABUSEIPDB_API_KEY=your_abuseipdb_api_key

SHODAN_API_KEY=your_shodan_api_key

VIRUSTOTAL_API_KEY=your_virustotal_api_key

ALIENVAULT_API_KEY=your_alienvault_api_key

JWT_SECRET=your_jwt_secret_key

### API Keys Required:

- AbuseIPDB
- Shodan
- VirusTotal
- AlienVault OTX

## 🎯 Usage
### Log Analysis
- Upload security log files (.log, .txt)
- View real-time processing progress
- Analyze correlated threats in interactive tables

### IP Reputation Check
- Enter IP address for comprehensive analysis
- View multi-source threat assessment
- Access detailed intelligence data

### Real-time Dashboard
- Monitor live threat feed
- View severity distribution charts
- Generate PDF reports

### Reporting
- Generate security assessment reports
- Export IP reputation analysis
- Download professional PDF documents

### 📁 Project Structure
```
security-dashboard/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── utils.py               # Threat intelligence APIs
│   ├── log_parser.py          # Log parsing engine
│   ├── threat_correlation.py  # Threat matching logic
│   ├── report_generator.py    # PDF report generation
│   ├── websocket.py           # Real-time communication
│   ├── requirements.txt       # Python dependencies
│   └── uploads/               # File upload directory
└── frontend/
    ├── src/
    │   ├── App.js             # Main React component
    │   ├── App.css            # Styling
    │   ├── components/
    │   │   ├── Dashboard.js   # Data visualizations
    │   │   ├── LogTable.js    # Data tables
    │   │   └── Filters.js     # Filter components
    │   └── services/
    │       └── api.js         # API service layer
    ├── public/
    └── package.json           # Node.js dependencies
```
### 🔌 API Endpoints
| Endpoint                       | Method | Description                     |
|--------------------------------|--------|---------------------------------|
| /api/login                     | POST   | Generate JWT token               |
| /api/check-ip                  | POST   | Basic IP reputation check        |
| /api/enhanced-check-ip         | POST   | Multi-source IP analysis         |
| /api/analyze-logs              | POST   | Process and analyze log files    |
| /api/generate-security-report  | POST   | Generate PDF security report     |
| /api/generate-ip-report        | POST   | Generate PDF IP report           |
| /api/health                    | GET    | System status check              |


### 🤝 Contributing
- Fork the repository

- Create a feature branch: git checkout -b feature/amazing-feature

- Commit changes: git commit -m 'Add amazing feature'

- Push to branch: git push origin feature/amazing-feature

- Open a Pull Request

#Reported by: Ehmaan Shafqat
