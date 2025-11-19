import React, { useState, useEffect, useCallback, useMemo } from "react";
import { login, uploadLogFile, checkIP, healthCheck, generateSecurityReport, generateIPReport, webSocketService } from "./services/api";
import LogTable from "./components/LogTable";
import Dashboard from "./components/Dashboard";
import Filters from "./components/Filters";
import "./App.css";

function App() {
  const [logs, setLogs] = useState([]);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [ipSearch, setIpSearch] = useState("");
  const [ipResult, setIpResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState("info");
  const [dragOver, setDragOver] = useState(false);
  const [showRawData, setShowRawData] = useState(false);
  const [currentView, setCurrentView] = useState("welcome");
  
  // New state for real-time features
  const [threatFeed, setThreatFeed] = useState([]);
  const [analysisProgress, setAnalysisProgress] = useState(null);
  const [isConnected, setIsConnected] = useState(false);

  // Login once on mount to get JWT token
  useEffect(() => {
    const initializeApp = async () => {
      try {
        setMessage("🚀 Initializing Security Dashboard...");
        setMessageType("info");
        await healthCheck();
        await login();
        setMessage("✅ Application ready. Upload log files or check IP reputations to begin security analysis.");
        setMessageType("success");
      } catch (err) {
        setMessage(`❌ Initialization failed: ${err.message}. Ensure backend server is running on port 5000.`);
        setMessageType("error");
        console.error("Initialization error:", err);
      }
    };
    
    initializeApp();
  }, []);

  // WebSocket setup for real-time features
  useEffect(() => {
    // Connect to WebSocket
    const socket = webSocketService.connect();
    
    socket.on('connect', () => {
      setIsConnected(true);
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
    });

    // Subscribe to threat updates
    webSocketService.subscribeToThreats((threatData) => {
      setThreatFeed(prev => [threatData, ...prev.slice(0, 9)]); // Keep last 10 threats
    });

    // Subscribe to analysis progress
    webSocketService.subscribeToProgress((progressData) => {
      setAnalysisProgress(progressData);
    });

    return () => {
      webSocketService.disconnect();
    };
  }, []);

  // Handle drag and drop events
  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileUpload({ target: { files } });
    }
  }, []);

  // Handle log file upload
  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.match(/\.(log|txt)$/i)) {
      setMessage("❌ Please upload only .log or .txt files.");
      setMessageType("error");
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setMessage("❌ File size too large. Please upload files smaller than 10MB.");
      setMessageType("error");
      return;
    }

    setLoading(true);
    setMessage("🔍 Analyzing log file...");
    setMessageType("info");
    
    try {
      console.time('FileProcessing');
      const res = await uploadLogFile(file);
      console.timeEnd('FileProcessing');
      
      if (res.correlated_entries && res.correlated_entries.length > 0) {
        const normalized = res.correlated_entries.map(entry => ({
          ip: entry.ip || "N/A",
          url: entry.url || "N/A",
          timestamp: entry.timestamp || "N/A",
          method: entry.method || "N/A",
          overall_severity: entry.overall_severity || 0,
          threat_matches: entry.threat_matches || [],
          raw: entry.raw || ""
        }));
        
        setLogs(normalized);
        setMessage(`✅ Successfully analyzed ${normalized.length} log entries`);
        setMessageType("success");
        setCurrentView("results");
      } else {
        setMessage("⚠️ No log entries processed. File may be empty or format unsupported.");
        setMessageType("warning");
      }
    } catch (err) {
      setMessage(`❌ Analysis failed: ${err.message}`);
      setMessageType("error");
      console.error("Upload error:", err);
    } finally {
      setLoading(false);
      event.target.value = "";
    }
  };

  // Handle IP check
  const handleIPCheck = async () => {
    if (!ipSearch.trim()) {
      setMessage("⚠️ Please enter an IP address to check.");
      setMessageType("warning");
      return;
    }

    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipPattern.test(ipSearch)) {
      setMessage("❌ Please enter a valid IP address format.");
      setMessageType("error");
      return;
    }

    setLoading(true);
    setMessage("🌐 Checking IP reputation...");
    setMessageType("info");
    
    try {
      console.log(`Starting IP check for: ${ipSearch}`);
      const result = await checkIP(ipSearch);
      console.log('IP check result:', result);
      
      if (result.error) {
        setMessage(`❌ IP check failed: ${result.error}`);
        setMessageType("error");
      } else {
        setIpResult(result);
        setMessage(`✅ IP reputation analysis completed for ${ipSearch}`);
        setMessageType("success");
        setCurrentView("results");
      }
    } catch (err) {
      console.error('IP check error details:', err);
      setMessage(`❌ IP reputation check failed: ${err.message}`);
      setMessageType("error");
    } finally {
      setLoading(false);
    }
  };

  // Report generation functions
  const handleGenerateSecurityReport = async () => {
    try {
      setMessage("📄 Generating security report...");
      
      await generateSecurityReport(
        {
          logs: logs,
          stats: stats,
          filteredLogs: filteredLogs
        },
        ipResult ? { [ipResult.ip]: ipResult } : {}
      );
      
      setMessage("✅ Security report downloaded successfully");
    } catch (err) {
      setMessage(`❌ Report generation failed: ${err.message}`);
    }
  };

  const handleGenerateIPReport = async () => {
    if (!ipResult) {
      setMessage("⚠️ No IP data available for report generation");
      return;
    }
    
    try {
      setMessage("📄 Generating IP reputation report...");
      
      await generateIPReport({
        [ipResult.ip]: ipResult
      });
      
      setMessage("✅ IP reputation report downloaded successfully");
    } catch (err) {
      setMessage(`❌ IP report generation failed: ${err.message}`);
    }
  };

  // Navigation handlers
  const handleNavigation = useCallback((view) => {
    setCurrentView(view);
    setMessage("");
  }, []);

  const handleBackToWelcome = useCallback(() => {
    setCurrentView("welcome");
    setLogs([]);
    setIpResult(null);
    setSearch("");
    setIpSearch("");
    setMessage("🔄 Ready for new security analysis.");
    setMessageType("info");
  }, []);

  // Optimized filtered logs
  const filteredLogs = useMemo(() => {
    return logs
      .filter(l => severityFilter === "all" || l.overall_severity === parseInt(severityFilter))
      .filter(l => !search || (l.ip && l.ip.includes(search)));
  }, [logs, severityFilter, search]);

  // Statistics
  const stats = useMemo(() => {
    return {
      total: logs.length,
      low: logs.filter(l => l.overall_severity === 0).length,
      medium: logs.filter(l => l.overall_severity === 1).length,
      high: logs.filter(l => l.overall_severity === 2).length
    };
  }, [logs]);

  const getThreatLevelClass = useCallback((level) => {
    switch (level?.toLowerCase()) {
      case 'high': return 'high-risk';
      case 'medium': return 'medium-risk';
      case 'low': return 'low-risk';
      default: return '';
    }
  }, []);

  // Real-time threat feed component
  const RealTimeThreatFeed = () => (
    <div className="card threat-feed">
      <div className="threat-feed-header">
        <h3>🔄 Real-time Threat Feed</h3>
        <span className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
          {isConnected ? '● Connected' : '● Disconnected'}
        </span>
      </div>
      <div className="threat-list">
        {threatFeed.length === 0 ? (
          <p className="no-threats">No recent threats detected</p>
        ) : (
          threatFeed.map((threat, index) => (
            <div key={index} className={`threat-item ${threat.severity}`}>
              <span className="threat-type">{threat.type}</span>
              <span className="threat-ip">{threat.ip}</span>
              <span className={`threat-severity ${threat.severity}`}>
                {threat.severity}
              </span>
              <span className="threat-source">{threat.source}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );

  // Render Welcome View
  const renderWelcomeView = () => (
    <div className="welcome-container">
      <div className="welcome-header">
        <h1>Security Dashboard / Threat Intel Aggregator</h1>
        <p className="subtitle">
          Advanced threat detection and IP reputation analysis
        </p>
      </div>

      {message && (
        <div className={`status-message ${messageType}`}>
          {loading && <div className="loading-spinner"></div>}
          {message}
        </div>
      )}

      <div className="action-cards">
        <div className="action-card" onClick={() => handleNavigation("logAnalysis")}>
          <div className="action-icon">📊</div>
          <h3>Log Analysis</h3>
          <p>Analyze security logs with real-time threat correlation</p>
          <div className="action-features">
            <span>Real-time Threat Correlation</span>
            <span>Multi-source Intelligence</span>
            <span>Interactive Dashboards</span>
            <span>Automated Severity Scoring</span>
          </div>
          <button className="action-btn">
            Start Log Analysis
          </button>
        </div>

        <div className="action-card" onClick={() => handleNavigation("ipCheck")}>
          <div className="action-icon">🌐</div>
          <h3>IP Reputation</h3>
          <p>Check IP addresses against global threat databases</p>
          <div className="action-features">
            <span>AbuseIPDB Integration</span>
            <span>Shodan Intelligence Data</span>
            <span>Risk Scoring</span>
            <span>Historical Threat Data</span>
          </div>
          <button className="action-btn">
            Check IP Reputation
          </button>
        </div>

        <div className="action-card">
          <div className="action-icon">🚀</div>
          <h3>Quick Start Guide</h3>
          <p>Get started with our security platform in minutes</p>
          <div className="instruction-steps">
            <div className="step">
              <div className="step-number">1</div>
              <div>
                <strong>Upload Security Logs</strong>
                <p>Import server access logs for analysis</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">2</div>
              <div>
                <strong>Threat Intelligence</strong>
                <p>Cross-reference with threat databases</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">3</div>
              <div>
                <strong>Interactive Analysis</strong>
                <p>Use filters to investigate security events</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">4</div>
              <div>
                <strong>IP Reputation Checks</strong>
                <p>Verify suspicious IP addresses</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="footer">
        <p>🔒 Developed by Ehmaan Shafqat</p>
      </div>
    </div>
  );

  // Render Log Analysis View
  const renderLogAnalysisView = () => (
    <div className="tool-container">
      <div className="tool-header">
        <button className="back-btn" onClick={handleBackToWelcome}>
          ← Back to Dashboard
        </button>
        <h2>Log File Analysis</h2>
        <p>Upload and analyze security logs</p>
      </div>

      <div className="card">
        <div 
          className={`upload-area ${dragOver ? 'drag-over' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => document.getElementById('file-input').click()}
        >
          <div className="upload-icon">📁</div>
          <div className="upload-text">
            <strong>Upload Log File</strong>
            <p>Drag & drop or click to upload</p>
          </div>
          <input
            id="file-input"
            type="file"
            className="file-input"
            onChange={handleFileUpload}
            accept=".log,.txt"
            disabled={loading}
          />
        </div>
      </div>

      {/* Progress indicator */}
      {analysisProgress && (
        <div className="progress-indicator">
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${analysisProgress.progress}%` }}
            ></div>
          </div>
          <p>Analysis: {analysisProgress.stage} ({analysisProgress.progress}%)</p>
          {analysisProgress.error && (
            <p className="error">Error: {analysisProgress.error}</p>
          )}
        </div>
      )}

      {loading && (
        <div className="card loading">
          <div className="loading-spinner"></div>
          <p>Processing log file...</p>
        </div>
      )}
    </div>
  );

  // Render IP Check View
  const renderIPCheckView = () => (
    <div className="tool-container">
      <div className="tool-header">
        <button className="back-btn" onClick={handleBackToWelcome}>
          ← Back to Dashboard
        </button>
        <h2>IP Reputation Check</h2>
        <p>Check IP addresses against threat databases</p>
      </div>

      <div className="card">
        <div className="ip-check-simple">
          <input
            type="text"
            placeholder="Enter IP address..."
            value={ipSearch}
            onChange={(e) => setIpSearch(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleIPCheck()}
          />
          <button onClick={handleIPCheck} disabled={loading}>
            {loading ? 'Checking...' : 'Check'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="card loading">
          <div className="loading-spinner"></div>
          <p>Checking IP reputation...</p>
        </div>
      )}
    </div>
  );

  // Render Results View
  const renderResultsView = () => (
    <div className="results-container">
      <div className="results-header">
        <button className="back-btn" onClick={handleBackToWelcome}>
          ← Back to Dashboard
        </button>
        <h2>Analysis Results</h2>
        <p>Security analysis and threat intelligence results</p>
      </div>

      {message && (
        <div className={`status-message ${messageType}`}>
          {message}
        </div>
      )}

      {/* Report Actions */}
      <div className="report-actions">
        <button 
          className="report-btn"
          onClick={handleGenerateSecurityReport}
          disabled={logs.length === 0}
        >
          📊 Generate Security Report
        </button>
        
        <button 
          className="report-btn"
          onClick={handleGenerateIPReport}
          disabled={!ipResult}
        >
          🌐 Generate IP Report
        </button>
      </div>

      {/* Real-time Threat Feed */}
      <RealTimeThreatFeed />

      <div className="main-container">
        {/* Left Panel - Tools */}
        <div className="left-panel">
          {/* Real-time Stats */}
          {logs.length > 0 && (
            <div className="card">
              <h3>📈 Statistics</h3>
              <div className="stats-grid">
                <div className="stat-item">
                  <span className="stat-value">{stats.total}</span>
                  <span className="stat-label">Total</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value">{stats.low}</span>
                  <span className="stat-label">Low</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value">{stats.medium}</span>
                  <span className="stat-label">Medium</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value">{stats.high}</span>
                  <span className="stat-label">High</span>
                </div>
              </div>
            </div>
          )}

          {/* Search & Filters */}
          {logs.length > 0 && (
            <div className="card">
              <h3>🔍 Filter Logs</h3>
              <div className="search-box">
                <input
                  type="text"
                  placeholder="Search by IP..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <div className="filter-box">
                <Filters 
                  severityFilter={severityFilter} 
                  setSeverityFilter={setSeverityFilter} 
                />
              </div>
            </div>
          )}

          {/* Quick IP Check */}
          <div className="card">
            <h3>🌐 Quick IP Check</h3>
            <div className="ip-check-area">
              <input
                type="text"
                placeholder="Enter IP..."
                value={ipSearch}
                onChange={(e) => setIpSearch(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleIPCheck()}
              />
              <button onClick={handleIPCheck}>
                Check
              </button>
            </div>
          </div>
        </div>

        {/* Right Panel - Results */}
        <div className="right-panel">
          {/* IP Reputation Results */}
          {ipResult && (
            <div className="card ip-result-card">
              <div className="ip-result-header">
                <h3>🔍 IP Reputation Analysis</h3>
                <span className={`risk-badge ${getThreatLevelClass(ipResult.summary?.threat_level)}`}>
                  {ipResult.summary?.threat_level || 'Unknown'} Risk
                </span>
              </div>
              
              {ipResult.error ? (
                <div className="error-message">
                  <h4>❌ Error Checking IP</h4>
                  <p>{ipResult.error}</p>
                </div>
              ) : (
                <div className="ip-result-content">
                  {/* Summary Section */}
                  {ipResult.summary && (
                    <div className={`summary-card ${getThreatLevelClass(ipResult.summary.threat_level)}`}>
                      <h4>📊 Overall Assessment</h4>
                      <div className="summary-grid">
                        <div className="summary-item">
                          <strong>IP Address</strong>
                          <span>{ipResult.ip}</span>
                        </div>
                        <div className="summary-item">
                          <strong>Threat Level</strong>
                          <span className={`threat-level ${ipResult.summary.threat_level?.toLowerCase()}`}>
                            {ipResult.summary.threat_level}
                          </span>
                        </div>
                        <div className="summary-item">
                          <strong>Risk Score</strong>
                          <span>{ipResult.summary.risk_score}/100</span>
                        </div>
                        <div className="summary-item">
                          <strong>Verdict</strong>
                          <span>{ipResult.summary.verdict}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* AbuseIPDB Results */}
                  <div className="data-section">
                    <h4>🛡️ AbuseIPDB Reputation</h4>
                    {ipResult.abuseipdb && !ipResult.abuseipdb.error ? (
                      <div className="data-grid">
                        <div className="data-item">
                          <strong>Confidence Score</strong>
                          <span className="score-value">
                            {ipResult.abuseipdb.abuse_confidence_score || 0}%
                          </span>
                        </div>
                        <div className="data-item">
                          <strong>Total Reports</strong>
                          <span>{ipResult.abuseipdb.details?.totalReports || 0}</span>
                        </div>
                        <div className="data-item">
                          <strong>Country</strong>
                          <span>{ipResult.abuseipdb.details?.country || 'Unknown'}</span>
                        </div>
                        <div className="data-item">
                          <strong>ISP</strong>
                          <span>{ipResult.abuseipdb.details?.usageType || 'Unknown'}</span>
                        </div>
                        <div className="data-item">
                          <strong>Last Reported</strong>
                          <span>
                            {ipResult.abuseipdb.details?.lastReported ? 
                              new Date(ipResult.abuseipdb.details.lastReported).toLocaleDateString() : 'Never'
                            }
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="no-data">
                        <p>❌ No AbuseIPDB data available</p>
                        {ipResult.abuseipdb?.error && (
                          <small>Error: {ipResult.abuseipdb.error}</small>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Shodan Results */}
                  <div className="data-section">
                    <h4>🌐 Shodan Information</h4>
                    {ipResult.shodan && !ipResult.shodan.error ? (
                      <div className="data-grid">
                        <div className="data-item">
                          <strong>Status</strong>
                          <span>{ipResult.shodan.status || 'Found'}</span>
                        </div>
                        <div className="data-item">
                          <strong>Organization</strong>
                          <span>{ipResult.shodan.details?.organization || ipResult.shodan.organization || 'Unknown'}</span>
                        </div>
                        <div className="data-item">
                          <strong>Open Ports</strong>
                          <div className="ports-list">
                            {ipResult.shodan.details?.open_ports?.length > 0 ? (
                              ipResult.shodan.details.open_ports.map(port => (
                                <span key={port} className="port-tag">{port}</span>
                              ))
                            ) : ipResult.shodan.open_ports?.length > 0 ? (
                              ipResult.shodan.open_ports.map(port => (
                                <span key={port} className="port-tag">{port}</span>
                              ))
                            ) : (
                              <span className="no-ports">No open ports found</span>
                            )}
                          </div>
                        </div>
                        <div className="data-item">
                          <strong>Hostnames</strong>
                          <div className="hostnames-list">
                            {ipResult.shodan.details?.hostnames?.length > 0 ? (
                              ipResult.shodan.details.hostnames.map(hostname => (
                                <span key={hostname} className="hostname-tag">{hostname}</span>
                              ))
                            ) : ipResult.shodan.hostnames?.length > 0 ? (
                              ipResult.shodan.hostnames.map(hostname => (
                                <span key={hostname} className="hostname-tag">{hostname}</span>
                              ))
                            ) : (
                              <span className="no-hostnames">No hostnames found</span>
                            )}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="no-data">
                        <p>❌ No Shodan data available</p>
                        {ipResult.shodan?.error && (
                          <small>Error: {ipResult.shodan.error}</small>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Raw Data Toggle */}
                  <div className="raw-data-section">
                    <button 
                      className="raw-data-toggle"
                      onClick={() => setShowRawData(!showRawData)}
                    >
                      {showRawData ? '📋 Hide Raw Data' : '📋 Show Raw Data'}
                    </button>
                    
                    {showRawData && (
                      <div className="raw-data">
                        <pre>{JSON.stringify(ipResult, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Logs Overview */}
          {logs.length > 0 && (
            <div className="card">
              <h3>Log Analysis</h3>
              <p>Showing {filteredLogs.length} of {logs.length} entries</p>
            </div>
          )}
        </div>
      </div>

      {/* Charts and Table */}
      {filteredLogs.length > 0 && (
        <div className="results-content">
          <div className="card">
            <h3>Threat Severity Analysis</h3>
            <Dashboard logs={filteredLogs} />
          </div>
          <div className="card">
            <h3>Log Entries ({filteredLogs.length})</h3>
            <LogTable logs={filteredLogs} />
          </div>
        </div>
      )}
    </div>
  );

  // Main render function
  return (
    <div className="App">
      {currentView === "welcome" && renderWelcomeView()}
      {currentView === "logAnalysis" && renderLogAnalysisView()}
      {currentView === "ipCheck" && renderIPCheckView()}
      {currentView === "results" && renderResultsView()}
    </div>
  );
}

export default App;