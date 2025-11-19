import React from "react";
const LogTable = ({ logs }) => (
  <table border="1">
    <thead>
      <tr><th>IP</th><th>URL</th><th>Timestamp</th><th>Method</th><th>Severity</th><th>Sources</th></tr>
    </thead>
    <tbody>
      {logs.map((log,i)=>(
        <tr key={i} style={{background:log.overall_severity===2?"#ffcccc":log.overall_severity===1?"#fff3cd":"#d4edda"}}>
          <td>{log.ip}</td>
          <td>{log.url}</td>
          <td>{log.timestamp}</td>
          <td>{log.method}</td>
          <td>{log.overall_severity}</td>
          <td>{log.threat_matches.map((m,j)=><div key={j}>{m.source}</div>)}</td>
        </tr>
      ))}
    </tbody>
  </table>
);
export default LogTable;
