import React from "react";

const Filters = ({ severityFilter, setSeverityFilter, disabled }) => (
  <select 
    value={severityFilter} 
    onChange={e => setSeverityFilter(e.target.value)}
    disabled={disabled}
    style={{
      padding: '12px 15px',
      border: '2px solid #e0e0e0',
      borderRadius: '8px',
      fontSize: '1rem',
      transition: 'all 0.3s ease',
      width: '100%'
    }}
  >
    <option value="all">All Severities</option>
    <option value="0">🟢 Low Severity</option>
    <option value="1">🟡 Medium Severity</option>
    <option value="2">🔴 High Severity</option>
  </select>
);

export default Filters;