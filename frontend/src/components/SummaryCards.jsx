import React from 'react';

export default function SummaryCards({ summary }) {
  const {
    total_alerts = 0,
    dependabot_alerts = 0,
    code_scanning_alerts = 0,
    open_alerts = 0,
    by_severity = { critical: 0, high: 0, medium: 0, low: 0 }
  } = summary || {};

  return (
    <div className="summary-grid">
      <div className="summary-card">
        <div className="summary-card-label">Total Alerts</div>
        <div className="summary-card-value">{total_alerts}</div>
        <div className="severity-pills">
          <span className="severity-pill badge-critical">{by_severity.critical} Critical</span>
          <span className="severity-pill badge-high">{by_severity.high} High</span>
          <span className="severity-pill badge-medium">{by_severity.medium} Med</span>
          <span className="severity-pill badge-low">{by_severity.low} Low</span>
        </div>
      </div>

      <div className="summary-card">
        <div className="summary-card-label">Dependabot Alerts</div>
        <div className="summary-card-value" style={{ color: '#8250df' }}>
          {dependabot_alerts}
        </div>
        <div className="alert-meta">SCA (Software Composition Analysis)</div>
      </div>

      <div className="summary-card">
        <div className="summary-card-label">Code Scanning Alerts</div>
        <div className="summary-card-value" style={{ color: '#1a7f37' }}>
          {code_scanning_alerts}
        </div>
        <div className="alert-meta">SAST (CodeQL Static Analysis)</div>
      </div>

      <div className="summary-card">
        <div className="summary-card-label">Open Alerts</div>
        <div className="summary-card-value" style={{ color: '#cf222e' }}>
          {open_alerts}
        </div>
        <div className="alert-meta">Requiring triage or remediation</div>
      </div>
    </div>
  );
}
