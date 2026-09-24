import React from 'react';

function formatDate(isoStr) {
  if (!isoStr) return '-';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoStr;
  }
}

function getSeverityBadgeClass(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 'badge-critical';
    case 'high':
      return 'badge-high';
    case 'medium':
      return 'badge-medium';
    case 'low':
      return 'badge-low';
    default:
      return 'badge-low';
  }
}

function getScannerBadgeClass(scanner) {
  switch ((scanner || '').toLowerCase()) {
    case 'dependabot':
      return 'badge-dependabot';
    case 'code_scanning':
      return 'badge-codescanning';
    default:
      return 'badge-scanner';
  }
}

function getStateBadgeClass(state) {
  switch ((state || '').toLowerCase()) {
    case 'open':
      return 'badge-open';
    case 'fixed':
      return 'badge-fixed';
    case 'dismissed':
      return 'badge-dismissed';
    default:
      return 'badge-open';
  }
}

export default function AlertsTable({ alerts, loading }) {
  if (loading) {
    return (
      <div className="empty-state">
        <p>Loading security alerts...</p>
      </div>
    );
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="empty-state">
        <h3>No Security Alerts Found</h3>
        <p>
          Click <strong>"Sync GitHub Alerts"</strong> to fetch alerts from your repository,
          or configure the GitHub Webhook for real-time notifications.
        </p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Scanner</th>
            <th>Severity</th>
            <th>Alert</th>
            <th>Status</th>
            <th>Created</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>
                <span className={`badge ${getScannerBadgeClass(alert.scanner)}`}>
                  {alert.scanner === 'dependabot' ? 'Dependabot' : 'CodeQL'}
                </span>
              </td>
              <td>
                <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                  {alert.severity}
                </span>
              </td>
              <td>
                <div className="alert-title">
                  {alert.title}
                  {alert.html_url && (
                    <a
                      href={alert.html_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="alert-link"
                      title="View on GitHub"
                    >
                      ↗ View on GitHub
                    </a>
                  )}
                </div>
                <div className="alert-meta">
                  <strong>{alert.scanner === 'dependabot' ? 'Package: ' : 'Rule: '}</strong>
                  <code>{alert.package_or_rule}</code>
                  {alert.affected_file && (
                    <span> &bull; File: <code>{alert.affected_file}</code></span>
                  )}
                </div>
              </td>
              <td>
                <span className={`badge ${getStateBadgeClass(alert.state)}`}>
                  {alert.state}
                </span>
              </td>
              <td style={{ whiteSpace: 'nowrap', fontSize: '0.85rem' }}>
                {formatDate(alert.created_at)}
              </td>
              <td style={{ whiteSpace: 'nowrap', fontSize: '0.85rem' }}>
                {formatDate(alert.updated_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
