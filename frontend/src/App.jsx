import React, { useState, useEffect, useCallback } from 'react';
import SummaryCards from './components/SummaryCards';
import FilterBar from './components/FilterBar';
import AlertsTable from './components/AlertsTable';
import { fetchAlerts, fetchSummary, triggerSync, fetchHealth } from './services/api';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [repository, setRepository] = useState('');
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [notification, setNotification] = useState(null);
  const [filters, setFilters] = useState({
    scanner: '',
    severity: '',
    state: '',
  });

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [alertsData, summaryData, healthData] = await Promise.all([
        fetchAlerts(filters),
        fetchSummary(),
        fetchHealth(),
      ]);

      setAlerts(alertsData);
      setSummary(summaryData);
      setRepository(healthData.repository_configured || summaryData.repository || 'Not configured');
    } catch (err) {
      console.error('Error fetching governance data:', err);
      setNotification({
        type: 'error',
        message: `Failed to connect to backend: ${err.message}. Ensure backend is running on http://localhost:8000.`,
      });
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Optional lightweight interval to auto-refresh data when webhooks arrive
  useEffect(() => {
    const timer = setInterval(() => {
      fetchAlerts(filters).then(setAlerts).catch(() => {});
      fetchSummary().then(setSummary).catch(() => {});
    }, 8000);
    return () => clearInterval(timer);
  }, [filters]);

  const handleSync = async () => {
    try {
      setSyncing(true);
      setNotification({
        type: 'info',
        message: 'Synchronizing security alerts from GitHub REST API...',
      });

      const res = await triggerSync();
      setNotification({
        type: 'success',
        message: `Synchronization successful! Retrieved ${res.dependabot_synced} Dependabot and ${res.code_scanning_synced} Code Scanning alert(s).`,
      });

      // Reload alerts and summary
      await loadData();
    } catch (err) {
      console.error('Sync error:', err);
      setNotification({
        type: 'error',
        message: `Sync failed: ${err.message}`,
      });
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="container">
      {/* Header */}
      <header className="header">
        <div className="header-title">
          <h1>GitHub Security Governance POC</h1>
          <div className="header-repo">
            Repository: <strong>{repository || 'github-security-governance-poc'}</strong>
          </div>
        </div>

        <div className="header-actions">
          <button
            className="btn btn-primary"
            onClick={handleSync}
            disabled={syncing}
          >
            {syncing ? '⏳ Syncing...' : '↻ Sync GitHub Alerts'}
          </button>
        </div>
      </header>

      {/* Notifications */}
      {notification && (
        <div className={`alert-banner ${notification.type}`}>
          <span>{notification.message}</span>
          <button
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontWeight: 'bold' }}
            onClick={() => setNotification(null)}
          >
            &times;
          </button>
        </div>
      )}

      {/* Metrics Summary Cards */}
      <SummaryCards summary={summary} />

      {/* Main Alerts Table Card */}
      <div className="content-card">
        <FilterBar
          filters={filters}
          setFilters={setFilters}
          onRefresh={loadData}
        />
        <AlertsTable alerts={alerts} loading={loading} />
      </div>
    </div>
  );
}
