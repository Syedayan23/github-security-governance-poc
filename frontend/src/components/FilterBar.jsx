import React from 'react';

export default function FilterBar({ filters, setFilters, onRefresh }) {
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFilters((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  return (
    <div className="table-toolbar">
      <div className="filter-group">
        <label htmlFor="scanner-select">Scanner:</label>
        <select
          id="scanner-select"
          name="scanner"
          value={filters.scanner || ''}
          onChange={handleChange}
        >
          <option value="">All Scanners</option>
          <option value="dependabot">Dependabot (SCA)</option>
          <option value="code_scanning">Code Scanning (CodeQL)</option>
        </select>

        <label htmlFor="severity-select">Severity:</label>
        <select
          id="severity-select"
          name="severity"
          value={filters.severity || ''}
          onChange={handleChange}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <label htmlFor="state-select">Status:</label>
        <select
          id="state-select"
          name="state"
          value={filters.state || ''}
          onChange={handleChange}
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="fixed">Fixed</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </div>

      <div>
        <button className="btn btn-secondary" onClick={onRefresh} title="Reload alerts from local database">
          ↻ Refresh View
        </button>
      </div>
    </div>
  );
}
