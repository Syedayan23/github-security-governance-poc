/**
 * API service for interacting with the FastAPI backend.
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

async function handleResponse(response) {
  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errorJson = await response.json();
      if (errorJson.detail) {
        errorMessage = errorJson.detail;
      }
    } catch {
      // ignore
    }
    throw new Error(errorMessage);
  }
  return response.json();
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return handleResponse(res);
}

export async function fetchSummary() {
  const res = await fetch(`${API_BASE}/alerts/summary`);
  return handleResponse(res);
}

export async function fetchAlerts(filters = {}) {
  const params = new URLSearchParams();
  if (filters.scanner) params.append('scanner', filters.scanner);
  if (filters.severity) params.append('severity', filters.severity);
  if (filters.state) params.append('state', filters.state);

  const query = params.toString() ? `?${params.toString()}` : '';
  const res = await fetch(`${API_BASE}/alerts${query}`);
  return handleResponse(res);
}

export async function triggerSync() {
  const res = await fetch(`${API_BASE}/sync`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  return handleResponse(res);
}
