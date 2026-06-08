const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

async function request(path, options) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  return response.json();
}

export const api = {
  health: () => request("/health"),
  recentAlerts: (size = 1000) => request(`/alerts/recent?size=${size}`),
  suricataAlerts: (size = 1000) => request(`/alerts/suricata?size=${size}`),
  highAlerts: () => request("/alerts/high"),
  searchAlerts: (query, size = 1000) => request(`/alerts/search?query=${encodeURIComponent(query || "*")}&size=${size}`),
  alert: (id) => request(`/alerts/${encodeURIComponent(id)}`),
  investigate: (id) => request(`/investigate/${encodeURIComponent(id)}`, { method: "POST" }),
  hunt: (payload) => request("/hunt", { method: "POST", body: JSON.stringify(payload) }),
};
