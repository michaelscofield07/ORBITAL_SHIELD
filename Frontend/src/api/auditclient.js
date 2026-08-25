const API_BASE = "http://127.0.0.1:8001";

export async function fetchEvents() {
  const response = await fetch(`${API_BASE}/audit/events`);
  if (!response.ok) throw new Error("Failed to fetch events");
  return response.json();
}

export async function submitReview(eventId, status, reviewedBy = "admin_user") {
  const response = await fetch(
    `${API_BASE}/audit/${eventId}/review?status=${status}&reviewed_by=${reviewedBy}`,
    { method: "POST" }
  );
  if (!response.ok) throw new Error("Review update failed");
  return response.json();
}

export async function verifyChain() {
  const response = await fetch(`${API_BASE}/audit/verify`);
  if (!response.ok) throw new Error("Chain verification failed");
  return response.json();
}

export function downloadReport(eventId) {
  window.open(`${API_BASE}/audit/${eventId}/report`, "_blank");
}
