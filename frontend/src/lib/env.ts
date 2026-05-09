export const env = {
  // If unset, we default to same-origin `/api` so Vite's dev proxy works (no CORS headaches).
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL || '',
}

