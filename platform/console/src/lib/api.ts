import axios from "axios";

export const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8888",
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Attach auth token from Keycloak on each request
apiClient.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = sessionStorage.getItem("kc_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Retry on 401 (token refresh)
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Phase 1: trigger Keycloak token refresh
      sessionStorage.removeItem("kc_token");
    }
    return Promise.reject(error);
  }
);
