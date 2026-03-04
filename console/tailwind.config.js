// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        // Severity palette
        severity: {
          critical: "#dc2626", // red-600
          high: "#ea580c",     // orange-600
          medium: "#ca8a04",   // yellow-600
          low: "#2563eb",      // blue-600
          info: "#6b7280",     // gray-500
        },
        // Brand
        brand: {
          DEFAULT: "#1e40af", // blue-800
          light: "#3b82f6",   // blue-500
        },
      },
    },
  },
  plugins: [],
};
