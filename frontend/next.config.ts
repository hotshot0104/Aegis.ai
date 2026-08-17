import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  outputFileTracingRoot: import.meta.dirname,
  turbopack: {
    root: import.meta.dirname,
  },
  async headers() {
    return [
      {
        // Global security headers for all routes
        source: "/(.*)",
        headers: [
          {
            // Allow Pipedream OAuth popups to communicate with the opener window
            key: "Cross-Origin-Opener-Policy",
            value: "same-origin-allow-popups",
          },
          {
            // Prevent clickjacking
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            // Prevent MIME type sniffing
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            // Control referrer information
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            // HSTS — enforce HTTPS in production
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
          {
            // Restrict browser features
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
        ],
      },
    ];
  },
  async rewrites() {
    const backendUrl = process.env.BACKEND_INTERNAL_URL || "http://localhost:8000";
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendUrl}/api/v1/:path*`,
      },
      {
        source: "/health",
        destination: `${backendUrl}/health`,
      },
    ];
  },
};

export default nextConfig;
