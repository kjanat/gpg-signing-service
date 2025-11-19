import type { MiddlewareHandler } from "hono";
import type { Env } from "../types";

/**
 * Security headers middleware for production hardening
 */
export const securityHeaders: MiddlewareHandler<{ Bindings: Env }> = async (
  c,
  next,
) => {
  await next();

  // Security headers
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("X-XSS-Protection", "1; mode=block");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header(
    "Content-Security-Policy",
    "default-src 'none'; frame-ancestors 'none'",
  );
  c.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

  // Remove server identification
  c.res.headers.delete("Server");
  c.res.headers.delete("X-Powered-By");

  // Expose rate limit headers if present
  const rateLimitRemaining = c.res.headers.get("X-RateLimit-Remaining");
  if (rateLimitRemaining !== null) {
    c.header(
      "Access-Control-Expose-Headers",
      "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset",
    );
  }
};

/**
 * Production CORS middleware with restricted origins
 */
export const productionCors: MiddlewareHandler<{ Bindings: Env }> = async (
  c,
  next,
) => {
  const origin = c.req.header("Origin");
  const allowedOrigins = c.env.ALLOWED_ORIGINS?.split(",") ?? [];

  // Check if origin is allowed
  const isAllowed =
    allowedOrigins.length === 0 ||
    (origin !== undefined && allowedOrigins.includes(origin));

  if (c.req.method === "OPTIONS") {
    // Preflight request
    if (isAllowed && origin !== undefined) {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers":
            "Authorization, Content-Type, X-Request-ID",
          "Access-Control-Max-Age": "86400",
        },
      });
    }
    return new Response(null, { status: 204 });
  }

  await next();

  // Set CORS headers for allowed origins
  if (isAllowed && origin !== undefined) {
    c.header("Access-Control-Allow-Origin", origin);
    c.header("Access-Control-Allow-Credentials", "true");
  }

  return;
};
