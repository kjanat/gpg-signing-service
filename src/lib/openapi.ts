import { OpenAPIHono } from "@hono/zod-openapi";
import type { Env, Variables } from "~/types";

/**
 * OpenAPI configuration
 */
export const openApiConfig = {
  // OpenAPI 3.1.x is not yet supported by `oapi-codegen`
  // See https://github.com/oapi-codegen/oapi-codegen/issues/373
  openapi: "3.0.0",
  info: { version: "1.0.0", title: "GPG Signing Service API" },
  components: {
    securitySchemes: {
      oidcAuth: {
        type: "http" as const,
        scheme: "bearer",
        bearerFormat: "JWT",
        description: "OIDC token from GitHub Actions or GitLab CI",
      },
      bearerAuth: {
        type: "http" as const,
        scheme: "bearer",
        bearerFormat: "JWT",
        description: "Admin token for /admin/* endpoints",
      },
    },
  },
};

export function createOpenAPIApp() {
  return new OpenAPIHono<{ Bindings: Env; Variables: Variables }>({
    defaultHook: (result, c) => {
      if (!result.success) {
        return c.json(
          {
            error: "Validation failed",
            code: "INVALID_REQUEST",
            issues: result.error.issues,
          },
          400,
        );
      }
      return;
    },
  });
}
