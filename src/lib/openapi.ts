import { OpenAPIHono } from "@hono/zod-openapi";
import type { Env, Variables } from "~/types";

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
