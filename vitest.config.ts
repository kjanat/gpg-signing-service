import path from "node:path";
import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  resolve: {
    alias: {
      "~": path.resolve(__dirname, "./src"),
      "gpg-signing-service": path.resolve(__dirname, "./src/index.ts"),
    },
  },
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.test.toml" },
        isolatedStorage: false, // Disable isolated storage for simpler testing
      },
    },
    sequence: { concurrent: false },
    isolate: true,
    reporters: process.env.GITHUB_ACTIONS
      ? ["github-actions", "dot", "junit", "json"]
      : ["default"], // "dot",
    include: ["src/__tests__/**/*.{ts,js}"],
    exclude: ["**/*.d.ts", "node_modules/**"],
    coverage: {
      enabled: true,
      provider: "istanbul",
      reporter: ["text", "html", "json"],
      include: ["src/**/*.ts"],
      exclude: ["scripts", "dist", ".commitlint.ts", "vitest.config.ts"],
      // strict thresholds, if you modify this, you are fired !!!
      thresholds: { lines: 95, functions: 98, branches: 95, statements: 95 },
    },
  },
});
