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
    include: ["src/**/*.{test,spec}.{js,ts}"],
    coverage: {
      provider: "istanbul",
      reporter: process.env.CI
        ? ["lcov", "json"]
        : ["text", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.{test,spec}.ts", "src/__tests__/**", "src/types/**"],
      // strict thresholds, if you modify this, you are fired !!!
      thresholds: { lines: 95, functions: 98, branches: 95, statements: 95 },
    },
  },
});
