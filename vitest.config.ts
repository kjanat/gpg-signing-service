import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import path from "node:path";

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
      reporter: ["text", "json", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.{test,spec}.ts", "src/__tests__/**", "src/types/**"],
      thresholds: { lines: 60, functions: 70, branches: 50, statements: 60 },
    },
  },
});
