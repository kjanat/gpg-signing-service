import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
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
      thresholds: { lines: 10, functions: 10, branches: 0, statements: 10 },
    },
  },
});
