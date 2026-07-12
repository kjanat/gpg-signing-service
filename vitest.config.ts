import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.test.toml" },
		}),
	],
	test: {
		sequence: { concurrent: false },
		isolate: true,
		reporters: process.env.GITHUB_ACTIONS ? ["github-actions", "dot", "junit", "json"] : ["default"], // "dot",
		include: ["src/__tests__/**/*.{ts,js}"],
		exclude: ["**/*.d.ts", "node_modules/**"],
		coverage: {
			enabled: true,
			provider: "istanbul",
			reporter: ["text", "html", "json"],
			include: ["src/**/*.ts"],
			exclude: ["scripts", "dist", ".commitlintrc.ts", "vitest.config.ts"],
			// strict thresholds, if you modify this, you are fired !!!
			thresholds: { lines: 95, functions: 98, branches: 95, statements: 95 },
		},
	},
});
