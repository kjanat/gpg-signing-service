/// <reference types="@cloudflare/vitest-pool-workers/types" />

// `import("cloudflare:test").env` is typed as `Cloudflare.Env` since
// vitest-pool-workers 0.18; augment it with the test vars and secrets from
// wrangler.test.toml that the generated worker-configuration.d.ts lacks.
declare namespace Cloudflare {
	interface Env {
		/** Token for admin endpoints */
		ADMIN_TOKEN: string;

		/** Passphrase for encrypted private key */
		KEY_PASSPHRASE: string;

		/** Comma-separated list of allowed issuers */
		ALLOWED_ISSUERS: string;

		/** Allowed origins for CORS */
		ALLOWED_ORIGINS?: string;

		/** ID of the signing key */
		KEY_ID: string;
	}
}
