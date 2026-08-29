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

// Optional vars a suite overrides per request. `wrangler types` only writes the
// keys wrangler.toml declares, and these are deliberately absent from it — they
// are opt-in per deployment — so the global `Env` the tests build overrides
// against has to be told about them here.
interface Env {
	/** Public origin the `docs` link on an error response is built from. */
	SERVICE_BASE_URL?: string;

	/** Document that `/e/:code` redirects into. */
	ERROR_DOCS_URL?: string;

	/** "true" to name the trusted subject prefixes in an untrusted-subject 401. */
	DISCLOSE_TRUST_PATTERNS?: string;
}

// Vite's `?raw` suffix, used by the error-docs suite to read `docs/errors.md`.
// The Workers pool has no filesystem, so inlining the file at build time is the
// only way a test can check that every code the enum declares has a section to
// link to.
declare module "*.md?raw" {
	const content: string;
	export default content;
}

// Same mechanism for `wrangler.toml`, which the key-expiry suite reads so the
// active-key rule is asserted against the real deployment config rather than a
// hand-copied excerpt that can drift away from it.
declare module "*.toml?raw" {
	const content: string;
	export default content;
}
