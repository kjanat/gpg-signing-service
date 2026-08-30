/// <reference types="@cloudflare/vitest-pool-workers/types" />

// `import("cloudflare:test").env` is typed as `Cloudflare.Env` since
// vitest-pool-workers 0.18; augment it with the test vars and secrets from
// wrangler.test.toml that the generated worker-configuration.d.ts lacks.
declare namespace Cloudflare {
	interface Env {
		/** Token for admin endpoints */
		ADMIN_TOKEN: string;

		/** Admin token accepted on GET and HEAD only; refused 403 on the rest. */
		ADMIN_READONLY_TOKEN: string;

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

// The same suffix on the shell example. `docs-contract.test.ts` holds its `503`
// branch against the codes the reference sorts onto that status, because two of
// them land there and they disagree about carrying a `Retry-After`.
declare module "*.sh?raw" {
	const content: string;
	export default content;
}

// Vite's `import.meta.glob`, narrowed to the one form `docs-contract.test.ts`
// uses: eager, `?raw`, default export. `vite/client` declares it in full, but
// this directory's tsconfig loads only the Workers pool's types, and pulling in
// the whole client surface to type one call is a worse trade than six lines.
interface ImportMeta {
	glob<T = string>(pattern: string, options: { query: "?raw"; import: "default"; eager: true }): Record<string, T>;
}
