/**
 * Test fixture for the OIDC subject allowlist.
 *
 * Signing through the OIDC path now requires a trusted-subject row, so any
 * suite that drives `/sign` with a JWT has to seed one. Mirrors the inline
 * table creation the other suites already do for `audit_logs` and
 * `service_tokens`.
 */

const CREATE_TABLE = `CREATE TABLE IF NOT EXISTS oidc_subjects (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	issuer TEXT NOT NULL,
	subject_prefix TEXT NOT NULL,
	key_ids TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	expires_at TEXT,
	revoked_at TEXT,
	last_used_at TEXT
);`;

/**
 * The partial unique index from migration 0003. Without it the test schema is
 * weaker than production, so a duplicate (issuer, prefix) inserts cleanly here
 * and fails in the real database — which is how the revoke lockout went
 * unnoticed.
 */
const CREATE_INDEX = `CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_subjects_issuer_prefix
	ON oidc_subjects (issuer, subject_prefix) WHERE revoked_at IS NULL;`;

/** Issuers the suites mint tokens for. */
const TEST_ISSUERS = [
	"https://token.actions.githubusercontent.com",
	"https://token.actions.githubusercontent.com/unique-test-issuer",
	"https://gitlab.com",
];

/** Subjects the suites sign with. */
const TEST_SUBJECT_PREFIXES = ["test", "test-subject", "subject", "repo:user/repo"];

/**
 * Create the table and trust every issuer/subject pair the tests use, with no
 * key restriction. Safe to call repeatedly.
 *
 * @param db - The test D1 binding
 */
export async function seedTrustedSubjects(db: D1Database): Promise<void> {
	await db.prepare(CREATE_TABLE).run();
	await db.prepare(CREATE_INDEX).run();

	const createdAt = new Date().toISOString();
	for (const issuer of TEST_ISSUERS) {
		for (const prefix of TEST_SUBJECT_PREFIXES) {
			await db
				.prepare(
					`INSERT OR IGNORE INTO oidc_subjects (id, name, issuer, subject_prefix, key_ids, created_at)
					 VALUES (?, ?, ?, ?, '', ?)`,
				)
				.bind(crypto.randomUUID(), `${issuer}|${prefix}`, issuer, prefix, createdAt)
				.run();
		}
	}
}

/** Drop every trusted subject, for tests that assert the deny path. */
export async function clearTrustedSubjects(db: D1Database): Promise<void> {
	await db.prepare(CREATE_TABLE).run();
	await db.prepare(CREATE_INDEX).run();
	await db.prepare("DELETE FROM oidc_subjects").run();
}
