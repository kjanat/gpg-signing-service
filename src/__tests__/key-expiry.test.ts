import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import {
	type ActiveKey,
	type ActiveKeySet,
	actionableRows,
	classifyExpiry,
	DEFAULT_WARN_DAYS,
	daysUntil,
	describeActivation,
	effectiveExpiry,
	extractDefaultKeyId,
	isGrantLive,
	KEY_ROTATION_DOCS_URL,
	type KeyExpiryRow,
	type KeyGrant,
	keyMaterialExpiry,
	missingKeyRow,
	parseWarnDays,
	pgpKeyExpiry,
	type ReportContext,
	renderReport,
	resolveActiveKeys,
	x509CertificateExpiry,
} from "#utils/key-expiry";
import realWranglerToml from "../../wrangler.toml?raw";

/** Fixed clock so every threshold assertion is a pure date comparison */
const NOW = new Date("2026-08-29T00:00:00.000Z");
const DAY_MS = 24 * 60 * 60 * 1000;

/** A date `days` from NOW, positive for the future */
function fromNow(days: number): Date {
	return new Date(NOW.getTime() + days * DAY_MS);
}

/** The production key from wrangler.toml, per issue #44 */
const PRODUCTION_KEY_ID = "62E75E54497815DD";

describe("parseWarnDays", () => {
	it("defaults to 60 days when unset or blank", () => {
		expect(parseWarnDays(undefined)).toBe(DEFAULT_WARN_DAYS);
		expect(parseWarnDays("")).toBe(DEFAULT_WARN_DAYS);
		expect(parseWarnDays("   ")).toBe(DEFAULT_WARN_DAYS);
		expect(DEFAULT_WARN_DAYS).toBe(60);
	});

	it("accepts a positive whole number of days", () => {
		expect(parseWarnDays("30")).toBe(30);
		expect(parseWarnDays(" 90 ")).toBe(90);
		expect(parseWarnDays("1")).toBe(1);
	});

	it("rejects rather than silently falling back to the default", () => {
		// A typo'd threshold that quietly becomes 60 is a check that lies about
		// what it enforced, so every one of these has to throw.
		for (const bad of ["0", "-30", "30.5", "sixty", "60d", "NaN", "Infinity"]) {
			expect(() => parseWarnDays(bad)).toThrow(/KEY_EXPIRY_WARN_DAYS/);
		}
	});
});

describe("daysUntil", () => {
	it("floors to whole days ahead", () => {
		expect(daysUntil(fromNow(60), NOW)).toBe(60);
		// 59 days and 23 hours has not yet completed its 60th day.
		expect(daysUntil(new Date(NOW.getTime() + 59 * DAY_MS + 23 * 60 * 60 * 1000), NOW)).toBe(59);
	});

	it("goes negative once the date has passed", () => {
		expect(daysUntil(fromNow(-1), NOW)).toBe(-1);
		expect(daysUntil(fromNow(-400), NOW)).toBe(-400);
	});
});

describe("classifyExpiry", () => {
	it("reports a key well beyond the threshold as ok", () => {
		const row = classifyExpiry("AAAABBBBCCCCDDDD", { kind: "date", expiresAt: fromNow(365) }, NOW, 60);
		expect(row).toMatchObject({ state: "ok", daysRemaining: 365 });
		expect(row.expiresAt).toBe(fromNow(365).toISOString());
	});

	it("warns inclusively at the threshold boundary", () => {
		// Exactly `warnDays` out is already inside the window; one day more is not.
		expect(classifyExpiry("K", { kind: "date", expiresAt: fromNow(60) }, NOW, 60).state).toBe("warning");
		expect(classifyExpiry("K", { kind: "date", expiresAt: fromNow(61) }, NOW, 60).state).toBe("ok");
		expect(classifyExpiry("K", { kind: "date", expiresAt: fromNow(59) }, NOW, 60).state).toBe("warning");
	});

	it("honours a non-default threshold", () => {
		expect(classifyExpiry("K", { kind: "date", expiresAt: fromNow(45) }, NOW, 30).state).toBe("ok");
		expect(classifyExpiry("K", { kind: "date", expiresAt: fromNow(45) }, NOW, 90).state).toBe("warning");
	});

	it("reports a lapsed key as expired with negative days", () => {
		const row = classifyExpiry("K", { kind: "date", expiresAt: fromNow(-3) }, NOW, 60);
		expect(row).toMatchObject({ state: "expired", daysRemaining: -3 });
	});

	it("treats expiry exactly at now as expired, not as a warning", () => {
		expect(classifyExpiry("K", { kind: "date", expiresAt: new Date(NOW) }, NOW, 60).state).toBe("expired");
	});

	it("passes through never-expiring and unreadable keys", () => {
		expect(classifyExpiry("K", { kind: "never" }, NOW, 60)).toEqual({
			keyId: "K",
			state: "no-expiry",
			expiresAt: null,
			daysRemaining: null,
		});
		expect(classifyExpiry("K", { kind: "unknown", reason: "revoked" }, NOW, 60)).toMatchObject({
			state: "unknown",
			detail: "revoked",
		});
	});

	it("classifies the production key against its documented expiry", () => {
		// Issue #44: 62E75E54497815DD expires 2027-11-19. It must read as ok
		// today and as a warning once the check runs inside the window.
		const expiresAt = new Date("2027-11-19T00:00:00.000Z");
		expect(classifyExpiry(PRODUCTION_KEY_ID, { kind: "date", expiresAt }, NOW, 60).state).toBe("ok");

		const insideWindow = new Date("2027-10-01T00:00:00.000Z");
		const row = classifyExpiry(PRODUCTION_KEY_ID, { kind: "date", expiresAt }, insideWindow, 60);
		expect(row).toMatchObject({ keyId: PRODUCTION_KEY_ID, state: "warning", daysRemaining: 49 });

		const afterwards = new Date("2027-12-01T00:00:00.000Z");
		expect(classifyExpiry(PRODUCTION_KEY_ID, { kind: "date", expiresAt }, afterwards, 60).state).toBe("expired");
	});
});

describe("extractDefaultKeyId", () => {
	/** The shape of the real file: a top-level `[vars]` and a staging one. */
	const toml = [
		"#:schema node_modules/wrangler/config-schema.json",
		'name = "gpg-signing-service"',
		"",
		"[vars]",
		'ALLOWED_ISSUERS = "https://token.actions.githubusercontent.com"',
		`KEY_ID          = "${PRODUCTION_KEY_ID}"`,
		'# KEY_ID        = "DEADBEEFDEADBEEF"',
		"",
		"[env.staging]",
		'name = "gpg-signing-service-staging"',
		"",
		"[[env.staging.routes]]",
		'pattern = "staging.gpg.kajkowalski.nl"',
		"",
		"[env.staging.vars]",
		'KEY_ID      = "aaaabbbbccccdddd"',
		'ENVIRONMENT = "staging"',
	].join("\n");

	it("reads the top-level environment by default", () => {
		expect(extractDefaultKeyId(toml)).toEqual({ env: null, keyId: PRODUCTION_KEY_ID, envExists: true });
	});

	it("reads a named environment's own KEY_ID, not the top-level one", () => {
		// The whole point of the scoping: checking production must not report
		// staging's key as missing, week after week, until someone mutes it.
		expect(extractDefaultKeyId(toml, "staging")).toEqual({
			env: "staging",
			keyId: "AAAABBBBCCCCDDDD",
			envExists: true,
		});
	});

	it("ignores commented-out and unrelated declarations", () => {
		const noisy = [
			"[vars]",
			'# KEY_ID = "DEADBEEFDEADBEEF"',
			'OTHER_KEY_ID = "1111222233334444"',
			`KEY_ID = "${PRODUCTION_KEY_ID}"`,
		].join("\n");
		expect(extractDefaultKeyId(noisy).keyId).toBe(PRODUCTION_KEY_ID);
	});

	it("does not read KEY_ID from a table that is not the environment's vars", () => {
		const misplaced = ["[env.staging.vars]", `KEY_ID = "${PRODUCTION_KEY_ID}"`].join("\n");
		expect(extractDefaultKeyId(misplaced).keyId).toBeNull();
	});

	it("reports an environment that declares no KEY_ID rather than borrowing one", () => {
		// Wrangler does not inherit `vars` into named environments, so falling
		// back to the top-level value would report a key this deployment does not
		// actually sign with by default.
		const bare = ["[vars]", `KEY_ID = "${PRODUCTION_KEY_ID}"`, "[env.preview]", 'name = "preview"'].join("\n");
		expect(extractDefaultKeyId(bare, "preview")).toEqual({ env: "preview", keyId: null, envExists: true });
	});

	it("flags an environment the file does not define", () => {
		expect(extractDefaultKeyId(toml, "typo").envExists).toBe(false);
		expect(extractDefaultKeyId(toml, "staging").envExists).toBe(true);
	});

	it("finds the production key in the real wrangler.toml", () => {
		// Against the real file, not an excerpt: the rule is only worth anything
		// if it holds for the config this repository actually deploys.
		expect(extractDefaultKeyId(realWranglerToml)).toEqual({ env: null, keyId: PRODUCTION_KEY_ID, envExists: true });
		expect(extractDefaultKeyId(realWranglerToml, "staging")).toEqual({
			env: "staging",
			keyId: PRODUCTION_KEY_ID,
			envExists: true,
		});
		expect(extractDefaultKeyId(realWranglerToml, "production").envExists).toBe(false);
	});
});

describe("isGrantLive", () => {
	const grant = (over: Partial<KeyGrant>): KeyGrant => ({
		kind: "service-token",
		name: "ci",
		keyIds: null,
		expiresAt: null,
		revokedAt: null,
		...over,
	});

	it("honours a grant with no expiry", () => {
		expect(isGrantLive(grant({}), NOW)).toBe(true);
	});

	it("drops a revoked grant even when it has not expired", () => {
		expect(
			isGrantLive(grant({ revokedAt: fromNow(-1).toISOString(), expiresAt: fromNow(90).toISOString() }), NOW),
		).toBe(false);
	});

	it("drops an expired grant", () => {
		expect(isGrantLive(grant({ expiresAt: fromNow(-1).toISOString() }), NOW)).toBe(false);
	});

	it("keeps a grant expiring exactly now, as the sign path does", () => {
		// `verifyServiceToken` refuses only on `expires_at < now`, so the boundary
		// instant is still live. A stricter rule here would drop a key the service
		// would still sign with.
		expect(isGrantLive(grant({ expiresAt: NOW.toISOString() }), NOW)).toBe(true);
	});

	it("treats an unparseable expiry as live, mirroring the server", () => {
		// Date.parse yields NaN and every comparison against it is false, so the
		// server honours the row. The monitor has to agree or it under-reports.
		expect(isGrantLive(grant({ expiresAt: "not a date" }), NOW)).toBe(true);
	});
});

describe("resolveActiveKeys", () => {
	const STORED_A = "AAAABBBBCCCCDDDD";
	const defaultKey = { env: null, keyId: PRODUCTION_KEY_ID, envExists: true };
	const grant = (over: Partial<KeyGrant>): KeyGrant => ({
		kind: "service-token",
		name: "ci",
		keyIds: null,
		expiresAt: null,
		revokedAt: null,
		...over,
	});

	it("leaves a retained key alone when no live grant reaches it", () => {
		// The false-alarm case: an old key kept on purpose, and every credential
		// scoped away from it. Warning about it teaches people to mute the monitor.
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID, STORED_A],
			defaultKey,
			grants: [grant({ name: "prod-ci", keyIds: [PRODUCTION_KEY_ID] })],
			now: NOW,
		});

		expect(scope.keys.map((key) => key.keyId)).toEqual([PRODUCTION_KEY_ID]);
		expect(scope.retainedInactive).toEqual([STORED_A]);
	});

	it("treats storage as the boundary only when a live grant pins no key ids", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID, STORED_A],
			defaultKey,
			grants: [grant({ name: "anything" })],
			now: NOW,
		});

		expect(scope.keys.map((key) => key.keyId)).toEqual(
			[PRODUCTION_KEY_ID, STORED_A].sort((a, b) => a.localeCompare(b)),
		);
		expect(scope.unrestrictedGrants).toEqual(["service-token:anything"]);
		expect(scope.retainedInactive).toEqual([]);
		expect(scope.keys.find((key) => key.keyId === STORED_A)?.reasons).toEqual(["unrestricted-grant"]);
	});

	it("ignores revoked and expired grants", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID, STORED_A],
			defaultKey,
			grants: [
				grant({ name: "dead", keyIds: [STORED_A], revokedAt: fromNow(-1).toISOString() }),
				grant({ kind: "oidc-subject", name: "old", expiresAt: fromNow(-1).toISOString() }),
			],
			now: NOW,
		});

		expect(scope.keys.map((key) => key.keyId)).toEqual([PRODUCTION_KEY_ID]);
		expect(scope.retainedInactive).toEqual([STORED_A]);
		expect(scope).toMatchObject({ liveGrantCount: 0, totalGrantCount: 2, unrestrictedGrants: [] });
	});

	it("keeps the configured default even with no live grant at all", () => {
		// It is what this environment signs with the moment anyone is trusted
		// again, so its lapsing is still news.
		const scope = resolveActiveKeys({ storedKeyIds: [PRODUCTION_KEY_ID], defaultKey, grants: [], now: NOW });
		expect(scope.keys).toEqual([{ keyId: PRODUCTION_KEY_ID, reasons: ["default"], grants: [], stored: true }]);
	});

	it("marks a granted key the deployment does not hold as unstored", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID],
			defaultKey,
			grants: [grant({ name: "stale", keyIds: [STORED_A] })],
			now: NOW,
		});

		expect(scope.keys.find((key) => key.keyId === STORED_A)).toEqual({
			keyId: STORED_A,
			reasons: ["grant"],
			grants: ["service-token:stale"],
			stored: false,
		});
	});

	it("does not invent an active key when the environment declares none", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID],
			defaultKey: { env: "preview", keyId: null, envExists: true },
			grants: [],
			now: NOW,
		});

		expect(scope.keys).toEqual([]);
		expect(scope.retainedInactive).toEqual([PRODUCTION_KEY_ID]);
	});

	it("merges every reason and grant that reaches one key", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID],
			defaultKey,
			grants: [
				grant({ kind: "oidc-subject", name: "repo:kjanat/svc", keyIds: [PRODUCTION_KEY_ID] }),
				grant({ name: "anything" }),
			],
			now: NOW,
		});

		expect(scope.keys[0]).toEqual({
			keyId: PRODUCTION_KEY_ID,
			reasons: ["default", "grant", "unrestricted-grant"],
			grants: ["oidc-subject:repo:kjanat/svc", "service-token:anything"],
			stored: true,
		});
	});

	it("compares key ids case-insensitively across config, grants and storage", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: ["aaaabbbbccccdddd"],
			defaultKey: { env: null, keyId: STORED_A, envExists: true },
			grants: [grant({ name: "lower", keyIds: ["aaaabbbbccccdddd"] })],
			now: NOW,
		});

		expect(scope.keys).toHaveLength(1);
		expect(scope.keys[0]).toMatchObject({ keyId: STORED_A, stored: true });
	});
});

describe("describeActivation", () => {
	const key = (over: Partial<ActiveKey>): ActiveKey => ({
		keyId: PRODUCTION_KEY_ID,
		reasons: [],
		grants: [],
		stored: true,
		...over,
	});

	it("names the default, the grants, or both", () => {
		expect(describeActivation(key({ reasons: ["default"] }))).toBe("`KEY_ID` default");
		expect(describeActivation(key({ reasons: ["grant"], grants: ["service-token:ci"] }))).toBe(
			"granted to `service-token:ci`",
		);
		expect(describeActivation(key({ reasons: ["default", "grant"], grants: ["service-token:ci"] }))).toBe(
			"`KEY_ID` default; granted to `service-token:ci`",
		);
	});

	it("says when a key is only reachable through an any-key grant", () => {
		expect(describeActivation(key({ reasons: ["unrestricted-grant"], grants: ["service-token:ci"] }))).toBe(
			"any-key grant `service-token:ci`",
		);
	});

	it("falls back to a dash when nothing explains the key", () => {
		// Defensive: every key in a resolved set carries at least one reason, so
		// this only fires if that invariant is ever broken.
		expect(describeActivation(key({}))).toBe("—");
	});

	it("truncates a long grant list rather than flooding the table", () => {
		const grants = ["a", "b", "c", "d"].map((name) => `service-token:${name}`);
		expect(describeActivation(key({ reasons: ["grant"], grants }))).toBe(
			"granted to `service-token:a`, `service-token:b` +2 more",
		);
	});
});

describe("pgpKeyExpiry", () => {
	it("reads the expiry date out of the key material", async () => {
		const seconds = 120 * 24 * 60 * 60;
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Expiring", email: "expiring@test.com" }],
			keyExpirationTime: seconds,
			format: "armored",
		});

		const expiry = await pgpKeyExpiry(publicKey);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		const key = await openpgp.readKey({ armoredKey: publicKey });
		// The key was created "now", so its expiry is creation + 120 days.
		const expected = key.getCreationTime().getTime() + seconds * 1000;
		expect(expiry.expiresAt.getTime()).toBe(expected);
	});

	it("reports a key with no expiration date as never expiring", async () => {
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Forever", email: "forever@test.com" }],
			format: "armored",
		});

		expect(await pgpKeyExpiry(publicKey)).toEqual({ kind: "never" });
	});

	it("classifies an already-expired key rather than hiding it", async () => {
		// openpgp refuses to hand back an expired signing key under its default
		// validity filtering; the check looks it up with date checks disabled so
		// the key still reaches the report.
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Lapsed", email: "lapsed@test.com" }],
			date: new Date(NOW.getTime() - 400 * DAY_MS),
			keyExpirationTime: 30 * 24 * 60 * 60,
			format: "armored",
		});

		const expiry = await pgpKeyExpiry(publicKey);
		expect(expiry.kind).toBe("date");
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("expired");
	});

	it("prefers a signing subkey that lapses before the primary key", async () => {
		// Commits are signed by the signing subkey, so a subkey that lapses first
		// is the date that actually stops signing working.
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Subkey", email: "subkey@test.com" }],
			keyExpirationTime: 400 * 24 * 60 * 60,
			subkeys: [{ sign: true, keyExpirationTime: 30 * 24 * 60 * 60 }, {}],
			format: "armored",
		});

		const expiry = await pgpKeyExpiry(publicKey);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		const key = await openpgp.readKey({ armoredKey: publicKey });
		const created = key.getCreationTime().getTime();
		expect(expiry.expiresAt.getTime()).toBe(created + 30 * 24 * 60 * 60 * 1000);
		// ...and not the primary key's much later date.
		expect(expiry.expiresAt.getTime()).toBeLessThan(created + 400 * 24 * 60 * 60 * 1000);
	});

	it("keeps the primary key's date when the signing subkey outlives it", async () => {
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Primary", email: "primary@test.com" }],
			keyExpirationTime: 30 * 24 * 60 * 60,
			subkeys: [{ sign: true }, {}],
			format: "armored",
		});

		const expiry = await pgpKeyExpiry(publicKey);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		const key = await openpgp.readKey({ armoredKey: publicKey });
		expect(expiry.expiresAt.getTime()).toBe(key.getCreationTime().getTime() + 30 * 24 * 60 * 60 * 1000);
	});

	it("takes the subkey's date when the primary key never expires", async () => {
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Mixed", email: "mixed@test.com" }],
			subkeys: [{ sign: true, keyExpirationTime: 45 * 24 * 60 * 60 }, {}],
			format: "armored",
		});

		const expiry = await pgpKeyExpiry(publicKey);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		const key = await openpgp.readKey({ armoredKey: publicKey });
		expect(expiry.expiresAt.getTime()).toBe(key.getCreationTime().getTime() + 45 * 24 * 60 * 60 * 1000);
	});

	it("reports a revoked key rather than passing it off as healthy", async () => {
		// A revoked key's expiration subpacket is untouched by the revocation, so
		// reading only `getExpirationTime()` would call this key `ok` while every
		// verifier rejects its signatures.
		const { publicKey, revocationCertificate } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Revoked", email: "revoked@test.com" }],
			keyExpirationTime: 400 * 24 * 60 * 60,
			format: "object",
		});
		const revoked = await openpgp.revokeKey({ key: publicKey, revocationCertificate, format: "object" });

		const expiry = await pgpKeyExpiry(revoked.publicKey.armor());
		expect(expiry).toEqual({ kind: "revoked" });
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60)).toMatchObject({
			state: "revoked",
			detail: "key is revoked",
		});
	});

	it("reports unreadable key material as unknown", async () => {
		const expiry = await pgpKeyExpiry(
			"-----BEGIN PGP PUBLIC KEY BLOCK-----\nnonsense\n-----END PGP PUBLIC KEY BLOCK-----",
		);
		expect(expiry).toMatchObject({ kind: "unknown" });
		if (expiry.kind === "unknown") expect(expiry.reason).toMatch(/could not read PGP key/);
	});
});

describe("effectiveExpiry", () => {
	const soon = fromNow(30);
	const late = fromNow(400);

	it("reports a key with no valid self-certification as unknown", () => {
		// openpgp returns null here for a malformed primary key. No key it will
		// read back can produce it, so it is asserted directly.
		expect(effectiveExpiry(null, soon)).toEqual({
			kind: "unknown",
			reason: "PGP primary key has no valid self-certification (malformed)",
		});
		expect(effectiveExpiry(null, null)).toMatchObject({ kind: "unknown" });
	});

	it("takes whichever of the two lapses first", () => {
		expect(effectiveExpiry(late, soon)).toEqual({ kind: "date", expiresAt: soon });
		expect(effectiveExpiry(soon, late)).toEqual({ kind: "date", expiresAt: soon });
	});

	it("treats Infinity on either side as the other side's date", () => {
		expect(effectiveExpiry(Infinity, soon)).toEqual({ kind: "date", expiresAt: soon });
		expect(effectiveExpiry(soon, Infinity)).toEqual({ kind: "date", expiresAt: soon });
	});

	it("is never-expiring only when neither side expires", () => {
		expect(effectiveExpiry(Infinity, Infinity)).toEqual({ kind: "never" });
	});

	it("falls back to the primary key when the signing key has no verdict", () => {
		expect(effectiveExpiry(soon, null)).toEqual({ kind: "date", expiresAt: soon });
		expect(effectiveExpiry(Infinity, null)).toEqual({ kind: "never" });
	});
});

describe("x509CertificateExpiry", () => {
	it("reports an unparseable certificate as unknown", () => {
		const expiry = x509CertificateExpiry("-----BEGIN CERTIFICATE-----\nnonsense\n-----END CERTIFICATE-----");
		expect(expiry).toMatchObject({ kind: "unknown" });
		if (expiry.kind === "unknown") expect(expiry.reason).toMatch(/could not parse X.509 certificate/);
	});
});

describe("keyMaterialExpiry", () => {
	it("dispatches on the armor header", async () => {
		const { publicKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Dispatch", email: "dispatch@test.com" }],
			format: "armored",
		});

		expect(await keyMaterialExpiry(publicKey)).toEqual({ kind: "never" });
		expect(await keyMaterialExpiry("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")).toMatchObject({
			kind: "unknown",
		});
	});

	it("rejects a body that is neither a public key nor a certificate", async () => {
		const expiry = await keyMaterialExpiry('{"error":"Key not found"}');
		expect(expiry).toMatchObject({ kind: "unknown" });
		if (expiry.kind === "unknown")
			expect(expiry.reason).toMatch(/neither a PGP public key block nor a PEM certificate/);
	});
});

describe("missingKeyRow", () => {
	const key = (over: Partial<ActiveKey>): ActiveKey => ({
		keyId: PRODUCTION_KEY_ID,
		reasons: [],
		grants: [],
		stored: false,
		...over,
	});

	it("names KEY_ID as the cause when the default is absent", () => {
		const row = missingKeyRow(key({ reasons: ["default"] }));
		expect(row).toMatchObject({
			keyId: PRODUCTION_KEY_ID,
			state: "missing",
			detail: "this environment's KEY_ID, but the deployment does not hold it",
		});
		expect(actionableRows([row])).toHaveLength(1);
	});

	it("names the grant when a credential outlived the key it was scoped to", () => {
		// The two causes need opposite fixes, so the report has to distinguish
		// them: deploy the key, or re-scope the credential.
		const row = missingKeyRow(key({ reasons: ["grant"], grants: ["service-token:ci"] }));
		expect(row.detail).toBe("granted to service-token:ci, but the deployment does not hold it");
	});

	it("still reads as a sentence when no cause is recorded", () => {
		// An any-key grant only ever reaches keys the deployment holds, so this
		// combination cannot arise from `resolveActiveKeys` — the fallback exists
		// so a future caller cannot render a dangling clause.
		expect(missingKeyRow(key({ reasons: ["unrestricted-grant"] })).detail).toBe(
			"expected, but the deployment does not hold it",
		);
	});

	it("names both when the default is also granted", () => {
		const row = missingKeyRow(key({ reasons: ["default", "grant"], grants: ["oidc-subject:repo:kjanat/svc"] }));
		expect(row.detail).toBe(
			"this environment's KEY_ID; granted to oidc-subject:repo:kjanat/svc, but the deployment does not hold it",
		);
	});
});

describe("actionableRows", () => {
	const rows: KeyExpiryRow[] = [
		{ keyId: "OK", state: "ok", expiresAt: null, daysRemaining: 200 },
		{ keyId: "NEVER", state: "no-expiry", expiresAt: null, daysRemaining: null },
		{ keyId: "WARN", state: "warning", expiresAt: null, daysRemaining: 10 },
		{ keyId: "GONE", state: "expired", expiresAt: null, daysRemaining: -1 },
		{ keyId: "HUH", state: "unknown", expiresAt: null, daysRemaining: null },
		{ keyId: "REVOKED", state: "revoked", expiresAt: null, daysRemaining: null },
		{ keyId: "ABSENT", state: "missing", expiresAt: null, daysRemaining: null },
	];

	it("selects only the states that need a human", () => {
		expect(actionableRows(rows).map((row) => row.keyId)).toEqual(["WARN", "GONE", "HUH", "REVOKED", "ABSENT"]);
	});

	it("returns nothing when every key is healthy", () => {
		expect(actionableRows(rows.slice(0, 2))).toEqual([]);
	});
});

describe("renderReport", () => {
	/**
	 * A report context whose scope covers exactly the rows being rendered, so a
	 * test only has to say what it is actually asserting about.
	 */
	function contextFor(rows: readonly KeyExpiryRow[], scope: Partial<ActiveKeySet> = {}): ReportContext {
		return {
			warnDays: 60,
			now: NOW,
			serviceUrl: "https://gpg.example.test",
			scope: {
				keys: rows.map((row) => ({
					keyId: row.keyId,
					reasons: ["default"] as ActiveKey["reasons"],
					grants: [],
					stored: row.state !== "missing",
				})),
				retainedInactive: [],
				unrestrictedGrants: [],
				liveGrantCount: 1,
				totalGrantCount: 1,
				defaultKey: { env: null, keyId: rows[0]?.keyId ?? null, envExists: true },
				...scope,
			},
		};
	}

	/** Key ids in the order the rendered table lists them */
	function tableOrder(report: string): (string | undefined)[] {
		return [...report.matchAll(/\| `([0-9A-Z]{16})` \|/g)].map((match) => match[1]);
	}

	it("says so plainly when nothing is expiring", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(447).toISOString(), daysRemaining: 447 },
		];
		const report = renderReport(rows, contextFor(rows));

		expect(report).toContain("No active signing key expires within 60 days.");
		expect(report).not.toContain("### Action required");
		expect(report).toContain("Monitored 1 active signing key on https://gpg.example.test");
		expect(report).toContain("wrangler environment `top-level`");
		expect(report).toContain(`\`${PRODUCTION_KEY_ID}\``);
	});

	it("lists every affected key under an action heading", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: PRODUCTION_KEY_ID, state: "warning", expiresAt: fromNow(12).toISOString(), daysRemaining: 12 },
			{ keyId: "LAPSED0000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
		];
		const report = renderReport(rows, contextFor(rows));

		expect(report).toContain("### Action required");
		expect(report).toContain(`- \`${PRODUCTION_KEY_ID}\`: ⚠️ expiring (12 days)`);
		expect(report).toContain("- `LAPSED0000000000`: 🚨 expired (5 days ago)");
		expect(report).toContain("Monitored 3 active signing keys");
		// Absolute: a repo-relative path does not resolve in a GitHub issue body.
		expect(report).toContain(`(${KEY_ROTATION_DOCS_URL})`);
		expect(KEY_ROTATION_DOCS_URL).toMatch(/^https:\/\/github\.com\/.*#key-rotation$/);
		// The healthy key is still in the table, just not in the action list.
		expect(report).toContain("`HEALTHY000000000`");
		expect(report.split("### Action required")[1]?.split("<details>")[0]).not.toContain("HEALTHY000000000");
	});

	it("pluralises so no row ever reads `1 days`", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "TOMORROW00000000", state: "warning", expiresAt: fromNow(1).toISOString(), daysRemaining: 1 },
			{ keyId: "YESTERDAY0000000", state: "expired", expiresAt: fromNow(-1).toISOString(), daysRemaining: -1 },
		];
		const report = renderReport(rows, contextFor(rows));

		expect(report).toContain("- `TOMORROW00000000`: ⚠️ expiring (1 day)");
		expect(report).toContain("- `YESTERDAY0000000`: 🚨 expired (1 day ago)");
		expect(report).not.toContain("1 days");
	});

	it("says why each key is being watched", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "DEFAULTKEY000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: "GRANTEDKEY000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const report = renderReport(
			rows,
			contextFor(rows, {
				keys: [
					{ keyId: "DEFAULTKEY000000", reasons: ["default"], grants: [], stored: true },
					{
						keyId: "GRANTEDKEY000000",
						reasons: ["unrestricted-grant"],
						grants: ["service-token:ci"],
						stored: true,
					},
				],
			}),
		);

		expect(report).toContain("| Key ID | Status | Expires | Remaining | Active because |");
		expect(report).toContain("`KEY_ID` default");
		expect(report).toContain("any-key grant `service-token:ci`");
	});

	it("declares the retained keys it deliberately left out", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const report = renderReport(rows, contextFor(rows, { retainedInactive: ["OLDKEY0000000000"] }));

		expect(report).toContain("Which keys count as active");
		expect(report).toContain("stored but no live grant reaches it: `OLDKEY0000000000`");
	});

	it("warns that an any-key grant makes storage the boundary", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const report = renderReport(
			rows,
			contextFor(rows, { unrestrictedGrants: ["service-token:ci"], liveGrantCount: 1, totalGrantCount: 3 }),
		);

		expect(report).toContain("**every stored key is signable**");
		expect(report).toContain("`service-token:ci`");
		expect(report).toContain("Read 3 grants, of which 1 live.");
	});

	it("warns when the checked environment declares no default key", () => {
		const report = renderReport([], contextFor([], { defaultKey: { env: "preview", keyId: null, envExists: true } }));

		expect(report).toContain("wrangler environment `preview`");
		expect(report).toContain("declares no `KEY_ID`");
	});

	it("renders a row the scope does not explain rather than dropping it", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "ORPHANED00000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const report = renderReport(rows, contextFor(rows, { keys: [] }));

		expect(report).toContain("`ORPHANED00000000`");
		expect(report).toContain("| 400 days | — |");
	});

	it("pluralises the scope notes too", () => {
		const report = renderReport(
			[],
			contextFor([], {
				unrestrictedGrants: ["service-token:a", "service-token:b"],
				retainedInactive: ["OLD1000000000000", "OLD2000000000000"],
				liveGrantCount: 2,
				totalGrantCount: 2,
			}),
		);

		expect(report).toContain("2 live grants pin no key ids");
		expect(report).toContain("no live grant reaches them: `OLD1000000000000`, `OLD2000000000000`");
	});

	it("sorts worst first so the row that matters is read first", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: "NOEXPIRY00000000", state: "no-expiry", expiresAt: null, daysRemaining: null },
			{ keyId: "WARNING000000000", state: "warning", expiresAt: fromNow(30).toISOString(), daysRemaining: 30 },
			{ keyId: "EXPIRED000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
			{ keyId: "ABSENT0000000000", state: "missing", expiresAt: null, daysRemaining: null },
		];

		expect(tableOrder(renderReport(rows, contextFor(rows)))).toEqual([
			"EXPIRED000000000",
			"WARNING000000000",
			"ABSENT0000000000",
			"HEALTHY000000000",
			"NOEXPIRY00000000",
		]);
	});

	it("orders dateless actionable rows after dated ones either way round", () => {
		// Exercises both arms of the comparator's null handling, whichever order
		// the sort happens to feed the pair in.
		const dated: KeyExpiryRow = { keyId: "DATED00000000000", state: "expired", expiresAt: null, daysRemaining: -5 };
		const dateless: KeyExpiryRow = {
			keyId: "ABSENT0000000000",
			state: "missing",
			expiresAt: null,
			daysRemaining: null,
		};

		for (const rows of [
			[dated, dateless],
			[dateless, dated],
		]) {
			expect(tableOrder(renderReport(rows, contextFor(rows)))).toEqual(["DATED00000000000", "ABSENT0000000000"]);
		}
	});

	it("falls back to key id order for two dateless rows", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "ZZZZ000000000000", state: "missing", expiresAt: null, daysRemaining: null },
			{ keyId: "AAAA000000000000", state: "unknown", expiresAt: null, daysRemaining: null },
		];

		expect(tableOrder(renderReport(rows, contextFor(rows)))).toEqual(["AAAA000000000000", "ZZZZ000000000000"]);
	});

	it("renders detail text for keys it could not read", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "BROKEN0000000000", state: "unknown", expiresAt: null, daysRemaining: null, detail: "revoked" },
		];
		const report = renderReport(rows, contextFor(rows));

		expect(report).toContain("- `BROKEN0000000000`: ❓ unknown (—) — revoked");
	});

	it("reports a deployment with no active keys without crashing", () => {
		const report = renderReport([], contextFor([]));
		expect(report).toContain("Monitored 0 active signing keys");
		expect(report).toContain("No active signing key expires within 60 days.");
	});
});
