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
	isGrantLive,
	KEY_EXPIRY_MONITOR_DOCS_URL,
	KEY_ROTATION_DOCS_URL,
	type KeyExpiryRow,
	type KeyGrant,
	keyMaterialExpiry,
	type MonitorFailureKind,
	missingKeyRow,
	parseWarnDays,
	pgpKeyExpiry,
	type ReportContext,
	renderFailureReport,
	renderReport,
	reportSubject,
	resolveActiveKeys,
	type SigningSubkey,
	signingSubkeyExpiry,
	x509CertificateExpiry,
} from "#utils/key-expiry";

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

	it("rejects every numeric spelling that is not plain decimal digits", () => {
		// `Number` reads all of these as integers, so each would otherwise be
		// accepted as a threshold nobody wrote: `1e3` as 1000 days, `0x3C` as
		// exactly the default it was meant to override, `+60` and `60.` as 60.
		for (const [bad, wouldHaveMeant] of [
			["1e3", 1000],
			["0x3C", 60],
			["0b111100", 60],
			["0o74", 60],
			["+60", 60],
			["60.", 60],
			["6_0", null],
			["9007199254740993", null],
		] as const) {
			expect(() => parseWarnDays(bad)).toThrow(/KEY_EXPIRY_WARN_DAYS must be a positive whole number/);
			// Pinned so the mutation is visible: the rejection is the point only
			// because `Number` would have produced a usable number instead.
			if (wouldHaveMeant !== null) expect(Number(bad)).toBe(wouldHaveMeant);
		}
	});

	it("keeps accepting the plain decimal forms an operator actually writes", () => {
		expect(parseWarnDays("7")).toBe(7);
		expect(parseWarnDays("060")).toBe(60);
		expect(parseWarnDays("\t120\n")).toBe(120);
		expect(parseWarnDays("365")).toBe(365);
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
		// `verifyServiceToken` refuses only on `expires_at < now` and
		// `resolveOIDCSubject` honours `expires_at >= now`, so the boundary
		// instant is live on both paths. A stricter rule here would drop a key
		// the service would still sign with.
		expect(isGrantLive(grant({ expiresAt: NOW.toISOString() }), NOW)).toBe(true);
		expect(isGrantLive(grant({ kind: "oidc-subject", expiresAt: NOW.toISOString() }), NOW)).toBe(true);
	});

	it("reads an unparseable expiry the way the grant's own auth path does", () => {
		// The two paths disagree, and `NaN` is why: `verifyServiceToken` refuses
		// on `NaN < now` (false, so the token is honoured) while
		// `resolveOIDCSubject` requires `NaN >= now` (also false, so the subject
		// is refused). Reading one rule for both would either monitor a key
		// nothing can sign with or drop one that still signs.
		expect(isGrantLive(grant({ expiresAt: "not a date" }), NOW)).toBe(true);
		expect(isGrantLive(grant({ kind: "oidc-subject", expiresAt: "not a date" }), NOW)).toBe(false);
	});
});

describe("resolveActiveKeys", () => {
	const STORED_A = "AAAABBBBCCCCDDDD";
	const defaultKey = { env: null, keyId: PRODUCTION_KEY_ID };
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
		expect(scope.keys).toEqual([
			{ keyId: PRODUCTION_KEY_ID, reasons: ["default"], grants: [], anyKeyGrants: [], stored: true },
		]);
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
			anyKeyGrants: [],
			stored: false,
		});
	});

	it("does not invent an active key when the environment declares none", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: [PRODUCTION_KEY_ID],
			defaultKey: { env: "preview", keyId: null },
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
			// The any-key grant is recorded apart from the scoped one, so the
			// report can say which of the two reached this key how.
			anyKeyGrants: ["service-token:anything"],
			stored: true,
		});
	});

	it("compares key ids case-insensitively across config, grants and storage", () => {
		const scope = resolveActiveKeys({
			storedKeyIds: ["aaaabbbbccccdddd"],
			defaultKey: { env: null, keyId: STORED_A },
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
		anyKeyGrants: [],
		stored: true,
		...over,
	});

	it("names the default, the grants, or both", () => {
		expect(describeActivation(key({ reasons: ["default"] }))).toBe("KEY_ID default");
		expect(describeActivation(key({ reasons: ["grant"], grants: ["service-token:ci"] }))).toBe(
			"granted to service-token:ci",
		);
		expect(describeActivation(key({ reasons: ["default", "grant"], grants: ["service-token:ci"] }))).toBe(
			"KEY_ID default; granted to service-token:ci",
		);
	});

	it("does not describe an any-key grant as if it were scoped to the key", () => {
		// A grant is scoped or unscoped as a property of the grant, so a key that
		// a scoped grant names *and* an any-key grant sweeps up has to show both.
		// Reporting only the scoped list printed `service-token:broad` under
		// "granted to" on this row while the very next row called the same
		// credential an any-key grant.
		expect(
			describeActivation(
				key({
					reasons: ["grant", "unrestricted-grant"],
					grants: ["service-token:broad", "service-token:ci"],
					anyKeyGrants: ["service-token:broad"],
				}),
			),
		).toBe("granted to service-token:ci; any-key grant service-token:broad");
	});

	it("says when a key is only reachable through an any-key grant", () => {
		expect(
			describeActivation(
				key({ reasons: ["unrestricted-grant"], grants: ["service-token:ci"], anyKeyGrants: ["service-token:ci"] }),
			),
		).toBe("any-key grant service-token:ci");
	});

	it("falls back to a dash when nothing explains the key", () => {
		// Defensive: every key in a resolved set carries at least one reason, so
		// this only fires if that invariant is ever broken.
		expect(describeActivation(key({}))).toBe("—");
	});

	it("truncates a long grant list rather than flooding the table", () => {
		const grants = ["a", "b", "c", "d"].map((name) => `service-token:${name}`);
		expect(describeActivation(key({ reasons: ["grant"], grants }))).toBe(
			"granted to service-token:a, service-token:b +2 more",
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

	// GnuPG key in the standard offline layout: a certify-only primary key that
	// expires in 2029, and a signing subkey that has been revoked. openpgp.js
	// cannot generate a certify-only primary, so this is real `gpg` output —
	// which is the point, since it is the layout the bug needs.
	const REVOKED_SIGNING_SUBKEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEapNZxxYJKwYBBAHaRw8BAQdAP0rR98D408ENU8GBzH4eZXURIbTwqNO5fWkS
16ao7ji0LVJldm9rZWQgU2lnbmluZyBTdWJrZXkgPHJldm9rZWQtc3ViQHRlc3Qu
Y29tPoiZBBMWCgBBFiEEbPMdMrXxwMBf2Ni5R3kFE3J0hgMFAmqTWccCGwEFCQWj
moAFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQR3kFE3J0hgN0KgEAmJvF
bh2kZ9gZzg5HiqOjqHFIqknb/hr+p1pOUlCxuxgBAPrEbwvnxsGLlscrwDbBjxeF
t1NRElxYLF0nXeP4oicCuDMEapNZxxYJKwYBBAHaRw8BAQdAeaMOUtly8Up3HBmC
izQgknayVMlXZ0foVtaa9XomNkeIeAQoFgoAIBYhBGzzHTK18cDAX9jYuUd5BRNy
dIYDBQJqk1nHAh0CAAoJEEd5BRNydIYDbyQBAI0Ott8sr579QOoJ6DYXPB+k1biN
btNpNpOIVnMqf+57AQDtp1I4LcYxvK/AdpZ7qehyQ5cUAGs8cVmQZKlrazhFA4j1
BBgWCgAmFiEEbPMdMrXxwMBf2Ni5R3kFE3J0hgMFAmqTWccCGwIFCQWjmoAAgQkQ
R3kFE3J0hgN2IAQZFgoAHRYhBFMPgbZjkFc85CeZ9ZpIZNvYd/LOBQJqk1nHAAoJ
EJpIZNvYd/LOLkYA/jXwYZK1mB6345d92S+LEj3cvplQURWhOhoNR2qUfnlwAQCU
R+Lw4vqNRyufQAjjgbJ+UayGObaqtpvHDUx6kPTlBouyAQCADlBIfJBe3W7szMlM
9+aKYI/ib4CPb2XhVhdkpfid5AD8Dv2YWyTqjGfMAU5uw+vy+dPjSoraHk+gJwLR
SAvgpQI=
=QTDx
-----END PGP PUBLIC KEY BLOCK-----`;

	it("refuses to call a key healthy when its signing subkey is revoked", async () => {
		// The subkey is what signs — that is why its expiry is preferred over the
		// primary key's above. Revoking it stops verifiers accepting the
		// signatures just as completely, but leaves the primary key valid and
		// both expiration subpackets untouched. openpgp then refuses to resolve a
		// signing key at all, and reading the primary key's 2029 date instead
		// would report a comfortable `ok` for a key that can no longer sign.
		const key = await openpgp.readKey({ armoredKey: REVOKED_SIGNING_SUBKEY });
		// Neither existing check catches it: the primary key is not revoked, and
		// its own expiration date is years away.
		expect(await key.isRevoked()).toBe(false);
		expect(await key.getExpirationTime()).toBeInstanceOf(Date);

		const expiry = await pgpKeyExpiry(REVOKED_SIGNING_SUBKEY);
		// Reported as revoked rather than as an unexplained `unknown`: the subkey
		// is enumerated instead of being inferred from a failed lookup, so the
		// verdict can say which decision broke signing and which subkey to replace.
		expect(expiry).toMatchObject({ kind: "revoked" });
		if (expiry.kind === "revoked") {
			expect(expiry.detail).toMatch(/no usable signing subkey/);
			expect(expiry.detail).toContain(key.subkeys[0]?.getKeyID().toHex());
		}
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("revoked");
	});

	it("reports a certify-only primary with no signing subkey as unknown", async () => {
		// The same real `gpg` key with its subkey packets dropped, which is the
		// other half of the offline layout: a primary that may certify but not
		// sign, and nothing bound to sign in its place. Its 2029 expiry is a date
		// for a capability the key does not have, so reporting it would be an
		// all-clear for a deployment that cannot sign at all.
		const full = await openpgp.readKey({ armoredKey: REVOKED_SIGNING_SUBKEY });
		const kept = new openpgp.PacketList<openpgp.AnyPacket>();
		for (const packet of full.toPacketList()) {
			const isSubkeyPacket = packet instanceof openpgp.PublicSubkeyPacket;
			const isSubkeySignature =
				packet instanceof openpgp.SignaturePacket &&
				(packet.signatureType === openpgp.enums.signature.subkeyBinding ||
					packet.signatureType === openpgp.enums.signature.subkeyRevocation);
			if (!isSubkeyPacket && !isSubkeySignature) kept.push(packet);
		}
		const armored = new openpgp.PublicKey(kept).armor();

		const stripped = await openpgp.readKey({ armoredKey: armored });
		expect(stripped.getSubkeys()).toHaveLength(0);
		expect(await stripped.isRevoked()).toBe(false);
		expect(await stripped.getExpirationTime()).toBeInstanceOf(Date);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry).toMatchObject({ kind: "unknown" });
		if (expiry.kind === "unknown") expect(expiry.reason).toMatch(/no signing key/);
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("unknown");
	});

	it("reports unreadable key material as unknown", async () => {
		const expiry = await pgpKeyExpiry(
			"-----BEGIN PGP PUBLIC KEY BLOCK-----\nnonsense\n-----END PGP PUBLIC KEY BLOCK-----",
		);
		expect(expiry).toMatchObject({ kind: "unknown" });
		if (expiry.kind === "unknown") expect(expiry.reason).toMatch(/could not read PGP key/);
	});
});

describe("pgpKeyExpiry with revoked signing subkeys", () => {
	const DAY_SECONDS = 24 * 60 * 60;

	/**
	 * Real key material with some of its signing subkeys revoked.
	 *
	 * openpgp has no "generate this already revoked" switch, so the subkey is
	 * revoked afterwards and swapped back into the key — which is what applying a
	 * revocation certificate does to the published key in the first place.
	 *
	 * The primary key openpgp generates always carries the sign flag, so every
	 * fixture here is one where `getSigningKey()` *can* fall back to the primary
	 * key. That is the point: the fallback is what used to hide the revocation.
	 */
	async function keyWithRevokedSubkeys(
		primaryDays: number,
		subkeys: openpgp.SubkeyOptions[],
		revokeIndices: readonly number[],
	): Promise<string> {
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Rotating", email: "rotating@test.com" }],
			keyExpirationTime: primaryDays * DAY_SECONDS,
			subkeys,
			format: "object",
		});

		for (const index of revokeIndices) {
			const subkey = privateKey.subkeys[index];
			if (!subkey) throw new Error(`fixture has no subkey at index ${index}`);
			privateKey.subkeys[index] = await subkey.revoke(privateKey.keyPacket as openpgp.SecretKeyPacket);
		}

		return privateKey.toPublic().armor();
	}

	/** Days from the key's own creation, which is "now" for a freshly generated key */
	async function daysFromCreation(armoredKey: string, expiresAt: Date): Promise<number> {
		const key = await openpgp.readKey({ armoredKey });
		return Math.round((expiresAt.getTime() - key.getCreationTime().getTime()) / DAY_MS);
	}

	it("does not report a key whose only signing subkey is revoked as ok", async () => {
		// The regression from #90: openpgp skips the revoked subkey and hands back
		// the primary key instead, whose far-off expiry reads as perfectly healthy.
		const armored = await keyWithRevokedSubkeys(400, [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}], [0]);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("revoked");
		if (expiry.kind !== "revoked") return;
		expect(expiry.detail).toMatch(/no usable signing subkey/);

		const row = classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60);
		expect(row.state).toBe("revoked");
		expect(actionableRows([row])).toHaveLength(1);
	});

	it("names the revoked subkey so the report says which one to replace", async () => {
		const armored = await keyWithRevokedSubkeys(400, [{ sign: true }, {}], [0]);
		const key = await openpgp.readKey({ armoredKey: armored });
		const revokedId = key.subkeys[0]?.getKeyID().toHex();

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("revoked");
		if (expiry.kind !== "revoked") return;
		expect(revokedId).toBeDefined();
		expect(expiry.detail).toContain(revokedId);
	});

	it("stays healthy when a valid replacement signing subkey remains", async () => {
		// Rotation: the old signing subkey is revoked and a new one takes over.
		// Signing still works, so warning here would be a pure false positive.
		const armored = await keyWithRevokedSubkeys(
			400,
			[{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, { sign: true, keyExpirationTime: 200 * DAY_SECONDS }, {}],
			[0],
		);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		// The replacement's own 200 days, not the revoked subkey's 300 and not the
		// primary key's 400.
		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(200);
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("ok");
	});

	it("counts the longest-lived usable subkey when several can sign", async () => {
		// Signing keeps working until the last usable subkey lapses, so the one
		// that expires in 30 days is not an outage while another covers 400.
		const armored = await keyWithRevokedSubkeys(
			500,
			[{ sign: true, keyExpirationTime: 30 * DAY_SECONDS }, { sign: true, keyExpirationTime: 400 * DAY_SECONDS }, {}],
			[],
		);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(400);
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("ok");

		// The rule above is a claim about openpgp, so it is asserted against
		// openpgp: `getSigningKey` skips a lapsed subkey and carries on down the
		// list, which is why warning at day 30 would be an outage that never
		// happens. Day 100 is past the short subkey and well inside the long one.
		const key = await openpgp.readKey({ armoredKey: armored });
		const atDay100 = new Date(key.getCreationTime().getTime() + 100 * DAY_MS);
		const stillSigning = await key.getSigningKey(undefined, atDay100);
		expect(stillSigning.getKeyID().toHex()).toBe(key.subkeys[1]?.getKeyID().toHex());
	});

	it("still warns when every usable signing subkey is inside the window", async () => {
		const armored = await keyWithRevokedSubkeys(
			500,
			[{ sign: true, keyExpirationTime: 400 * DAY_SECONDS }, { sign: true, keyExpirationTime: 30 * DAY_SECONDS }, {}],
			[0],
		);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(30);
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("warning");
	});

	it("keeps the primary key's expiry as a cap on its subkeys", async () => {
		// A subkey cannot outlive the key that binds it, so a 30-day primary key
		// ends signing regardless of what the usable subkey claims.
		const armored = await keyWithRevokedSubkeys(30, [{ sign: true, keyExpirationTime: 400 * DAY_SECONDS }, {}], []);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(30);
	});

	it("ignores a revoked encryption subkey, which never signed anything", async () => {
		// Revoking the encryption subkey has nothing to do with signing, and a
		// monitor that raises an outage for it is one nobody will read twice.
		const armored = await keyWithRevokedSubkeys(400, [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}], [1]);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;

		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(300);
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("ok");
	});

	it("reports a revoked primary key before looking at its subkeys", async () => {
		// The existing #86 path, re-asserted against a key that also has a
		// perfectly usable signing subkey: a revoked primary takes it down too.
		const { privateKey, revocationCertificate } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Dead", email: "dead@test.com" }],
			keyExpirationTime: 400 * DAY_SECONDS,
			subkeys: [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}],
			format: "object",
		});
		const revoked = await openpgp.revokeKey({ key: privateKey, revocationCertificate, format: "object" });

		const expiry = await pgpKeyExpiry(revoked.publicKey.armor());
		expect(expiry).toEqual({ kind: "revoked" });
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).detail).toBe("key is revoked");
	});

	it("keeps an expired signing subkey visible instead of dropping it", async () => {
		// Date checks are switched off while the set is collected, so a lapsed
		// signing subkey is still reported rather than silently skipped in favour
		// of the primary key.
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Lapsed sub", email: "lapsedsub@test.com" }],
			date: new Date(NOW.getTime() - 400 * DAY_MS),
			keyExpirationTime: 800 * DAY_SECONDS,
			subkeys: [{ sign: true, keyExpirationTime: 30 * DAY_SECONDS }, {}],
			format: "object",
		});

		const expiry = await pgpKeyExpiry(privateKey.toPublic().armor());
		expect(expiry.kind).toBe("date");
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("expired");
	});
});

describe("pgpKeyExpiry with binding signatures it cannot verify", () => {
	const DAY_SECONDS = 24 * 60 * 60;

	/**
	 * A subkey binding signature issued by an *unrelated* key.
	 *
	 * `readKey` appends every `subkeyBinding` packet it parses to
	 * `Subkey.bindingSignatures` without verifying any of them — verification is
	 * deferred to whoever asks a question later. So a packet spliced into an
	 * armored key sits in that array looking exactly like the real one, and if it
	 * carries a later `created` it is the newest entry there. Nothing exotic is
	 * needed to produce one: appending packets to an armored key takes a text
	 * editor, and merging a key with an unrelated copy leaves them behind with
	 * nobody trying.
	 *
	 * Borrowing a real binding from a second generated key keeps the fixture
	 * honest — it is a well-formed signature packet with a real issuer and a real
	 * digest, and the only thing wrong with it is that this primary key did not
	 * issue it, which is precisely what has to be detected.
	 */
	async function foreignBinding(options: { sign: boolean; createdDaysAgo: number }): Promise<openpgp.SignaturePacket> {
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Elsewhere", email: "elsewhere@test.com" }],
			date: new Date(NOW.getTime() - options.createdDaysAgo * DAY_MS),
			subkeys: [options.sign ? { sign: true } : {}],
			format: "object",
		});

		const binding = privateKey.subkeys[0]?.bindingSignatures[0];
		if (!binding) throw new Error("fixture key has no subkey binding signature");
		return binding;
	}

	/** Generate a key, splice a foreign binding onto one subkey, and re-armor it */
	async function keyWithSplicedBinding(options: {
		subkeys: openpgp.SubkeyOptions[];
		spliceOnto: number;
		binding: openpgp.SignaturePacket;
		revoke?: number;
	}): Promise<string> {
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Spliced", email: "spliced@test.com" }],
			date: new Date(NOW.getTime() - 10 * DAY_MS),
			keyExpirationTime: 400 * DAY_SECONDS,
			subkeys: options.subkeys,
			format: "object",
		});

		privateKey.subkeys[options.spliceOnto]?.bindingSignatures.push(options.binding);
		if (options.revoke !== undefined) {
			const subkey = privateKey.subkeys[options.revoke];
			if (!subkey) throw new Error(`fixture has no subkey at index ${options.revoke}`);
			privateKey.subkeys[options.revoke] = await subkey.revoke(privateKey.keyPacket as openpgp.SecretKeyPacket);
		}

		return privateKey.toPublic().armor();
	}

	/** Days from the key's own creation, which is 10 days before `NOW` for these fixtures */
	async function daysFromCreation(armoredKey: string, expiresAt: Date): Promise<number> {
		const key = await openpgp.readKey({ armoredKey });
		return Math.round((expiresAt.getTime() - key.getCreationTime().getTime()) / DAY_MS);
	}

	it("keeps a live signing subkey that a foreign binding signature disowns", async () => {
		// The newest *raw* binding on this subkey says encrypt-only, and reading
		// key flags off it drops the subkey out of the signing set — which leaves
		// the set empty and reports the primary key's 400 days for a key that
		// signs with a subkey lapsing at 300. openpgp itself is not fooled, so
		// the monitor must not be either.
		const armored = await keyWithSplicedBinding({
			subkeys: [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}],
			spliceOnto: 0,
			binding: await foreignBinding({ sign: false, createdDaysAgo: 1 }),
		});

		const key = await openpgp.readKey({ armoredKey: armored });
		const signingSubkey = key.getSubkeys()[0];
		expect(signingSubkey?.bindingSignatures).toHaveLength(2);
		// openpgp still signs with it: the spliced binding fails verification, so
		// `getLatestValidSignature` never selects it.
		await expect(key.getSigningKey(signingSubkey?.getKeyID(), null)).resolves.toBeDefined();

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;
		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(300);
	});

	it("still catches a revoked signing subkey a foreign binding signature disowns", async () => {
		// The same splice, on the revoked subkey this module exists to catch.
		// Dropping it from the set would send the verdict back to the primary
		// key's healthy date — the exact #90 regression, reachable again through
		// a packet anyone can append.
		const armored = await keyWithSplicedBinding({
			subkeys: [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}],
			spliceOnto: 0,
			binding: await foreignBinding({ sign: false, createdDaysAgo: 1 }),
			revoke: 0,
		});

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("revoked");
		if (expiry.kind !== "revoked") return;
		const key = await openpgp.readKey({ armoredKey: armored });
		expect(expiry.detail).toContain(key.subkeys[0]?.getKeyID().toHex());
	});

	it("ignores a subkey whose only binding signature does not verify", async () => {
		// Not "the newest binding is wrong" but "there is no binding at all": every
		// packet claiming to bind this subkey was issued elsewhere, so nothing on
		// this key says it may sign and it is not signing material to report on.
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Unbound", email: "unbound@test.com" }],
			date: new Date(NOW.getTime() - 10 * DAY_MS),
			keyExpirationTime: 400 * DAY_SECONDS,
			subkeys: [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}],
			format: "object",
		});
		const orphan = privateKey.subkeys[0];
		if (!orphan) throw new Error("fixture has no signing subkey");
		orphan.bindingSignatures = [await foreignBinding({ sign: true, createdDaysAgo: 1 })];
		const armored = privateKey.toPublic().armor();

		// The primary key openpgp generates can sign, so this key still has a
		// signing path and its 400 days are the honest answer.
		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;
		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(400);
	});

	/**
	 * A signing subkey carrying two binding signatures that both verify.
	 *
	 * Extending a subkey adds a second, later binding rather than replacing the
	 * first, so this is the ordinary shape of a key whose subkey has been
	 * renewed. The newest one is stored first, so the older has to lose on its
	 * creation time rather than on being last in the packet list.
	 */
	async function keyWithRebound(
		revoke: boolean,
		order: "newest-first" | "oldest-first" = "newest-first",
	): Promise<string> {
		const userIDs = [{ name: "Rebound", email: "rebound@test.com" }];
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs,
			date: new Date(NOW.getTime() - 10 * DAY_MS),
			keyExpirationTime: 800 * DAY_SECONDS,
			subkeys: [{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }, {}],
			format: "object",
		});
		const extended = await openpgp.reformatKey({
			privateKey,
			userIDs,
			keyExpirationTime: 800 * DAY_SECONDS,
			date: new Date(NOW.getTime() - DAY_MS),
			format: "object",
		});

		const subkey = privateKey.subkeys[0];
		const rebinding = extended.privateKey.subkeys[0]?.bindingSignatures[0];
		const original = subkey?.bindingSignatures[0];
		if (!subkey || !rebinding || !original) throw new Error("fixture is missing a subkey binding");
		subkey.bindingSignatures = order === "newest-first" ? [rebinding, original] : [original, rebinding];

		if (revoke) privateKey.subkeys[0] = await subkey.revoke(privateKey.keyPacket as openpgp.SecretKeyPacket);

		return privateKey.toPublic().armor();
	}

	it.each(["newest-first", "oldest-first"] as const)(
		"reads a re-bound subkey from its newest binding signature, %s in the packet list",
		async (order) => {
			// Both orders, because neither "first verified wins" nor "last verified
			// wins" is the rule: the *newest* verified binding is, and a fixture
			// that only ever puts it at one end cannot tell those three apart.
			const armored = await keyWithRebound(false, order);

			const expiry = await pgpKeyExpiry(armored);
			expect(expiry.kind).toBe("date");
			if (expiry.kind !== "date") return;
			// `reformatKey` re-binds the subkey for the key's own 800 days, so the
			// superseded 300-day binding is no longer what ends signing.
			expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(800);
		},
	);

	it("still recognises a re-bound subkey as signing material once it is revoked", async () => {
		// The same two verified bindings, on the subkey openpgp now refuses. This
		// is where the module has to pick among them itself, and picking the
		// superseded one — or neither — would drop a revoked signing subkey out
		// of the set and hand back the primary key's date instead.
		const armored = await keyWithRebound(true);

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("revoked");
		if (expiry.kind !== "revoked") return;
		const key = await openpgp.readKey({ armoredKey: armored });
		expect(expiry.detail).toContain(key.subkeys[0]?.getKeyID().toHex());
	});

	/**
	 * A subkey binding this key really did issue, with the key flags of our
	 * choosing — including none at all.
	 *
	 * Unlike {@link foreignBinding}, this one verifies. That is the whole point:
	 * the rules under test here are about which *valid* binding the module reads,
	 * and a fixture whose bindings all fail verification cannot exercise them.
	 * `sign` takes (key, data, date, detached, config) at runtime; the typings
	 * stop at `detached`, and the config argument has no default.
	 */
	async function selfSignedBinding(
		privateKey: openpgp.PrivateKey,
		subkey: openpgp.Subkey,
		options: { keyFlags: number | null; createdDaysAgo: number },
	): Promise<openpgp.SignaturePacket> {
		const binding = new openpgp.SignaturePacket();
		binding.signatureType = openpgp.enums.signature.subkeyBinding;
		binding.publicKeyAlgorithm = privateKey.keyPacket.algorithm;
		binding.hashAlgorithm = openpgp.enums.hash.sha256;
		if (options.keyFlags !== null) binding.keyFlags = new Uint8Array([options.keyFlags]);

		await (
			binding.sign as unknown as (
				key: openpgp.SecretKeyPacket,
				data: object,
				date: Date,
				detached: boolean,
				config: typeof openpgp.config,
			) => Promise<void>
		)(
			privateKey.keyPacket as openpgp.SecretKeyPacket,
			{ key: privateKey.keyPacket, bind: subkey.keyPacket },
			new Date(NOW.getTime() - options.createdDaysAgo * DAY_MS),
			false,
			openpgp.config,
		);

		return binding;
	}

	/** A 400-day key with the given subkeys, created 10 days before `NOW` */
	async function freshKey(subkeys: openpgp.SubkeyOptions[], email: string): Promise<openpgp.PrivateKey> {
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Bound", email }],
			date: new Date(NOW.getTime() - 10 * DAY_MS),
			keyExpirationTime: 400 * DAY_SECONDS,
			subkeys,
			format: "object",
		});
		return privateKey;
	}

	it("does not adopt an encryption subkey whose own binding sets no key flags", async () => {
		// The case the algorithm allow-list exists for, and the only one that
		// reaches it: a binding with no key flags at all is "unrestricted" by
		// openpgp's own rule, so nothing but the subkey's algorithm keeps an ECDH
		// subkey out of the signing set. Letting it in empties the usable set and
		// reports `unknown` for a key whose primary signs perfectly well.
		const privateKey = await freshKey([{}], "flagless@test.com");
		const subkey = privateKey.subkeys[0];
		if (!subkey) throw new Error("fixture has no encryption subkey");

		const flagless = await selfSignedBinding(privateKey, subkey, { keyFlags: null, createdDaysAgo: 9 });
		expect(flagless.keyFlags).toBeNull();
		subkey.bindingSignatures = [flagless];

		const armored = privateKey.toPublic().armor();
		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;
		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(400);
	});

	it.each(["newest-first", "oldest-first"] as const)(
		"lets a subkey re-bound as encrypt-only leave the signing set, %s in the packet list",
		async (order) => {
			// The rule the module states and openpgp shares: the *newest* verified
			// binding decides, not the first one, not the last one and not any of
			// them. A subkey re-bound without the sign flag has left the signing
			// set; reading the superseded binding instead keeps it there, so the
			// usable set empties out and this healthy key reports `unknown`.
			const privateKey = await freshKey([{ sign: true, keyExpirationTime: 300 * DAY_SECONDS }], "rebound@test.com");
			const subkey = privateKey.subkeys[0];
			const original = subkey?.bindingSignatures[0];
			if (!subkey || !original) throw new Error("fixture has no signing subkey binding");

			const encryptOnly = await selfSignedBinding(privateKey, subkey, {
				keyFlags: openpgp.enums.keyFlags.encryptCommunication | openpgp.enums.keyFlags.encryptStorage,
				createdDaysAgo: 1,
			});
			subkey.bindingSignatures = order === "newest-first" ? [encryptOnly, original] : [original, encryptOnly];

			const armored = privateKey.toPublic().armor();
			const expiry = await pgpKeyExpiry(armored);
			// No signing subkey is left, so the primary key's own 400 days are the
			// answer — not the departed subkey's 300, and not `unknown`.
			expect(expiry.kind).toBe("date");
			if (expiry.kind !== "date") return;
			expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(400);
		},
	);

	it("does not adopt an encryption subkey a foreign binding signature claims can sign", async () => {
		// The mirror image, and a false alarm rather than a missed one: an
		// encryption subkey with a spliced sign-flagged binding is not signing
		// material, so revoking it says nothing about signing. Trusting the raw
		// binding makes this key read as `revoked` while the primary key signs
		// perfectly well.
		const armored = await keyWithSplicedBinding({
			subkeys: [{}],
			spliceOnto: 0,
			binding: await foreignBinding({ sign: true, createdDaysAgo: 1 }),
			revoke: 0,
		});

		const key = await openpgp.readKey({ armoredKey: armored });
		// This key's primary is signing-capable, which is what openpgp's generator
		// always produces, so signing genuinely still works.
		await expect(key.getSigningKey(key.getKeyID(), null)).resolves.toBeDefined();

		const expiry = await pgpKeyExpiry(armored);
		expect(expiry.kind).toBe("date");
		if (expiry.kind !== "date") return;
		expect(await daysFromCreation(armored, expiry.expiresAt)).toBe(400);
		expect(classifyExpiry(PRODUCTION_KEY_ID, expiry, NOW, 60).state).toBe("ok");
	});
});

describe("signingSubkeyExpiry", () => {
	const soon = fromNow(30);
	const late = fromNow(400);

	function subkey(overrides: Partial<SigningSubkey> = {}): SigningSubkey {
		return { keyId: "aaaaaaaaaaaaaaaa", revoked: false, usable: true, expiresAt: soon, ...overrides };
	}

	it("reports a malformed primary key as unknown, subkeys or not", () => {
		expect(signingSubkeyExpiry(null, [subkey()], true)).toMatchObject({ kind: "unknown" });
		expect(signingSubkeyExpiry(null, [], true)).toMatchObject({ kind: "unknown" });
	});

	it("falls back to the primary key when nothing signs but it", () => {
		expect(signingSubkeyExpiry(soon, [], true)).toEqual({ kind: "date", expiresAt: soon });
		expect(signingSubkeyExpiry(Infinity, [], true)).toEqual({ kind: "never" });
	});

	it("reports a key with no signing subkey and a primary that may not sign as unknown", () => {
		// The standard offline layout is a certify-only primary. Reading its
		// expiry there answers a question nobody asked: the date it stops
		// certifying, for a key that has never been able to sign.
		expect(signingSubkeyExpiry(soon, [], false)).toEqual({
			kind: "unknown",
			reason: "no signing key: no signing subkey is bound and the primary key may not sign data",
		});
		expect(signingSubkeyExpiry(Infinity, [], false)).toMatchObject({ kind: "unknown" });
	});

	it("still prefers a malformed primary key over the missing-signing-key verdict", () => {
		// Both are unknown, but "we could not read this key" has to win: the
		// signing-capability answer is derived from a self-certification that a
		// malformed key does not have.
		expect(signingSubkeyExpiry(null, [], false)).toEqual({
			kind: "unknown",
			reason: "PGP primary key has no valid self-certification (malformed)",
		});
	});

	it("takes the longest-lived usable subkey, not the first or the shortest", () => {
		const set = [subkey({ keyId: "short", expiresAt: soon }), subkey({ keyId: "long", expiresAt: late })];
		expect(signingSubkeyExpiry(Infinity, set, true)).toEqual({ kind: "date", expiresAt: late });
	});

	it("caps the usable set at the primary key's own expiry", () => {
		expect(signingSubkeyExpiry(soon, [subkey({ expiresAt: late })], true)).toEqual({ kind: "date", expiresAt: soon });
		expect(signingSubkeyExpiry(soon, [subkey({ expiresAt: Infinity })], true)).toEqual({
			kind: "date",
			expiresAt: soon,
		});
	});

	it("never expires only when neither the primary key nor a usable subkey does", () => {
		expect(signingSubkeyExpiry(Infinity, [subkey({ expiresAt: Infinity })], true)).toEqual({ kind: "never" });
		expect(signingSubkeyExpiry(Infinity, [subkey({ expiresAt: soon }), subkey({ expiresAt: Infinity })], true)).toEqual(
			{
				kind: "never",
			},
		);
	});

	it("ignores revoked and unusable subkeys when a usable one remains", () => {
		const set = [
			subkey({ keyId: "revoked", revoked: true, usable: false, expiresAt: late }),
			subkey({ keyId: "broken", usable: false, expiresAt: late }),
			subkey({ keyId: "live", expiresAt: soon }),
		];
		expect(signingSubkeyExpiry(late, set, true)).toEqual({ kind: "date", expiresAt: soon });
	});

	it("reports revocation when no usable signing subkey is left", () => {
		const set = [subkey({ keyId: "dead", revoked: true, usable: false })];
		expect(signingSubkeyExpiry(late, set, true)).toEqual({
			kind: "revoked",
			detail: "no usable signing subkey — 1 signing subkey revoked (dead)",
		});
	});

	it("names every revoked subkey, pluralised", () => {
		const set = [
			subkey({ keyId: "one", revoked: true, usable: false }),
			subkey({ keyId: "two", revoked: true, usable: false }),
		];
		expect(signingSubkeyExpiry(late, set, true)).toMatchObject({
			detail: "no usable signing subkey — 2 signing subkeys revoked (one, two)",
		});
	});

	it("leads with revocation even when other subkeys failed for other reasons", () => {
		const set = [subkey({ keyId: "broken", usable: false }), subkey({ keyId: "dead", revoked: true, usable: false })];
		expect(signingSubkeyExpiry(late, set, true)).toMatchObject({
			kind: "revoked",
			detail: expect.stringContaining("dead"),
		});
	});

	it("reports unusable-but-unrevoked signing subkeys as unknown, not revoked", () => {
		// Different cause, different fix: nothing was revoked here, the material
		// itself is broken, and calling that a revocation sends the wrong person
		// looking for the wrong certificate.
		const set = [subkey({ keyId: "broken", usable: false }), subkey({ keyId: "alsobroken", usable: false })];
		expect(signingSubkeyExpiry(late, set, true)).toEqual({
			kind: "unknown",
			reason: "no usable signing subkey: openpgp will not sign with broken, alsobroken",
		});
	});

	it("treats a usable subkey with no verdict as lasting as long as the primary key", () => {
		expect(signingSubkeyExpiry(soon, [subkey({ expiresAt: null })], true)).toEqual({ kind: "date", expiresAt: soon });
		expect(signingSubkeyExpiry(Infinity, [subkey({ expiresAt: null })], true)).toEqual({ kind: "never" });
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

	it("reads a private key block, which is the shape storage actually holds", async () => {
		// The Durable Object stores armored *private* keys, and everything read
		// here — expirations, revocations, binding signatures — lives in the
		// public half of that same block, so it must not be refused for its header.
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Stored", email: "stored@test.com" }],
			keyExpirationTime: 90 * 24 * 60 * 60,
			format: "armored",
		});

		expect(await keyMaterialExpiry(privateKey)).toMatchObject({ kind: "date" });
	});

	it("rejects a body that is neither a public key nor a certificate", async () => {
		const expiry = await keyMaterialExpiry('{"error":"Key not found"}');
		expect(expiry).toMatchObject({ kind: "unknown" });
		if (expiry.kind === "unknown") expect(expiry.reason).toMatch(/neither a PGP key block nor a PEM certificate/);
	});
});

describe("missingKeyRow", () => {
	const key = (over: Partial<ActiveKey>): ActiveKey => ({
		keyId: PRODUCTION_KEY_ID,
		reasons: [],
		grants: [],
		anyKeyGrants: [],
		stored: false,
		...over,
	});

	it("names KEY_ID as the cause when the default is absent", () => {
		const row = missingKeyRow(key({ reasons: ["default"] }));
		expect(row).toMatchObject({
			keyId: PRODUCTION_KEY_ID,
			state: "missing",
			detail: "this deployment's KEY_ID, but the deployment does not hold it",
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
			"this deployment's KEY_ID; granted to oidc-subject:repo:kjanat/svc, but the deployment does not hold it",
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
			service: "gpg-signing-service",
			scope: {
				keys: rows.map((row) => ({
					keyId: row.keyId,
					reasons: ["default"] as ActiveKey["reasons"],
					grants: [],
					anyKeyGrants: [],
					stored: row.state !== "missing",
				})),
				retainedInactive: [],
				unrestrictedGrants: [],
				liveGrantCount: 1,
				totalGrantCount: 1,
				defaultKey: { env: null, keyId: rows[0]?.keyId ?? null },
				...scope,
			},
		};
	}

	/** Key ids in the order the rendered table lists them */
	function tableOrder(text: string): (string | undefined)[] {
		return [...text.matchAll(/^([0-9A-Z]{16}) /gm)].map((match) => match[1]);
	}

	it("says so plainly when nothing is expiring", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(447).toISOString(), daysRemaining: 447 },
		];
		const { text } = renderReport(rows, contextFor(rows));

		expect(text).toContain("No active signing key expires within 60 days.");
		expect(text).not.toContain("Action required");
		expect(text).toContain("Monitored 1 active signing key on gpg-signing-service");
		expect(text).toContain(PRODUCTION_KEY_ID);
	});

	it("lists every affected key under an action heading", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: PRODUCTION_KEY_ID, state: "warning", expiresAt: fromNow(12).toISOString(), daysRemaining: 12 },
			{ keyId: "LAPSED0000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
		];
		const { text } = renderReport(rows, contextFor(rows));

		expect(text).toContain("Action required");
		expect(text).toContain(`- ${PRODUCTION_KEY_ID}: EXPIRING (12 days)`);
		expect(text).toContain("- LAPSED0000000000: EXPIRED (5 days ago)");
		expect(text).toContain("Monitored 3 active signing keys");
		// Absolute: a relative path resolves against nothing in a mail client.
		expect(text).toContain(`Key rotation procedure: ${KEY_ROTATION_DOCS_URL}`);
		expect(KEY_ROTATION_DOCS_URL).toMatch(/^https:\/\/github\.com\/.*#key-rotation$/);
		// The healthy key is still in the table, just not in the action list.
		expect(text).toContain("HEALTHY000000000");
		expect(text.split("Action required")[1]?.split("Which keys count")[0]).not.toContain("HEALTHY000000000");
	});

	it("pluralises so no row ever reads `1 days`", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "TOMORROW00000000", state: "warning", expiresAt: fromNow(1).toISOString(), daysRemaining: 1 },
			{ keyId: "YESTERDAY0000000", state: "expired", expiresAt: fromNow(-1).toISOString(), daysRemaining: -1 },
		];
		const { text } = renderReport(rows, contextFor(rows));

		expect(text).toContain("- TOMORROW00000000: EXPIRING (1 day)");
		expect(text).toContain("- YESTERDAY0000000: EXPIRED (1 day ago)");
		expect(text).not.toContain("1 days");
	});

	it("says why each key is being watched", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "DEFAULTKEY000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: "GRANTEDKEY000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const { text } = renderReport(
			rows,
			contextFor(rows, {
				keys: [
					{ keyId: "DEFAULTKEY000000", reasons: ["default"], grants: [], anyKeyGrants: [], stored: true },
					{
						keyId: "GRANTEDKEY000000",
						reasons: ["unrestricted-grant"],
						grants: ["service-token:ci"],
						anyKeyGrants: ["service-token:ci"],
						stored: true,
					},
				],
			}),
		);

		expect(text).toContain("Key ID");
		expect(text).toContain("Active because");
		expect(text).toContain("KEY_ID default");
		expect(text).toContain("any-key grant service-token:ci");
	});

	it("declares the retained keys it deliberately left out", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const { text } = renderReport(rows, contextFor(rows, { retainedInactive: ["OLDKEY0000000000"] }));

		expect(text).toContain("Which keys count as active");
		expect(text).toContain("stored but no live grant reaches it: OLDKEY0000000000");
	});

	it("warns that an any-key grant makes storage the boundary", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const { text } = renderReport(
			rows,
			contextFor(rows, { unrestrictedGrants: ["service-token:ci"], liveGrantCount: 1, totalGrantCount: 3 }),
		);

		expect(text).toContain("every stored key is signable");
		expect(text).toContain("service-token:ci");
		expect(text).toContain("Read 3 grants, of which 1 live.");
	});

	it("warns when the deployment declares no default key", () => {
		const { text } = renderReport([], contextFor([], { defaultKey: { env: "preview", keyId: null } }));

		expect(text).toContain("the preview deployment declares no KEY_ID");
	});

	it("renders a row the scope does not explain rather than dropping it", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "ORPHANED00000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const { text } = renderReport(rows, contextFor(rows, { keys: [] }));

		expect(text).toContain("ORPHANED00000000");
		expect(text).toMatch(/400 days\s+—/);
	});

	it("pluralises the scope notes too", () => {
		const { text } = renderReport(
			[],
			contextFor([], {
				unrestrictedGrants: ["service-token:a", "service-token:b"],
				retainedInactive: ["OLD1000000000000", "OLD2000000000000"],
				liveGrantCount: 2,
				totalGrantCount: 2,
			}),
		);

		expect(text).toContain("2 live grants pin no key ids");
		expect(text).toContain("no live grant reaches them: OLD1000000000000, OLD2000000000000");
	});

	it("sorts worst first so the row that matters is read first", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: "NOEXPIRY00000000", state: "no-expiry", expiresAt: null, daysRemaining: null },
			{ keyId: "WARNING000000000", state: "warning", expiresAt: fromNow(30).toISOString(), daysRemaining: 30 },
			{ keyId: "EXPIRED000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
			{ keyId: "ABSENT0000000000", state: "missing", expiresAt: null, daysRemaining: null },
		];

		expect(tableOrder(renderReport(rows, contextFor(rows)).text)).toEqual([
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
			expect(tableOrder(renderReport(rows, contextFor(rows)).text)).toEqual(["DATED00000000000", "ABSENT0000000000"]);
		}
	});

	it("falls back to key id order for two dateless rows", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "ZZZZ000000000000", state: "missing", expiresAt: null, daysRemaining: null },
			{ keyId: "AAAA000000000000", state: "unknown", expiresAt: null, daysRemaining: null },
		];

		expect(tableOrder(renderReport(rows, contextFor(rows)).text)).toEqual(["AAAA000000000000", "ZZZZ000000000000"]);
	});

	it("renders detail text for keys it could not read", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "BROKEN0000000000", state: "unknown", expiresAt: null, daysRemaining: null, detail: "revoked" },
		];
		const { text } = renderReport(rows, contextFor(rows));

		expect(text).toContain("- BROKEN0000000000: UNKNOWN (—) — revoked");
	});

	it("says nothing was checked, not that everything is clear, when the set is empty", () => {
		// "No key is expiring" and "no key was looked at" are opposite pieces of
		// news. Rendering the all-clear line here hands out a green light earned
		// by an empty set, which is the one report a monitor must never produce.
		const { text, subject } = renderReport([], contextFor([]));

		expect(text).toContain("Monitored 0 active signing keys");
		expect(text).toContain("No key was checked.");
		expect(text).not.toContain("No active signing key expires within 60 days.");
		expect(subject).toBe("[gpg-signing-service] No signing key was checked");
	});

	it("aligns the plain-text table so it is readable in a mail window", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "AAAA000000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: "BBBB000000000000", state: "no-expiry", expiresAt: null, daysRemaining: null },
		];
		const table = renderReport(rows, contextFor(rows))
			.text.split("\n")
			.filter((line) => /^(Key ID|-{5,}|[A-Z0-9]{16}) /.test(line));

		// Header, rule and both rows, every one padded to the same column starts.
		expect(table).toHaveLength(4);
		const columnAt = (line: string) => line.indexOf("no expiry") + line.indexOf("ok");
		expect(new Set(table.map((line) => line.slice(0, 17)))).toHaveLength(4);
		expect(columnAt(table[2] ?? "")).toBe(columnAt(table[3] ?? ""));
	});

	it("escapes operator-supplied text before it reaches the HTML body", () => {
		// Grant names are chosen by whoever mints the credential and reach the
		// report unaltered, so an unescaped interpolation would let them write
		// markup into an operator's inbox.
		const rows: KeyExpiryRow[] = [
			{ keyId: "AAAA000000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];
		const { html, text } = renderReport(
			rows,
			contextFor(rows, {
				keys: [
					{
						keyId: "AAAA000000000000",
						reasons: ["grant"],
						grants: ['service-token:<img src=x onerror="alert(1)">'],
						anyKeyGrants: [],
						stored: true,
					},
				],
			}),
		);

		expect(html).not.toContain("<img");
		expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
		// The plain-text half needs no escaping and must stay legible.
		expect(text).toContain('service-token:<img src=x onerror="alert(1)">');
	});

	it("renders the same run into both bodies", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "warning", expiresAt: fromNow(12).toISOString(), daysRemaining: 12 },
		];
		const { text, html } = renderReport(rows, contextFor(rows));

		for (const body of [text, html]) {
			expect(body).toContain(PRODUCTION_KEY_ID);
			expect(body).toContain("Action required");
			expect(body).toContain("EXPIRING");
		}
		expect(html).toContain(`<a href="${KEY_ROTATION_DOCS_URL}">`);
		expect(html).toContain("<table");
		expect(html.startsWith("<html>")).toBe(true);
	});
});

describe("reportSubject", () => {
	const context = (service = "gpg-signing-service"): ReportContext => ({
		warnDays: 60,
		now: NOW,
		service,
		scope: {
			keys: [],
			retainedInactive: [],
			unrestrictedGrants: [],
			liveGrantCount: 0,
			totalGrantCount: 0,
			defaultKey: { env: null, keyId: null },
		},
	});

	it("names the one affected key, so the inbox row stands alone", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
			{ keyId: PRODUCTION_KEY_ID, state: "warning", expiresAt: fromNow(42).toISOString(), daysRemaining: 42 },
		];

		expect(reportSubject(rows, context())).toBe(
			`[gpg-signing-service] Signing key ${PRODUCTION_KEY_ID} expiring in 42 days`,
		);
	});

	it("counts them instead once more than one key needs attention", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "warning", expiresAt: fromNow(42).toISOString(), daysRemaining: 42 },
			{ keyId: "LAPSED0000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
		];

		expect(reportSubject(rows, context())).toBe("[gpg-signing-service] 2 signing keys need attention");
	});

	it("drops the remaining-time clause for a state that has no date", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "revoked", expiresAt: null, daysRemaining: null, detail: "key is revoked" },
		];

		expect(reportSubject(rows, context())).toBe(`[gpg-signing-service] Signing key ${PRODUCTION_KEY_ID} revoked`);
	});

	it("distinguishes two deployments' otherwise identical mail", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
		];

		expect(reportSubject(rows, context("gpg-signing-service (staging)"))).toBe(
			"[gpg-signing-service (staging)] 1 signing key healthy",
		);
	});
});

describe("renderFailureReport", () => {
	/** Every member of the closed vocabulary, so none of them ships unread */
	const KINDS: MonitorFailureKind[] = ["threshold", "key-storage", "grants", "report"];

	const context = { service: "gpg-signing-service", now: NOW };

	it.each(KINDS)("says the check did not run, for the %s failure", (kind) => {
		const { subject, text, html } = renderFailureReport(kind, context);

		expect(subject).toBe("[gpg-signing-service] Signing key expiry check did not run");
		// Every kind reaches a headline of its own: a `Record` miss would render
		// "could not complete at <date>: undefined" rather than throw.
		expect(text).toMatch(/could not complete at .+: \S/);
		expect(text).not.toContain("undefined");
		expect(text).toContain(NOW.toISOString());
		expect(text).toContain(KEY_EXPIRY_MONITOR_DOCS_URL);
		expect(html).toContain(KEY_EXPIRY_MONITOR_DOCS_URL);
	});

	it("gives each failure class copy an operator can act on", () => {
		expect(renderFailureReport("threshold", context).text).toContain("its warning threshold could not be read");
		expect(renderFailureReport("key-storage", context).text).toContain(
			"the deployment's key storage could not be read",
		);
		expect(renderFailureReport("grants", context).text).toContain("the grant tables could not be read");
		// The fallback class, reached by anything thrown outside a tagged stage.
		// Untested it is the one arm of the vocabulary nobody has ever read.
		expect(renderFailureReport("report", context).text).toContain("the check failed after reading its state");
	});

	it("names the deployment, so a staging failure is not read as production's", () => {
		expect(renderFailureReport("grants", { ...context, service: "gpg-signing-service (staging)" }).subject).toBe(
			"[gpg-signing-service (staging)] Signing key expiry check did not run",
		);
	});

	it("says the silence means nothing until it is fixed", () => {
		// The sentence that makes the alert worth sending: an operator who reads
		// only this one must not conclude the keys were checked and found fine.
		expect(renderFailureReport("grants", context).text).toContain("No signing key was checked on this run");
		expect(renderFailureReport("grants", context).text).toContain("the absence of an expiry warning means nothing");
	});

	it("escapes the deployment label into the HTML body", () => {
		// `ENVIRONMENT` is an operator-set variable that reaches the body
		// verbatim; the renderer, not the caller, is what keeps it inert.
		const { html } = renderFailureReport("report", { ...context, service: 'gpg <b id="x">' });

		expect(html).toContain("gpg &lt;b id=&quot;x&quot;&gt;");
		expect(html).not.toContain("<b id=");
	});
});
