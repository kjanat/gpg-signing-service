import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import {
	actionableRows,
	classifyExpiry,
	DEFAULT_WARN_DAYS,
	daysUntil,
	effectiveExpiry,
	extractDeclaredKeyIds,
	KEY_ROTATION_DOCS_URL,
	type KeyExpiryRow,
	keyMaterialExpiry,
	missingKeyRow,
	parseWarnDays,
	pgpKeyExpiry,
	renderReport,
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

describe("extractDeclaredKeyIds", () => {
	it("finds the production key id in the real wrangler.toml layout", () => {
		const toml = [
			"[vars]",
			'ALLOWED_ISSUERS = "https://token.actions.githubusercontent.com"',
			`KEY_ID          = "${PRODUCTION_KEY_ID}"`,
			"",
			"[env.staging.vars]",
			`KEY_ID          = "${PRODUCTION_KEY_ID}"`,
		].join("\n");

		expect(extractDeclaredKeyIds(toml)).toEqual([PRODUCTION_KEY_ID]);
	});

	it("normalises case, dedupes and sorts", () => {
		const toml = ['KEY_ID = "aaaabbbbccccdddd"', "KEY_ID='1111222233334444'", 'KEY_ID="AAAABBBBCCCCDDDD"'].join("\n");
		expect(extractDeclaredKeyIds(toml)).toEqual(["1111222233334444", "AAAABBBBCCCCDDDD"]);
	});

	it("ignores values that are not 16-hex key ids", () => {
		const toml = ['KEY_ID = "not-a-key-id"', 'KEY_ID = "62E75E54497815"', 'OTHER_KEY_ID = "AAAABBBBCCCCDDDD"'].join(
			"\n",
		);
		// `OTHER_KEY_ID` is a different variable and must not be picked up.
		expect(extractDeclaredKeyIds(toml)).toEqual([]);
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
	it("marks a declared-but-absent key as actionable", () => {
		const row = missingKeyRow(PRODUCTION_KEY_ID);
		expect(row).toMatchObject({
			keyId: PRODUCTION_KEY_ID,
			state: "missing",
			detail: expect.stringContaining("wrangler"),
		});
		expect(actionableRows([row])).toHaveLength(1);
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
	const context = { warnDays: 60, now: NOW, serviceUrl: "https://gpg.example.test" };

	it("says so plainly when nothing is expiring", () => {
		const report = renderReport(
			[{ keyId: PRODUCTION_KEY_ID, state: "ok", expiresAt: fromNow(447).toISOString(), daysRemaining: 447 }],
			context,
		);

		expect(report).toContain("No signing key expires within 60 days.");
		expect(report).not.toContain("### Action required");
		expect(report).toContain("Checked 1 key on https://gpg.example.test");
		expect(report).toContain(`\`${PRODUCTION_KEY_ID}\``);
	});

	it("lists every affected key under an action heading", () => {
		const report = renderReport(
			[
				{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
				{ keyId: PRODUCTION_KEY_ID, state: "warning", expiresAt: fromNow(12).toISOString(), daysRemaining: 12 },
				{ keyId: "LAPSED0000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
			],
			context,
		);

		expect(report).toContain("### Action required");
		expect(report).toContain(`- \`${PRODUCTION_KEY_ID}\`: ⚠️ expiring (12 days)`);
		expect(report).toContain("- `LAPSED0000000000`: 🚨 expired (5 days ago)");
		expect(report).toContain("Checked 3 keys");
		// Absolute: a repo-relative path does not resolve in a GitHub issue body.
		expect(report).toContain(`(${KEY_ROTATION_DOCS_URL})`);
		expect(KEY_ROTATION_DOCS_URL).toMatch(/^https:\/\/github\.com\/.*#key-rotation$/);
		// The healthy key is still in the table, just not in the action list.
		expect(report).toContain("`HEALTHY000000000`");
		expect(report.split("### Action required")[1]).not.toContain("HEALTHY000000000");
	});

	it("sorts worst first so the row that matters is read first", () => {
		const report = renderReport(
			[
				{ keyId: "HEALTHY000000000", state: "ok", expiresAt: fromNow(400).toISOString(), daysRemaining: 400 },
				{ keyId: "NOEXPIRY00000000", state: "no-expiry", expiresAt: null, daysRemaining: null },
				{ keyId: "WARNING000000000", state: "warning", expiresAt: fromNow(30).toISOString(), daysRemaining: 30 },
				{ keyId: "EXPIRED000000000", state: "expired", expiresAt: fromNow(-5).toISOString(), daysRemaining: -5 },
				{ keyId: "ABSENT0000000000", state: "missing", expiresAt: null, daysRemaining: null },
			],
			context,
		);

		const order = [...report.matchAll(/\| `([0-9A-Z]{16})` \|/g)].map((match) => match[1]);
		expect(order).toEqual([
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
			const order = [...renderReport(rows, context).matchAll(/\| `([0-9A-Z]{16})` \|/g)].map((match) => match[1]);
			expect(order).toEqual(["DATED00000000000", "ABSENT0000000000"]);
		}
	});

	it("falls back to key id order for two dateless rows", () => {
		const rows: KeyExpiryRow[] = [
			{ keyId: "ZZZZ000000000000", state: "missing", expiresAt: null, daysRemaining: null },
			{ keyId: "AAAA000000000000", state: "unknown", expiresAt: null, daysRemaining: null },
		];

		const order = [...renderReport(rows, context).matchAll(/\| `([0-9A-Z]{16})` \|/g)].map((match) => match[1]);
		expect(order).toEqual(["AAAA000000000000", "ZZZZ000000000000"]);
	});

	it("renders detail text for keys it could not read", () => {
		const report = renderReport(
			[{ keyId: "BROKEN0000000000", state: "unknown", expiresAt: null, daysRemaining: null, detail: "revoked" }],
			context,
		);

		expect(report).toContain("- `BROKEN0000000000`: ❓ unknown (—) — revoked");
	});

	it("reports an empty deployment without crashing", () => {
		const report = renderReport([], context);
		expect(report).toContain("Checked 0 keys");
		expect(report).toContain("No signing key expires within 60 days.");
	});
});
