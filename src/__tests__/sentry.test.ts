import type { Breadcrumb, ErrorEvent, Event } from "@sentry/cloudflare";
import { CloudflareClient, getCurrentScope, withScope } from "@sentry/cloudflare";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "#types";
import { logger } from "#utils/logger";
import {
	addRefusalBreadcrumb,
	buildSentryOptions,
	captureError,
	captureRefusalEvent,
	collectEnvSecrets,
	DEFAULT_TRACES_SAMPLE_RATE,
	isDeniedKey,
	isSentryConfigured,
	REDACTED,
	redactString,
	scrubBreadcrumb,
	scrubEvent,
	scrubValue,
} from "#utils/sentry";

/**
 * A syntactically valid DSN pointing at nothing. The transport is replaced in
 * every test that binds a client, so nothing is ever sent anywhere — but the
 * SDK refuses to consider itself enabled without a parseable DSN, and half of
 * what this suite proves is the difference between enabled and not.
 */
const FAKE_DSN = "https://0123456789abcdef0123456789abcdef@o0.ingest.example.invalid/1";

/** The forbidden values, one per shape the issue names. */
const SECRETS = {
	passphrase: "correct-horse-battery-staple",
	adminToken: "adm_S3cretAdminToken_do_not_ship",
	readonlyToken: "adm_ReadOnlyAdminToken_nope",
	jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwic3ViIjoicmVwbzprai9nOnJlZjpyZWZzL2hlYWRzL21haW4ifQ.c2lnbmF0dXJlLWhlcmUtbm90LXJlYWw",
	serviceToken: "gst_Yy1kZW1vLXNlcnZpY2UtdG9rZW4tZW50cm9weS12YWx1ZQ",
	armoredKey: [
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"",
		"lQOYBGabcdEFghIJklMNopQRstUVwxYZ0123456789abcdefghijklmnopqrstuv",
		"-----END PGP PRIVATE KEY BLOCK-----",
	].join("\n"),
	pemKey: [
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEAxGZ1p0Vd7bqu3sJd0Yy0mQeC4rXbT2n1qE8hVw6zKmA5cLbN",
		"-----END RSA PRIVATE KEY-----",
	].join("\n"),
} as const;

/** Values that must survive: all of them are already public. */
const PUBLIC = {
	keyId: "62E75E54497815DD",
	fingerprint: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
	issuer: "https://token.actions.githubusercontent.com",
	subject: "repo:kjanat/gpg-signing-service:ref:refs/heads/master",
	tokenHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
} as const;

const configuredEnv = {
	SENTRY_DSN: FAKE_DSN,
	KEY_PASSPHRASE: SECRETS.passphrase,
	ADMIN_TOKEN: SECRETS.adminToken,
	ADMIN_READONLY_TOKEN: SECRETS.readonlyToken,
} satisfies Partial<Env>;

const unconfiguredEnv = {
	KEY_PASSPHRASE: SECRETS.passphrase,
	ADMIN_TOKEN: SECRETS.adminToken,
} satisfies Partial<Env>;

const envSecrets = collectEnvSecrets(configuredEnv);

/** Everything that must never appear in an outgoing envelope. */
const ALL_SECRET_VALUES: readonly string[] = [
	SECRETS.passphrase,
	SECRETS.adminToken,
	SECRETS.readonlyToken,
	SECRETS.jwt,
	SECRETS.serviceToken,
	// The body line of the armor, not the header: the header is not the secret.
	"lQOYBGabcdEFghIJklMNopQRstUVwxYZ0123456789abcdefghijklmnopqrstuv",
	"MIIEowIBAAKCAQEAxGZ1p0Vd7bqu3sJd0Yy0mQeC4rXbT2n1qE8hVw6zKmA5cLbN",
	FAKE_DSN,
];

function expectNoSecrets(serialized: string): void {
	for (const secret of ALL_SECRET_VALUES) {
		expect(serialized).not.toContain(secret);
	}
}

/**
 * Bind a real `CloudflareClient` built from `buildSentryOptions`, with the
 * transport swapped for a recorder, and hand the callback whatever envelopes
 * the SDK actually tried to send.
 *
 * Going through a real client rather than calling `beforeSend` by hand is the
 * point: it proves the hooks are wired into the options the Worker ships, not
 * merely that a function exported next to them works.
 */
async function withRecordingClient<T>(
	env: Partial<Env>,
	run: (envelopes: unknown[], client: CloudflareClient) => Promise<T> | T,
	overrides: Record<string, unknown> = {},
): Promise<T> {
	const envelopes: unknown[] = [];
	const client = new CloudflareClient({
		...buildSentryOptions(env),
		integrations: [],
		stackParser: () => [],
		transport: () => ({
			send: async (envelope: unknown) => {
				envelopes.push(envelope);
				return {};
			},
			flush: async () => true,
		}),
		...overrides,
	} as never);

	return withScope(async (scope) => {
		scope.setClient(client);
		client.init();
		try {
			return await run(envelopes, client);
		} finally {
			await client.flush(0);
			client.dispose();
		}
	}) as Promise<T>;
}

/** The single event a recorded envelope carries. */
function eventFrom(envelopes: unknown[], index = 0): Event {
	const envelope = envelopes[index] as [unknown, [[unknown, Event]]];
	return envelope[1][0][1];
}

describe("Sentry option construction", () => {
	it("disables everything when no DSN is configured", () => {
		const options = buildSentryOptions(unconfiguredEnv);

		expect(options.dsn).toBeUndefined();
		expect(options.enabled).toBe(false);
		expect(options.tracesSampleRate).toBe(0);
		// No default integrations means no console wrapping, no fetch patching and
		// no request-body reader — the guarantee that an unset DSN leaves Workers
		// Logs and `audit_logs` exactly as they were.
		expect(options.defaultIntegrations).toBe(false);
		expect(options.integrations).toEqual([]);
	});

	it("treats a whitespace-only DSN as unset", () => {
		const options = buildSentryOptions({ ...unconfiguredEnv, SENTRY_DSN: "   " });

		expect(options.dsn).toBeUndefined();
		expect(options.enabled).toBe(false);
		expect(isSentryConfigured({ SENTRY_DSN: "   " })).toBe(false);
	});

	it("treats an empty DSN as unset", () => {
		expect(isSentryConfigured({ SENTRY_DSN: "" })).toBe(false);
		expect(isSentryConfigured({})).toBe(false);
		expect(isSentryConfigured(configuredEnv)).toBe(true);
	});

	it("enables reporting when a DSN is configured", () => {
		const options = buildSentryOptions(configuredEnv);

		expect(options.dsn).toBe(FAKE_DSN);
		expect(options.enabled).toBe(true);
		expect(options.tracesSampleRate).toBe(DEFAULT_TRACES_SAMPLE_RATE);
	});

	it("never sends default PII, configured or not", () => {
		expect(buildSentryOptions(configuredEnv).sendDefaultPii).toBe(false);
		expect(buildSentryOptions(unconfiguredEnv).sendDefaultPii).toBe(false);
	});

	it("pins spotlight off so a stray variable cannot enable forwarding", () => {
		expect(buildSentryOptions(configuredEnv).spotlight).toBe(false);
		expect(buildSentryOptions(unconfiguredEnv).spotlight).toBe(false);
	});

	it("honours a valid trace sample rate override", () => {
		expect(buildSentryOptions({ ...configuredEnv, SENTRY_TRACES_SAMPLE_RATE: "0.5" }).tracesSampleRate).toBe(0.5);
		expect(buildSentryOptions({ ...configuredEnv, SENTRY_TRACES_SAMPLE_RATE: "0" }).tracesSampleRate).toBe(0);
		expect(buildSentryOptions({ ...configuredEnv, SENTRY_TRACES_SAMPLE_RATE: "1" }).tracesSampleRate).toBe(1);
	});

	it("falls back to the default for an unusable trace sample rate", () => {
		for (const raw of ["", "  ", "nonsense", "-0.1", "1.5", "Infinity"]) {
			expect(buildSentryOptions({ ...configuredEnv, SENTRY_TRACES_SAMPLE_RATE: raw }).tracesSampleRate).toBe(
				DEFAULT_TRACES_SAMPLE_RATE,
			);
		}
	});

	it("labels events with the deployment environment when one is set", () => {
		expect(buildSentryOptions({ ...configuredEnv, ENVIRONMENT: "staging" }).environment).toBe("staging");
		expect(buildSentryOptions(configuredEnv).environment).toBeUndefined();
	});

	it("replaces the body-collecting and Hono integrations when enabled", () => {
		const build = buildSentryOptions(configuredEnv).integrations;
		expect(typeof build).toBe("function");

		const defaults = [{ name: "HttpServer" }, { name: "Hono" }, { name: "Dedupe" }] as never[];
		const resolved = (build as (integrations: never[]) => { name: string }[])(defaults);
		const names = resolved.map((integration) => integration.name);

		expect(names).toContain("Dedupe");
		// Exactly one of each: the defaults were removed, not shadowed.
		expect(names.filter((name) => name === "HttpServer")).toHaveLength(1);
		expect(names.filter((name) => name === "Hono")).toHaveLength(1);

		const httpServer = resolved.find((integration) => integration.name === "HttpServer") as {
			maxRequestBodySize?: string;
		};
		// Request bodies carry armored key material on the admin upload route.
		expect(httpServer.maxRequestBodySize).toBe("none");

		const hono = resolved.find((integration) => integration.name === "Hono") as {
			handleHonoException?: (error: unknown, context?: unknown) => void;
		};
		expect(typeof hono.handleHonoException).toBe("function");
	});

	it("installs the scrubbing hooks on both branches", () => {
		for (const env of [configuredEnv, unconfiguredEnv]) {
			const options = buildSentryOptions(env);
			expect(typeof options.beforeSend).toBe("function");
			expect(typeof options.beforeSendTransaction).toBe("function");
			expect(typeof options.beforeBreadcrumb).toBe("function");
		}
	});

	it("wires every hook to the scrubber, sweeping this deployment's own secrets", () => {
		const options = buildSentryOptions(configuredEnv);

		const sent = options.beforeSend?.(
			{
				type: undefined,
				message: `failed with ${SECRETS.passphrase}`,
				extra: { ADMIN_TOKEN: SECRETS.adminToken },
			} as ErrorEvent,
			{},
		) as ErrorEvent;
		expect(sent.message).not.toContain(SECRETS.passphrase);
		expect(sent.extra?.ADMIN_TOKEN).toBe(REDACTED);

		const transaction = options.beforeSendTransaction?.(
			{ type: "transaction", transaction: `POST /sign?token=${SECRETS.serviceToken}` } as never,
			{},
		) as Event;
		expect(transaction.transaction).not.toContain(SECRETS.serviceToken);

		const crumb = options.beforeBreadcrumb?.({
			category: "console",
			message: `presented ${SECRETS.jwt}`,
			data: { Authorization: `Bearer ${SECRETS.jwt}` },
		}) as Breadcrumb;
		expect(crumb.message).not.toContain(SECRETS.jwt);
		expect((crumb.data as Record<string, string>).Authorization).toBe(REDACTED);
	});

	it("sweeps literal secrets even with the DSN unset, so a later path cannot bypass it", () => {
		const sent = buildSentryOptions(unconfiguredEnv).beforeSend?.(
			{ type: undefined, message: `leaked ${SECRETS.passphrase}` } as ErrorEvent,
			{},
		) as ErrorEvent;
		expect(sent.message).not.toContain(SECRETS.passphrase);
	});
});

describe("collectEnvSecrets", () => {
	it("collects the deployment's own secret values", () => {
		expect(collectEnvSecrets(configuredEnv)).toEqual(
			expect.arrayContaining([SECRETS.passphrase, SECRETS.adminToken, SECRETS.readonlyToken, FAKE_DSN]),
		);
	});

	it("skips values too short to search for safely", () => {
		// A one-character passphrase would otherwise redact every word containing
		// that letter, turning the whole event into noise.
		expect(collectEnvSecrets({ KEY_PASSPHRASE: "x", ADMIN_TOKEN: "  " })).toEqual([]);
	});

	it("orders longest first so a containing secret is redacted whole", () => {
		const secrets = collectEnvSecrets({ KEY_PASSPHRASE: "shortsecret", ADMIN_TOKEN: "shortsecret-and-more" });
		expect(secrets[0]).toBe("shortsecret-and-more");
	});
});

describe("key denylist", () => {
	it("denies the names secrets actually arrive under", () => {
		for (const key of [
			"Authorization",
			"authorization",
			"AUTHORIZATION",
			"proxy-authorization",
			"KEY_PASSPHRASE",
			"keyPassphrase",
			"passphrase",
			"password",
			"ADMIN_TOKEN",
			"admin_token",
			"ADMIN_READONLY_TOKEN",
			"armoredPrivateKey",
			"privateKeyPem",
			"privateKey",
			"token",
			"idToken",
			"apiKey",
			"x-api-key",
			"cookie",
			"set-cookie",
			"clientSecret",
			"SENTRY_DSN",
		]) {
			expect(isDeniedKey(key), key).toBe(true);
		}
	});

	it("leaves the diagnostic vocabulary alone", () => {
		for (const key of [
			"keyId",
			"fingerprint",
			"issuer",
			"subject",
			"subjectId",
			"subjectPolicy",
			"requestId",
			"action",
			"errorCode",
			"tokenHash",
			"expiresAt",
			"revokedAt",
			"activePrefixCount",
		]) {
			expect(isDeniedKey(key), key).toBe(false);
		}
	});
});

describe("redactString", () => {
	it("redacts a raw OIDC JWT anywhere in a string", () => {
		const redacted = redactString(`verification failed for ${SECRETS.jwt} at issuer`);
		expect(redacted).not.toContain(SECRETS.jwt);
		expect(redacted).toContain(REDACTED);
		expect(redacted).toContain("at issuer");
	});

	it("redacts every JWT in a string, not only the first", () => {
		const redacted = redactString(`${SECRETS.jwt} then ${SECRETS.jwt}`);
		expect(redacted).not.toContain("eyJ");
	});

	it("redacts a gst_ service token", () => {
		const redacted = redactString(`presented ${SECRETS.serviceToken}`);
		expect(redacted).not.toContain(SECRETS.serviceToken);
		expect(redacted).toContain(REDACTED);
	});

	it("redacts a presented Bearer credential but keeps the scheme", () => {
		const redacted = redactString(`Authorization: Bearer ${SECRETS.serviceToken}`);
		expect(redacted).toContain(`Bearer ${REDACTED}`);
		expect(redacted).not.toContain(SECRETS.serviceToken);
	});

	it("redacts a Basic credential too", () => {
		const redacted = redactString("Basic YWRtaW46aHVudGVyMg==");
		expect(redacted).not.toContain("YWRtaW46aHVudGVyMg==");
	});

	it("leaves the documentation prose about Bearer readable", () => {
		const hint = "Send `Authorization: Bearer <token>` with an OIDC token minted for this service's audience.";
		expect(redactString(hint)).toBe(hint);
	});

	it("redacts armored PGP private key material", () => {
		const redacted = redactString(`stored key: ${SECRETS.armoredKey}`);
		expect(redacted).not.toContain("lQOYBGabcdEFghIJklMNopQRstUVwxYZ0123456789abcdefghijklmnopqrstuv");
		expect(redacted).toContain(REDACTED);
	});

	it("redacts a PEM private key", () => {
		const redacted = redactString(SECRETS.pemKey);
		expect(redacted).not.toContain("MIIEowIBAAKCAQEAxGZ1p0Vd7bqu3sJd0Yy0mQeC4rXbT2n1qE8hVw6zKmA5cLbN");
	});

	it("redacts a truncated armor block, which is still a private key", () => {
		const truncated = SECRETS.armoredKey.slice(0, SECRETS.armoredKey.length - 40);
		const redacted = redactString(truncated);
		expect(redacted).not.toContain("lQOYBGabcdEFghIJklMNopQRstUVwxYZ0123456789abcdefghijklmnopqrstuv");
	});

	it("redacts the deployment's own literal secrets", () => {
		const redacted = redactString(`passphrase was ${SECRETS.passphrase}`, envSecrets);
		expect(redacted).not.toContain(SECRETS.passphrase);
		expect(redacted).toContain(REDACTED);
	});

	it("does not redact literal secrets it was not given", () => {
		// The guard that makes the previous test meaningful: without the sweep
		// list, a secret under an innocuous name and shape survives — which is
		// exactly why `buildSentryOptions` binds `collectEnvSecrets(env)`.
		expect(redactString(`passphrase was ${SECRETS.passphrase}`)).toContain(SECRETS.passphrase);
	});

	it("leaves public diagnostic values untouched", () => {
		for (const value of Object.values(PUBLIC)) {
			expect(redactString(value, envSecrets)).toBe(value);
		}
	});
});

describe("scrubValue", () => {
	it("redacts denied keys at any depth", () => {
		const scrubbed = scrubValue(
			{
				keyId: PUBLIC.keyId,
				nested: { deeper: { Authorization: `Bearer ${SECRETS.serviceToken}`, keyPassphrase: SECRETS.passphrase } },
			},
			envSecrets,
		);

		expect(scrubbed.nested.deeper.Authorization).toBe(REDACTED);
		expect(scrubbed.nested.deeper.keyPassphrase).toBe(REDACTED);
		expect(scrubbed.keyId).toBe(PUBLIC.keyId);
	});

	it("redacts secret shapes inside arrays", () => {
		const scrubbed = scrubValue({ presented: [SECRETS.jwt, PUBLIC.keyId] }, envSecrets);
		expect(scrubbed.presented[0]).toBe(REDACTED);
		expect(scrubbed.presented[1]).toBe(PUBLIC.keyId);
	});

	it("does not mutate its input", () => {
		const original = { Authorization: `Bearer ${SECRETS.serviceToken}` };
		scrubValue(original, envSecrets);
		expect(original.Authorization).toBe(`Bearer ${SECRETS.serviceToken}`);
	});

	it("cuts cycles rather than recursing forever", () => {
		const cyclic: Record<string, unknown> = { keyId: PUBLIC.keyId };
		cyclic.self = cyclic;

		const scrubbed = scrubValue(cyclic, envSecrets);
		expect(scrubbed.keyId).toBe(PUBLIC.keyId);
		expect(scrubbed.self).toBe(REDACTED);
	});

	it("stops descending past the depth cap", () => {
		let deep: Record<string, unknown> = { leak: SECRETS.passphrase };
		for (let i = 0; i < 20; i++) deep = { next: deep };

		// The cap replaces the subtree wholesale, so nothing below it escapes.
		expect(JSON.stringify(scrubValue(deep, envSecrets))).not.toContain(SECRETS.passphrase);
	});

	it("passes primitives through unchanged", () => {
		expect(scrubValue(42)).toBe(42);
		expect(scrubValue(true)).toBe(true);
		expect(scrubValue(null)).toBe(null);
		expect(scrubValue(undefined)).toBe(undefined);
	});

	it("leaves objects with their own identity intact", () => {
		const date = new Date("2026-08-30T00:00:00.000Z");
		expect(scrubValue({ at: date }).at).toBe(date);
	});
});

describe("scrubEvent", () => {
	/** An event carrying every forbidden value, in every place one can hide. */
	function pollutedEvent(): ErrorEvent {
		return {
			type: undefined,
			message: `signing failed with ${SECRETS.jwt}`,
			exception: {
				values: [
					{
						type: "Error",
						value: `openpgp could not decrypt with passphrase ${SECRETS.passphrase}`,
					},
					{
						type: "Error",
						value: SECRETS.armoredKey,
					},
				],
			},
			request: {
				url: `https://gpg.example.test/sign?keyId=${PUBLIC.keyId}`,
				method: "POST",
				headers: {
					Authorization: `Bearer ${SECRETS.jwt}`,
					"X-Request-ID": "b3c1c0e0-0000-4000-8000-000000000000",
					"User-Agent": "gpg-sign/1.2.0",
				},
				cookies: { session: SECRETS.adminToken },
				data: { armoredPrivateKey: SECRETS.armoredKey, passphrase: SECRETS.passphrase },
				query_string: `token=${SECRETS.serviceToken}`,
			},
			extra: {
				ADMIN_TOKEN: SECRETS.adminToken,
				KEY_PASSPHRASE: SECRETS.passphrase,
				armoredPrivateKey: SECRETS.armoredKey,
				privateKeyPem: SECRETS.pemKey,
				presented: SECRETS.serviceToken,
				// An innocuous name holding a secret value: only the literal sweep
				// catches this one.
				detail: `operator supplied ${SECRETS.passphrase}`,
				nested: { deeper: [{ authorization: `Bearer ${SECRETS.jwt}` }] },
				keyId: PUBLIC.keyId,
				fingerprint: PUBLIC.fingerprint,
			},
			contexts: {
				runtime: { name: "cloudflare-workers" },
				credential: { adminToken: SECRETS.adminToken },
				caller: { tokenHash: PUBLIC.tokenHash, issuer: PUBLIC.issuer },
			},
			tags: { requestId: "b3c1c0e0-0000-4000-8000-000000000000", issuer: PUBLIC.issuer },
			user: { id: PUBLIC.subject },
			breadcrumbs: [
				{
					category: "console",
					message: `{"level":"warn","token":"${SECRETS.serviceToken}"}`,
					data: { Authorization: `Bearer ${SECRETS.jwt}`, keyId: PUBLIC.keyId },
				},
			],
		} as ErrorEvent;
	}

	it("leaves no forbidden value anywhere in the event", () => {
		const scrubbed = scrubEvent(pollutedEvent(), envSecrets);
		expectNoSecrets(JSON.stringify(scrubbed));
	});

	it("keeps the diagnostic values that make the event worth having", () => {
		const serialized = JSON.stringify(scrubEvent(pollutedEvent(), envSecrets));

		expect(serialized).toContain(PUBLIC.keyId);
		expect(serialized).toContain(PUBLIC.fingerprint);
		expect(serialized).toContain(PUBLIC.issuer);
		expect(serialized).toContain(PUBLIC.subject);
		expect(serialized).toContain(PUBLIC.tokenHash);
		expect(serialized).toContain("b3c1c0e0-0000-4000-8000-000000000000");
		expect(serialized).toContain("gpg-sign/1.2.0");
	});

	it("drops the request body and cookies outright", () => {
		const scrubbed = scrubEvent(pollutedEvent(), envSecrets);
		expect(scrubbed.request?.data).toBeUndefined();
		expect(scrubbed.request?.cookies).toBeUndefined();
		// The URL and method survive; they are the diagnosis.
		expect(scrubbed.request?.method).toBe("POST");
	});

	it("redacts the Authorization header rather than dropping the header bag", () => {
		const scrubbed = scrubEvent(pollutedEvent(), envSecrets);
		const headers = scrubbed.request?.headers as Record<string, string>;
		expect(headers.Authorization).toBe(REDACTED);
		expect(headers["User-Agent"]).toBe("gpg-sign/1.2.0");
	});

	it("scrubs exception messages", () => {
		const scrubbed = scrubEvent(pollutedEvent(), envSecrets);
		const values = scrubbed.exception?.values ?? [];
		expect(values[0]?.value).not.toContain(SECRETS.passphrase);
		expect(values[1]?.value).toBe(REDACTED);
	});

	it("scrubs breadcrumbs carried on the event", () => {
		const scrubbed = scrubEvent(pollutedEvent(), envSecrets);
		const crumb = scrubbed.breadcrumbs?.[0] as Breadcrumb;
		expect(crumb.message).not.toContain(SECRETS.serviceToken);
		expect((crumb.data as Record<string, string>).Authorization).toBe(REDACTED);
		expect((crumb.data as Record<string, string>).keyId).toBe(PUBLIC.keyId);
	});

	it("redacts a whole subtree hanging off a denied key", () => {
		const scrubbed = scrubEvent(pollutedEvent(), envSecrets);
		// `contexts.credential` is condemned by its name, so nothing under it is
		// inspected further — the conservative reading, and the one that survives
		// somebody adding a field to it later.
		expect(scrubbed.contexts?.credential).toBe(REDACTED);
	});

	it("handles an event with no request section", () => {
		const scrubbed = scrubEvent({ message: "plain" } as Event, envSecrets);
		expect(scrubbed.message).toBe("plain");
	});
});

describe("scrubBreadcrumb", () => {
	it("redacts both the message and the data of a standalone breadcrumb", () => {
		const scrubbed = scrubBreadcrumb(
			{
				category: "auth.refusal",
				message: `presented ${SECRETS.jwt}`,
				data: { authorization: `Bearer ${SECRETS.jwt}`, issuer: PUBLIC.issuer, secretValue: SECRETS.passphrase },
			},
			envSecrets,
		) as Breadcrumb;

		expect(scrubbed.message).not.toContain(SECRETS.jwt);
		expect((scrubbed.data as Record<string, string>).authorization).toBe(REDACTED);
		expect((scrubbed.data as Record<string, string>).issuer).toBe(PUBLIC.issuer);
		expect((scrubbed.data as Record<string, string>).secretValue).toBe(REDACTED);
	});
});

describe("capture helpers with no DSN configured", () => {
	it("report nothing and say so", async () => {
		await withRecordingClient(unconfiguredEnv, (envelopes) => {
			// `Sentry.captureException` returns an event id even with no usable
			// client, so `undefined` here can only come from this module's own
			// guard. Remove the guard and these assertions fail.
			expect(captureError("boom", new Error("boom"), { requestId: "req-1" })).toBeUndefined();
			expect(captureRefusalEvent("Key scope denied", { requestId: "req-1" })).toBeUndefined();
			expect(() => addRefusalBreadcrumb("Expired OIDC trust presented", { requestId: "req-1" })).not.toThrow();
			expect(envelopes).toHaveLength(0);
		});
	});

	it("report nothing when a client exists but carries no DSN", async () => {
		await withRecordingClient(
			configuredEnv,
			(envelopes) => {
				expect(captureError("boom", new Error("boom"))).toBeUndefined();
				expect(captureRefusalEvent("Key scope denied")).toBeUndefined();
				expect(envelopes).toHaveLength(0);
			},
			{ dsn: undefined },
		);
	});

	it("report nothing when a DSN is present but reporting is disabled", async () => {
		await withRecordingClient(
			configuredEnv,
			(envelopes) => {
				expect(captureError("boom", new Error("boom"))).toBeUndefined();
				expect(captureRefusalEvent("Key scope denied")).toBeUndefined();
				expect(envelopes).toHaveLength(0);
			},
			{ enabled: false },
		);
	});

	it("does not throw with no client bound at all", () => {
		expect(getCurrentScope().getClient()).toBeUndefined();
		expect(captureError("boom", new Error("boom"))).toBeUndefined();
		expect(captureRefusalEvent("Key scope denied")).toBeUndefined();
		expect(() => addRefusalBreadcrumb("Expired OIDC trust presented")).not.toThrow();
	});
});

describe("outgoing envelopes", () => {
	it("carries no secret out of an error that was full of them", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			const error = new Error(
				`sign failed: passphrase ${SECRETS.passphrase}, token ${SECRETS.serviceToken}, jwt ${SECRETS.jwt}`,
			);

			const eventId = captureError("Unhandled error", error, {
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
				code: "INTERNAL_ERROR",
				errorCode: "INTERNAL_ERROR",
				keyId: PUBLIC.keyId,
				issuer: PUBLIC.issuer,
				authorization: `Bearer ${SECRETS.jwt}`,
				armoredPrivateKey: SECRETS.armoredKey,
				adminToken: SECRETS.adminToken,
			});

			expect(eventId).toEqual(expect.any(String));
			await new Promise((resolve) => setTimeout(resolve, 0));

			expect(envelopes).toHaveLength(1);
			expectNoSecrets(JSON.stringify(envelopes[0]));
		});
	});

	it("tags the event with requestId, action and errorCode", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			captureError("Rate limiter failed", new Error("unreachable"), {
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
				errorCode: "RATE_LIMIT_ERROR",
				keyId: PUBLIC.keyId,
			});
			await new Promise((resolve) => setTimeout(resolve, 0));

			const event = eventFrom(envelopes);
			expect(event.tags).toMatchObject({
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
				errorCode: "RATE_LIMIT_ERROR",
			});
			// Anything not a tag rides along as `extra`, still scrubbed.
			expect(event.extra).toMatchObject({ keyId: PUBLIC.keyId, logMessage: "Rate limiter failed" });
			expect(event.level).toBe("error");
		});
	});

	it("never sets user data the caller did not ask for", async () => {
		await withRecordingClient(configuredEnv, async (envelopes, client) => {
			expect(client.getOptions().sendDefaultPii).toBe(false);

			captureError("boom", new Error("boom"), { requestId: "req-1" });
			await new Promise((resolve) => setTimeout(resolve, 0));

			expect(eventFrom(envelopes).user).toBeUndefined();
		});
	});

	it("reassembles the bag app.onError logs into a real error", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			// The shape `src/index.ts` has always logged: message and stack as
			// strings, not an Error. Reported without losing either.
			captureError(
				"Unhandled error",
				{
					requestId: "b3c1c0e0-0000-4000-8000-000000000000",
					error: "Cannot read properties of undefined",
					stack: "Error: Cannot read properties of undefined\n    at signHandler (src/routes/sign.ts:1:1)",
				},
				{ requestId: "b3c1c0e0-0000-4000-8000-000000000000" },
			);
			await new Promise((resolve) => setTimeout(resolve, 0));

			const value = eventFrom(envelopes).exception?.values?.[0];
			expect(value?.value).toBe("Unhandled error: Cannot read properties of undefined");
			expect(value?.type).toBe("LoggedError");
		});
	});

	it("reports a non-object error slot without losing the message", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			captureError("Key processing error", "not an object");
			await new Promise((resolve) => setTimeout(resolve, 0));

			expect(eventFrom(envelopes).exception?.values?.[0]?.value).toBe("Key processing error");
		});
	});

	it("raises an alertable, tagged event for a security-relevant refusal", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			captureRefusalEvent("Revoked OIDC trust presented", {
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
				errorCode: "AUTH_INVALID",
				reason: "revoked_trust_presented",
				issuer: PUBLIC.issuer,
				subject: PUBLIC.subject,
			});
			await new Promise((resolve) => setTimeout(resolve, 0));

			const event = eventFrom(envelopes);
			expect(event.message).toBe("Revoked OIDC trust presented");
			expect(event.level).toBe("warning");
			expect(event.tags).toMatchObject({
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
				errorCode: "AUTH_INVALID",
				refusal: "true",
			});
			expect(event.extra).toMatchObject({ reason: "revoked_trust_presented", issuer: PUBLIC.issuer });
		});
	});

	it("does not double-report: the SDK's Hono handler captures nothing", async () => {
		const resolveIntegrations = buildSentryOptions(configuredEnv).integrations as (
			defaults: never[],
		) => { name: string; handleHonoException?: (error: unknown, context?: unknown) => void }[];

		await withRecordingClient(
			configuredEnv,
			async (envelopes) => {
				const hono = resolveIntegrations([]).find((integration) => integration.name === "Hono");

				// This is what `withSentry` calls from inside `app.onError`. With the
				// SDK's own capture left on it emits an untagged second event for
				// every 500; with `shouldHandleError` pinned false it emits nothing,
				// and `logger.error` stays the only reporter.
				hono?.handleHonoException?.(new Error("unhandled route failure"));
				await new Promise((resolve) => setTimeout(resolve, 0));

				expect(envelopes).toHaveLength(0);
			},
			{ integrations: [] },
		);
	});

	it("attaches a routine refusal as a breadcrumb rather than an event", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			addRefusalBreadcrumb("Expired OIDC trust presented", {
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				issuer: PUBLIC.issuer,
				subject: PUBLIC.subject,
				presented: `Bearer ${SECRETS.jwt}`,
			});
			// No event yet: a breadcrumb is context, not a report.
			expect(envelopes).toHaveLength(0);

			captureError("Unhandled error", new Error("later failure"));
			await new Promise((resolve) => setTimeout(resolve, 0));

			const event = eventFrom(envelopes);
			const crumb = event.breadcrumbs?.find((entry) => entry.message === "Expired OIDC trust presented") as Breadcrumb;
			expect(crumb).toBeDefined();
			expect(crumb.category).toBe("auth.refusal");
			expect((crumb.data as Record<string, string>).issuer).toBe(PUBLIC.issuer);
			expectNoSecrets(JSON.stringify(envelopes[0]));
		});
	});
});

describe("logger.error reporting", () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
	});

	afterEach(() => {
		consoleSpy.mockRestore();
	});

	it("emits exactly one console line and one Sentry event", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			logger.error("Rate limiter failed", new Error("limiter unreachable"), {
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
				code: "RATE_LIMIT_ERROR",
			});
			await new Promise((resolve) => setTimeout(resolve, 0));

			expect(consoleSpy).toHaveBeenCalledTimes(1);
			expect(envelopes).toHaveLength(1);

			const event = eventFrom(envelopes);
			// `code` is the codebase's name; the tag an alert filters on is
			// `errorCode`.
			expect(event.tags).toMatchObject({ errorCode: "RATE_LIMIT_ERROR", action: "sign" });
		});
	});

	it("leaves the emitted log line byte-for-byte what it always was", async () => {
		await withRecordingClient(configuredEnv, async () => {
			logger.error("Key processing error", new Error("bad armor"), { requestId: "req-9" });

			const emitted = JSON.parse(consoleSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
			expect(Object.keys(emitted).sort()).toEqual(["error", "level", "message", "requestId", "timestamp"]);
			expect(emitted.level).toBe("error");
			expect(emitted.message).toBe("Key processing error");
			expect(emitted.error).toEqual({ message: "bad armor", name: "Error" });
		});
	});

	it("reports once, not twice, through a request-scoped logger", async () => {
		await withRecordingClient(configuredEnv, async (envelopes) => {
			const scoped = logger.withContext({
				get: () => "b3c1c0e0-0000-4000-8000-000000000000",
				req: { header: () => undefined },
			} as never);

			scoped.error("Scoped failure", new Error("boom"), { action: "sign" });
			await new Promise((resolve) => setTimeout(resolve, 0));

			expect(consoleSpy).toHaveBeenCalledTimes(1);
			expect(envelopes).toHaveLength(1);
			expect(eventFrom(envelopes).tags).toMatchObject({
				requestId: "b3c1c0e0-0000-4000-8000-000000000000",
				action: "sign",
			});
		});
	});

	it("still logs, and reports nothing, with no DSN configured", async () => {
		await withRecordingClient(unconfiguredEnv, async (envelopes) => {
			logger.error("Database health check failed", new Error("D1 down"), { requestId: "req-3" });
			await new Promise((resolve) => setTimeout(resolve, 0));

			expect(consoleSpy).toHaveBeenCalledTimes(1);
			expect(envelopes).toHaveLength(0);
		});
	});
});
