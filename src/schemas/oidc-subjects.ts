import { z } from "@hono/zod-openapi";

import { KeyIdSchema } from "#schemas/keys";

/** Trusted subject name: human-readable label for the CI identity. */
export const SubjectNameSchema = z
	.string()
	.min(1)
	.max(64)
	.regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/, "Name must be alphanumeric with ._/- separators")
	.openapi("SubjectName");

/**
 * Both prefix rules below as one expression, for the published JSON Schema.
 *
 * A JSON Schema string carries a single `pattern`, so the two `.regex()` checks
 * — which exist separately to keep their error messages apart — collapse to this
 * for `client/openapi.json`. It is the intersection: `\S` narrowed to exclude
 * the glob characters as well as whitespace. Written as an explicit character
 * class rather than a lookahead so it stays legible to somebody reading the spec
 * to work out why their prefix was refused.
 *
 * Change either `.regex()` and this must change with it; the round trip is
 * covered in `schemas.test.ts`.
 */
export const SUBJECT_PREFIX_PATTERN = "^[^\\s*?[\\]]*[:@/][^\\s*?[\\]]*[^\\s:@/*?[\\]][^\\s*?[\\]]*$";

/**
 * A `sub` prefix. Matched with a delimiter boundary, so `repo:owner/name`
 * does not admit `repo:owner/name-evil`, while `repo:owner/` is owner-wide.
 */
export const SubjectPrefixSchema = z
	.string()
	.min(1)
	.max(255)
	// A prefix must identify somebody. Because a prefix ending at a delimiter is
	// deliberately owner-wide, a bare scheme segment is *host*-wide: `repo:` —
	// and `repo` too, since the boundary check then lands on the `:` — matches
	// every repository on GitHub Actions, reinstating exactly what this table
	// exists to prevent. One truncated paste of a rollout command would do it,
	// and unlike every other degenerate input here it fails open.
	//
	// Expressed as a single regex rather than a `.refine()` so it survives into
	// client/openapi.json: refinements have no JSON Schema representation, so a
	// generated client would otherwise believe `repo:` is a legal value. The
	// leading `\S*` subsumes the no-whitespace rule, and requiring a
	// non-delimiter after *some* delimiter is equivalent to requiring one after
	// the *first*, since the first precedes every other.
	.regex(
		/^\S*[:@/]\S*[^\s:@/]\S*$/,
		"Subject prefix must have no whitespace and must name an identity after its scheme, e.g. repo:owner — not repo: or repo",
	)
	// Globs are the other degenerate input, and the one an operator reaches for
	// first: matching is `startsWith` plus a delimiter check, never a pattern
	// match, so `repo:owner/*` is stored and compared verbatim and matches only a
	// repository literally called `*`. That row lists as active, never authorizes
	// anybody, and the failure surfaces as `Subject is not trusted for signing` on
	// some later run with nothing tying it back to the create. Fail at the point
	// of the typo instead, and name the form that actually does what was meant.
	//
	// `*`, `?` and `[` cannot appear in a real subject: git-check-ref-format
	// forbids all three in a ref name, and neither GitHub's `repo:owner/name:…`
	// nor GitLab's `project_path:group/project:…` puts them anywhere else. So
	// nothing legitimate is refused here.
	//
	// A second `.regex()` rather than one combined pattern, so each rule keeps its
	// own message: a caller who typed a glob is told about globs, not handed the
	// bare-scheme rule to decode. Only the first check reaches `pattern` in
	// client/openapi.json — a JSON Schema string has one — so the combined
	// expression is restated in `.openapi()` below, and the two must be kept in
	// step. The whole-string alternation is written out rather than a lookahead so
	// the published pattern stays readable to whoever is debugging a 400 against
	// it.
	.regex(
		/^[^*?[\]]*$/,
		"Subject prefix is a literal prefix, not a glob — remove * ? [ ]. A prefix ending at a delimiter is already the wildcard: repo:owner/ trusts every repository of that owner",
	)
	.openapi("SubjectPrefix", {
		pattern: SUBJECT_PREFIX_PATTERN,
		// The rule is only obvious once you know matching is startsWith, so state
		// it where the spec is read. TSDoc above does not reach openapi.json.
		description:
			"A literal prefix of the token's `sub`, not a glob — `*`, `?` and `[` are refused. A subject " +
			"matches when it starts with this string and the next character is a delimiter (`:`, `@`, `/`) " +
			"or the end of the subject, so `repo:owner/svc` does not admit `repo:owner/svc-evil`. A prefix " +
			"that ends at a delimiter is the wildcard: `repo:owner/` trusts every repository of that owner. " +
			"Where several rows match, the longest live prefix wins.",
		example: "repo:owner/repository",
	});

/** Request body for trusting an OIDC subject. */
export const SubjectCreateSchema = z
	.object({
		name: SubjectNameSchema,
		/** Issuer this subject must present, pinned so issuers cannot collide. */
		issuer: z.string().url(),
		subjectPrefix: SubjectPrefixSchema,
		/**
		 * Key ids this subject may sign with; omit for every key. Uses the same
		 * schema as key upload, which normalizes to uppercase — a lowercase id
		 * would otherwise store as written, list as allowed, and never match the
		 * case-sensitive check in the sign route.
		 *
		 * An empty array is refused rather than accepted: it stores as the empty
		 * key_ids string, which means *every* key, so a caller that meant to
		 * restrict would silently widen. Omit the field to mean every key.
		 */
		keyIds: z.array(KeyIdSchema).min(1, "keyIds must list at least one key; omit it to allow every key").optional(),
		/** Days until expiry; omit for a non-expiring trust. */
		expiresInDays: z.number().int().min(1).max(3650).optional(),
	})
	.openapi("SubjectCreate");

/** One trusted subject in the list view. */
export const SubjectSummarySchema = z
	.object({
		id: z.string(),
		name: SubjectNameSchema,
		issuer: z.string(),
		subjectPrefix: SubjectPrefixSchema,
		keyIds: z.array(z.string()).nullable(),
		createdAt: z.string(),
		expiresAt: z.string().nullable(),
		revokedAt: z.string().nullable(),
		lastUsedAt: z.string().nullable(),
		/**
		 * Whether this row would authorize a token right now — neither revoked nor
		 * expired. Derived server-side because the alternative is every client
		 * re-implementing the same date comparison, and an expired row looks
		 * identical to a live one until you do it.
		 */
		active: z.boolean(),
	})
	.openapi("SubjectSummary");

export const SubjectCreatedResponseSchema = SubjectSummarySchema.openapi("SubjectCreatedResponse");

export const SubjectListResponseSchema = z
	.object({ subjects: z.array(SubjectSummarySchema) })
	.openapi("SubjectListResponse");

/** A live row that still covers a revoked subject's prefix. */
export const CoveringSubjectSchema = z
	.object({
		id: z.string(),
		name: SubjectNameSchema,
		subjectPrefix: SubjectPrefixSchema,
		keyIds: z.array(z.string()).nullable(),
	})
	.openapi("CoveringSubject");

export const SubjectRevokeResponseSchema = z
	.object({
		success: z.boolean(),
		id: z.string(),
		/** The revoked row's name — the key `sign` audit events are recorded under. */
		name: SubjectNameSchema,
		/**
		 * Live rows whose prefix *covers* the revoked one, most specific first.
		 * Non-empty means the identity keeps signing — under the surviving row's
		 * key grant, which may be wider than the one just revoked (`keyIds: null`
		 * is every key).
		 *
		 * The first entry is what resolution picks only for the part of the scope
		 * no `stillTrustedWithin` row claims: those are nested under the revoked
		 * prefix, hence longer than every row here, and longest live wins. A
		 * pinned `keyIds` at the head of this list is therefore not proof the
		 * scope was narrowed.
		 */
		stillCoveredBy: z
			.array(CoveringSubjectSchema)
			// Described rather than only commented: the ordering is incident
			// guidance, and TSDoc does not reach openapi.json or the generated
			// client, which is what somebody reads mid-incident.
			.describe(
				"Live rows whose prefix covers the revoked one, most specific first. The whole revoked " +
					"scope keeps signing, under key grants that may be wider than the revoked row's " +
					"(keyIds: null means every key). The first entry is what resolution picks only for the " +
					"part of the scope no stillTrustedWithin row claims — those are nested, hence longer " +
					"than every row here, and longest live wins.",
			),
		/**
		 * Live rows *nested under* the revoked prefix, outermost first: where one
		 * of these contains another, the container is listed above it. Rows in
		 * disjoint scopes are not ordered against each other, so read the whole
		 * list. Revoking a parent does not touch its children, so these keep
		 * signing. Only when both lists are empty was the revoke final.
		 */
		stillTrustedWithin: z
			.array(CoveringSubjectSchema)
			.describe(
				"Live rows nested under the revoked prefix, outermost first: where one contains another, " +
					"the container is listed above it. Rows in disjoint scopes are not ordered against each " +
					"other — a one-repo row can precede a team-wide one — so read the whole list. Only when " +
					"both lists are empty was the revoke final.",
			),
	})
	.openapi("SubjectRevokeResponse");
