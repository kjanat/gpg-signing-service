import { describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import { openApiConfig } from "#lib/openapi";
import { SUBJECT_PREFIX_PATTERN } from "#schemas";
import committedSpec from "../../client/openapi.json";

/**
 * `client/openapi.json` and the Go client generated from it are build outputs
 * that live in the tree, and nothing regenerates them on the way into CI. Until
 * this test, the only thing standing between a schema edit and a spec that
 * documents a rule the service no longer enforces was remembering to run
 * `task generate:api` — and the failure is silent in both directions, because
 * the committed spec parses fine and the generated client compiles fine.
 *
 * Comparison is on the parsed documents rather than the bytes: whitespace in
 * the committed file is not a contract, and a byte check would fail for
 * anybody's editor rather than for drift.
 */
describe("published OpenAPI spec", () => {
	it("matches the document the app generates", () => {
		// `JSON.parse(JSON.stringify(...))` and not the document itself: the
		// generated object carries `undefined` properties that survive `toEqual`
		// as present-but-undefined and vanish on the way through JSON, which is
		// the form the committed file was written from.
		const generated = JSON.parse(JSON.stringify(app.getOpenAPIDocument(openApiConfig)));
		expect(generated, "client/openapi.json is stale — run `task generate:api` and commit the result").toEqual(
			committedSpec,
		);
	});

	// The request and response views of a subject prefix have to differ, and the
	// difference is only visible in the published document: nothing validates a
	// response at runtime, so a mistake here is invisible until a third-party
	// client refuses a listing.
	describe("subject prefix components", () => {
		const schemas = (committedSpec as { components: { schemas: Record<string, Record<string, unknown>> } }).components
			.schemas;
		// A missing component would otherwise read as "no pattern published",
		// which is what half of these assert.
		const component = (name: string) => {
			const schema = schemas[name];
			expect(schema, `${name} is missing from the published spec`).toBeDefined();
			return schema as Record<string, unknown>;
		};

		it("constrains what may be created", () => {
			expect(component("SubjectPrefix").pattern).toBe(SUBJECT_PREFIX_PATTERN);
			expect(component("SubjectCreate").properties).toMatchObject({
				subjectPrefix: { $ref: "#/components/schemas/SubjectPrefix" },
			});
		});

		it("does not constrain what may be read back", () => {
			// A pattern on the stored view would re-impose the create rule on the
			// read path, and rows predating the rule are exactly the ones somebody
			// is listing in order to revoke.
			expect(component("StoredSubjectPrefix")).not.toHaveProperty("pattern");
			expect(component("StoredSubjectPrefix")).toMatchObject({ type: "string", minLength: 1, maxLength: 255 });
			for (const name of ["SubjectSummary", "SubjectCreatedResponse", "CoveringSubject"]) {
				expect([name, component(name).properties]).toEqual([
					name,
					expect.objectContaining({ subjectPrefix: { $ref: "#/components/schemas/StoredSubjectPrefix" } }),
				]);
			}
		});
	});
});
