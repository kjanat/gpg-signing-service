/**
 * Read the release workflow's privilege and tag-identity shape.
 *
 *   bun .github/scripts/release-workflow-shape.ts <workflow.yml> <job-id>
 *
 * Prints one JSON object on stdout, or a diagnostic on stderr and exit 1 when
 * the question cannot be answered. Called from
 * `.github/scripts/test-release-workflow.sh`.
 *
 * ## Why this is a second parser and not a grep
 *
 * `.github/scripts/workflow-steps.ts` answers the two questions that are the
 * same for every workflow — which script a `run:` step executes, and whether a
 * `uses:` is pinned — and is scoped to a workflow's STEPS by design. The
 * release contract needs three things that are not step-shaped and not general:
 *
 *   * the permission set the release job actually runs with, which is the job's
 *     own `permissions:` when it has one and the workflow's otherwise;
 *   * which jobs the workflow has at all — every other answer here is scoped to
 *     one job id, so a SECOND job is a second publisher, with its own
 *     `permissions:` and its own `tag_name:`, that the scoped reading is
 *     structurally unable to see;
 *   * `on:`, which is not a step and is not even spelled `on` after parsing —
 *     `on` is a YAML 1.1 boolean, so the key comes back as `true`;
 *   * the three places the requested tag is spent: the checkout `ref:`, the
 *     `RELEASE_TAG` the validation step is given, and the `tag_name:` the
 *     publisher publishes under;
 *   * which checkout is which. The release job has two, and they are not
 *     interchangeable: one replaces the workspace with the requested tag's tree
 *     and is identified by having no `path:`, the other lands the tag check
 *     under its own `path:` from `github.workflow_sha`. Reading `checkout[0]`
 *     would answer about whichever happened to be written first.
 *
 * The tag identity is the whole point. Nothing in the release job re-reads the
 * object after the checkout, so those three expressions being the same
 * requested tag is the property that makes `workflow_dispatch(tag: vX.Y.Z)`
 * safe. A job that validated one tag and published under another would be green
 * on every pin and wiring assertion this repository had before this file.
 *
 * None of it is answerable by a line scanner, for the reasons workflow-steps.ts
 * documents at length: a mapping key may be quoted, a comment may hold the
 * spelling being searched for, and an expression may be written across a folded
 * scalar. So this is a parse, from the `yaml` package this repository pins.
 *
 * ## Fail closed
 *
 * Every path that cannot answer exits non-zero: an unreadable file, a YAML
 * error, a missing `jobs:` mapping, a job that is not there, a `steps:` that is
 * not a sequence. Absent VALUES are reported as `null` rather than as an error,
 * because "the release job has no permissions: anywhere" is a real answer and
 * the caller has to be able to fail on it.
 */

import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";

/** The actions whose arguments carry the requested tag. */
const CHECKOUT = "actions/checkout";
const PUBLISHER = "softprops/action-gh-release";

function die(message: string): never {
	process.stderr.write(`release-workflow-shape.ts: ${message}\n`);
	process.exit(1);
}

interface Step {
	uses?: unknown;
	with?: unknown;
	env?: unknown;
	run?: unknown;
	if?: unknown;
	"continue-on-error"?: unknown;
}

/**
 * The properties that decide whether a step that is PRESENT actually runs, and
 * whether its failure stops the job.
 *
 * A step carrying `if: false` parses exactly like one that runs, and a step
 * carrying `continue-on-error: true` fails without failing the job. Both are
 * invisible to "is there a step that runs the tag check", which is why they are
 * reported rather than assumed: an advisory or skipped validation is a job that
 * publishes an unvalidated tag while every structural assertion stays green.
 */
function effective(step: Step): { guarded: boolean; advisory: unknown } {
	return {
		guarded: Object.hasOwn(step, "if"),
		advisory: step["continue-on-error"] ?? null,
	};
}

/** The `owner/repo` half of a `uses:`, or null when it is not a string. */
function actionName(uses: unknown): string | null {
	if (typeof uses !== "string") return null;
	const at = uses.lastIndexOf("@");
	return at > 0 ? uses.slice(0, at) : uses;
}

/**
 * One spelling for every expression that means the same thing.
 *
 * `${{ inputs.tag||github.ref_name }}` and `${{  inputs.tag || github.ref_name }}`
 * are one expression to the runner, so they have to be one string here — the
 * caller compares these for identity and a whitespace difference is not a
 * divergence in what gets published. Only whitespace is touched, and only
 * inside `${{ }}`: nothing else about the expression is interpreted, because
 * anything this file "understood" would be a place a real difference could hide.
 */
function canonical(value: unknown): string | null {
	if (typeof value !== "string") return null;
	return value
		.replace(
			/\$\{\{(.*?)\}\}/gs,
			(_match, body: string) => `\${{ ${body.replace(/\s+/g, "").replace(/\|\|/g, " || ")} }}`,
		)
		.trim();
}

/** A `with:` argument as a plain trimmed string, or null when it is not one. */
function scalar(value: unknown): string | null {
	return typeof value === "string" ? value.trim() : null;
}

function mappingOrNull(value: unknown): Record<string, unknown> | null {
	if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) return null;
	return value as Record<string, unknown>;
}

function main(argv: string[]): number {
	const [file, jobId] = argv;
	if (file === undefined || jobId === undefined) {
		process.stderr.write("usage: release-workflow-shape.ts <workflow.yml> <job-id>\n");
		return 2;
	}

	let source: string;
	try {
		source = readFileSync(file, "utf8");
	} catch (error) {
		die(`cannot read ${file}: ${error instanceof Error ? error.message : String(error)}`);
	}

	// Checked rather than trusting `toJS()` to throw: `yaml` recovers from many
	// syntax errors and hands back a partial document, which is the shape that
	// would let a malformed workflow answer "minimal permissions, coupled tag".
	const doc = parseDocument(source, { prettyErrors: false });
	if (doc.errors.length > 0) {
		die(`${file} is not parseable YAML: ${doc.errors.map((error) => error.message).join("; ")}`);
	}

	const root = mappingOrNull(doc.toJS({ maxAliasCount: 100 }));
	if (root === null) die(`${file} is not a workflow: its top level is not a mapping`);

	const jobs = mappingOrNull(root.jobs);
	if (jobs === null) die(`${file} has no jobs: mapping`);

	const job = mappingOrNull(jobs[jobId]);
	if (job === null) {
		die(`${file} has no job named ${jobId} (jobs: ${Object.keys(jobs).join(", ") || "none"})`);
	}

	// A job's own `permissions:` replaces the workflow's outright — it does not
	// merge with it — so the effective set is one or the other, and which one it
	// came from is worth reporting in a failure.
	const hasJobPermissions = Object.hasOwn(job, "permissions");
	const permissions = hasJobPermissions ? job.permissions : root.permissions;
	const permissionsSource = hasJobPermissions ? "job" : Object.hasOwn(root, "permissions") ? "workflow" : "none";

	const steps: unknown = job.steps;
	if (steps !== undefined && !Array.isArray(steps)) die(`${file}: job ${jobId} has a steps: that is not a sequence`);

	const checkout: {
		index: number;
		ref: string | null;
		path: string | null;
		persistCredentials: unknown;
	}[] = [];
	const validator: {
		index: number;
		releaseTag: string | null;
		run: string | null;
		guarded: boolean;
		advisory: unknown;
	}[] = [];
	const publisher: { index: number; uses: string; tagName: string | null }[] = [];

	for (const [index, raw] of (Array.isArray(steps) ? steps : []).entries()) {
		const step = mappingOrNull(raw) as Step | null;
		if (step === null) die(`${file}: job ${jobId} step ${index + 1} is not a mapping`);

		const name = actionName(step.uses);
		const withArgs = mappingOrNull(step.with);
		const env = mappingOrNull(step.env);

		if (name === CHECKOUT) {
			checkout.push({
				index: index + 1,
				ref: canonical(withArgs?.ref),
				path: scalar(withArgs?.path),
				persistCredentials: withArgs?.["persist-credentials"] ?? null,
			});
		}
		if (name === PUBLISHER) {
			publisher.push({ index: index + 1, uses: step.uses as string, tagName: canonical(withArgs?.tag_name) });
		}
		// The validation step is found by the variable it is given rather than by
		// its name or its `run:`, so the same reading answers for the inline check
		// this branch replaces and for the extracted script that replaces it.
		if (env !== null && Object.hasOwn(env, "RELEASE_TAG")) {
			validator.push({
				index: index + 1,
				releaseTag: canonical(env.RELEASE_TAG),
				run: typeof step.run === "string" ? step.run.trim() : null,
				...effective(step),
			});
		}
	}

	const rooted = checkout.filter((step) => step.path === null);
	const pathed = checkout.filter((step) => step.path !== null);

	// `on` is a YAML 1.1 boolean: a document that spells the key `on:` parses to
	// the key `true`. A scanner looking for the literal string would be answering
	// a different question than the runner does.
	const on = mappingOrNull(root.on ?? root[true as unknown as string]);
	const push = mappingOrNull(on?.push);
	const dispatch = mappingOrNull(on?.workflow_dispatch);
	const dispatchTag = mappingOrNull(mappingOrNull(dispatch?.inputs)?.tag);

	process.stdout.write(
		`${JSON.stringify({
			jobs: Object.keys(jobs),
			permissions: permissions ?? null,
			permissionsSource,
			checkout: {
				count: checkout.length,
				// Which checkout is the release workspace is decided by the absence
				// of a `path:`, not by position: a `path:`-less checkout is the one
				// that replaces $GITHUB_WORKSPACE, and $GITHUB_WORKSPACE is where a
				// `run:` step executes. Two of either kind leaves the question
				// unanswerable, so it is reported as unanswered rather than guessed.
				release: rooted.length === 1 ? rooted[0] : null,
				tooling: pathed.length === 1 ? pathed[0] : null,
				// Every checkout, not the first: the credential the second one
				// leaves behind is inherited by exactly the same later steps.
				persisting: checkout.filter((step) => step.persistCredentials !== false).map((step) => step.index),
			},
			validator: {
				count: validator.length,
				releaseTag: validator[0]?.releaseTag ?? null,
				run: validator[0]?.run ?? null,
				guarded: validator[0]?.guarded ?? null,
				advisory: validator[0]?.advisory ?? null,
				index: validator[0]?.index ?? null,
			},
			publisher: {
				count: publisher.length,
				uses: publisher[0]?.uses ?? null,
				tagName: publisher[0]?.tagName ?? null,
				index: publisher[0]?.index ?? null,
			},
			push: push?.tags ?? null,
			dispatchTagRequired: dispatchTag === null ? null : (dispatchTag.required ?? false),
		})}\n`,
	);
	return 0;
}

process.exit(main(process.argv.slice(2)));
