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
 *   * WHERE the job runs. `runs-on:`, `container:`, `services:` and `defaults:`
 *     are not steps, are not arguments, and decide the machine, the image and
 *     the shell every `run:` in the job executes under. `container: { image:
 *     ... }` is one added line that leaves every pin, permission, argument and
 *     expression exactly as reviewed while `sha256sum`, `chmod` and the whole
 *     build run inside an image nobody here controls;
 *   * `on:`, which is not a step and is not even spelled `on` after parsing —
 *     `on` is a YAML 1.1 boolean, so the key comes back as `true`;
 *   * the three places the requested tag is spent: the checkout `ref:`, the
 *     `RELEASE_TAG` the validation step is given, and the `tag_name:` the
 *     publisher publishes under;
 *   * what the BUILD step stamps into the binaries. `--version` on a published
 *     artifact is a claim about which source the binary came from, and the
 *     whole claim is one `-ldflags` string in one `run:`. `-X` naming a symbol
 *     no package declares is not a link error -- the linker drops it in
 *     silence -- so an injection that stops arriving looks exactly like one
 *     that arrives. Reported as the symbols the step sets and the expression
 *     each is set from, so the caller can pin the set AND pin that the version
 *     is the tag that was validated rather than a literal somebody typed.
 *   * which checkout is which. The release job has two, and they are not
 *     interchangeable: one replaces the workspace with the requested tag's tree
 *     and is identified by having no `path:`, the other lands the tag check
 *     under its own `path:` from `github.workflow_sha`. Reading `checkout[0]`
 *     would answer about whichever happened to be written first.
 *   * the WHOLE `with:` mapping of each checkout AND of the publisher, not the
 *     arguments the contract happens to name. `repository:` defaults to
 *     `github.repository` and `submodules:` defaults to false, and either one
 *     added redirects what lands in the workspace while `ref:`, `path:` and
 *     `persist-credentials:` all stay exactly as reviewed. The publisher is the
 *     same argument one step later: `files:` IS the asset set, `action.yml`
 *     installs an asset by name and verifies it against a `checksums.txt` taken
 *     from that same list, and `draft:` decides whether any of it is published
 *     at all -- none of which is visible in `tag_name:`.
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

/**
 * The compile step is found by what it does, because it has no `uses:` to be
 * found by and its `name:` is prose. `go build` in a `run:` is the step that
 * produces the artifacts, and it is also why this step has to be told apart
 * from the tag check at all: both are handed the requested tag through `env:`,
 * so a reading that identified the validator by that variable alone would see
 * two validators the moment the build began stamping the tag it publishes.
 */
const COMPILER = /(^|[\s;&|])go\s+build(\s|$)/;

/**
 * `-X main.<symbol>=<value>` as the linker reads it. The value stops at a quote
 * as well as at whitespace: the flag is written inside a double-quoted shell
 * assignment, so a run to end-of-word would report the closing quote as part of
 * the expression and no caller could pin the value it is comparing against.
 */
const LDFLAG = /-X\s+main\.([A-Za-z_][A-Za-z0-9_]*)=([^\s"']*)/g;

/**
 * `-ldflags <argument>`, quoted or bare, as it appears on the compile command.
 */
const LDFLAGS_ARGUMENT = /-ldflags[\s=]+(?:"([^"]*)"|'([^']*)'|(\S+))/;

/**
 * An `-ldflags` argument that is nothing but one shell parameter -- the shape
 * `-ldflags "${LDFLAGS}"` -- and the assignment that would give it a value.
 * Resolved because the flags the linker receives are what the artifact's
 * `--version` is a function of, and a run that composes them into a variable it
 * then never passes has stopped injecting anything while still spelling the
 * whole injection out for a reader.
 */
const LDFLAGS_INDIRECTION = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/;

/**
 * The `go build` invocations in one `run:`, with line continuations folded so a
 * command written across several lines is read as the one command it is.
 *
 * Reading the command rather than the whole script is the point: `-trimpath`
 * and every `-X` are only in effect if they are on the invocation. A `run:`
 * that still mentions them somewhere -- in a comment, or in a variable nothing
 * passes -- looks identical to one that uses them, and produces binaries that
 * report the compiled-in defaults.
 */
function compileCommands(run: string): string[] {
	return run
		.replace(/\\\r?\n\s*/g, " ")
		.split("\n")
		.filter((line) => COMPILER.test(line));
}

/**
 * The linker flags one compile command actually passes, with a single level of
 * `VAR="..."` indirection resolved against the run that contains it. An empty
 * string means the command passes no `-ldflags` at all, which is the original
 * bug: the binaries are published reporting whatever `version.go` compiled in.
 */
function linkerFlags(run: string, command: string): string {
	const match = LDFLAGS_ARGUMENT.exec(command);
	if (match === null) {
		return "";
	}

	const argument = match[1] ?? match[2] ?? match[3] ?? "";
	const indirect = LDFLAGS_INDIRECTION.exec(argument);
	if (indirect === null) {
		return argument;
	}

	const folded = run.replace(/\\\r?\n\s*/g, " ");
	const assignment = new RegExp(`(?:^|[\\s;&|])${indirect[1]}=(?:"([^"]*)"|'([^']*)'|(\\S*))`, "m").exec(folded);
	if (assignment === null) {
		return "";
	}
	return assignment[1] ?? assignment[2] ?? assignment[3] ?? "";
}

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

/**
 * EVERY `with:` argument of a step, not the three a caller reads by name.
 *
 * `actions/checkout` takes `repository:` (default `github.repository`) and
 * `submodules:` alongside `ref:` and `path:`, and either one redirects what
 * lands in the workspace without touching a key anything else here reports. A
 * contract that names the arguments it objects to can only refuse the ones
 * somebody thought of; a contract that reports the whole mapping lets the
 * caller pin the argument set and refuse an addition it has not reviewed.
 *
 * String values go through `canonical()` for the same reason `ref:` does — a
 * respacing inside `${{ }}` is not a change in what runs — and nothing else is
 * interpreted.
 */
function withArguments(args: Record<string, unknown> | null): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(args ?? {})) {
		out[key] = typeof value === "string" ? canonical(value) : value;
	}
	return out;
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
		with: Record<string, unknown>;
	}[] = [];
	const validator: {
		index: number;
		releaseTag: string | null;
		run: string | null;
		guarded: boolean;
		advisory: unknown;
	}[] = [];
	const publisher: {
		index: number;
		uses: string;
		tagName: string | null;
		with: Record<string, unknown>;
	}[] = [];
	const build: {
		index: number;
		releaseTag: string | null;
		env: Record<string, unknown>;
		symbols: Record<string, string>;
		trimpath: boolean;
		guarded: boolean;
		advisory: unknown;
	}[] = [];

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
				with: withArguments(withArgs),
			});
		}
		if (name === PUBLISHER) {
			publisher.push({
				index: index + 1,
				uses: step.uses as string,
				tagName: canonical(withArgs?.tag_name),
				with: withArguments(withArgs),
			});
		}
		const run = typeof step.run === "string" ? step.run : null;
		const compiles = run !== null && COMPILER.test(run);

		// One entry per `go build`, not per step: two invocations in one `run:`
		// produce two accounts of where the artifacts came from just as surely as
		// two steps do, and only the first would ever be pinned.
		for (const command of compiles && run !== null ? compileCommands(run) : []) {
			const symbols: Record<string, string> = {};
			for (const [, symbol, value] of linkerFlags(run, command).matchAll(LDFLAG)) {
				symbols[symbol] = value;
			}
			build.push({
				index: index + 1,
				releaseTag: canonical(env?.RELEASE_TAG),
				env: withArguments(env),
				symbols,
				trimpath: /(^|\s)-trimpath(\s|$)/.test(command),
				...effective(step),
			});
		}

		// The validation step is found by the variable it is given rather than by
		// its name or its `run:`, so the same reading answers for the inline check
		// this branch replaces and for the extracted script that replaces it. The
		// compile step is excluded because it is handed the same variable for a
		// different purpose -- stamping the tag into the binary rather than
		// deciding whether the tag may be published -- and counting it as a second
		// validator would make the identity assertions unanswerable.
		if (env !== null && Object.hasOwn(env, "RELEASE_TAG") && !compiles) {
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
			// The execution environment, reported whole for the reason the `with:`
			// mappings are: a contract that names what it objects to can only refuse
			// what somebody thought of. `defaults:` is reported from BOTH levels
			// because a job's merges with the workflow's rather than replacing it.
			environment: {
				runsOn: job["runs-on"] ?? null,
				container: job.container ?? null,
				services: job.services ?? null,
				defaults: { job: job.defaults ?? null, workflow: root.defaults ?? null },
			},
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
			// The compile step, reported whole for the reason the `with:` mappings
			// are. `symbols` is the artifact's own account of where it came from:
			// an entry that disappears downgrades `--version` to a default in
			// silence, and an entry that appears is a claim nobody reviewed.
			build: {
				count: build.length,
				index: build[0]?.index ?? null,
				releaseTag: build[0]?.releaseTag ?? null,
				env: build[0]?.env ?? null,
				symbols: build[0]?.symbols ?? null,
				trimpath: build[0]?.trimpath ?? null,
				guarded: build[0]?.guarded ?? null,
				advisory: build[0]?.advisory ?? null,
			},
			publisher: {
				count: publisher.length,
				uses: publisher[0]?.uses ?? null,
				tagName: publisher[0]?.tagName ?? null,
				index: publisher[0]?.index ?? null,
				// The whole mapping, for the reason the checkouts' is reported:
				// `tag_name:` says what the release is CALLED, `files:` says what
				// is in it, and `draft:` says whether it is published at all.
				with: publisher[0]?.with ?? null,
			},
			push: push?.tags ?? null,
			dispatchTagRequired: dispatchTag === null ? null : (dispatchTag.required ?? false),
		})}\n`,
	);
	return 0;
}

process.exit(main(process.argv.slice(2)));
