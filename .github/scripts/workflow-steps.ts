/**
 * Read a workflow's steps for the two properties its tests assert about them:
 * which script a `run:` step actually executes, and whether a `uses:` step is
 * pinned to something immutable.
 *
 *   bun .github/scripts/workflow-steps.ts runs-script   <file> <script>...
 *   bun .github/scripts/workflow-steps.ts mutable-uses  <file> [--job <id>] [--expect-uses]
 *   bun .github/scripts/workflow-steps.ts job-field     <file> <job> <field>
 *
 * Called through `.github/scripts/workflow-steps.sh`, which is what the shell
 * suites source. Nothing here is a regex over YAML source text, and that is the
 * point of the file existing.
 *
 * ## Why a parser and not a grep
 *
 * The first version of this was awk over `run:` lines and `grep -oE` over
 * `uses:` lines. Both were correct for the spellings this repository happened
 * to have written, and both had a bypass that a valid GitHub Actions workflow
 * reaches:
 *
 *   * A folded block scalar joins its lines. In
 *
 *       run: >
 *         echo hello
 *         .github/scripts/sign-commits.sh
 *
 *     the runner receives ONE command, `echo hello .github/scripts/sign-commits.sh`,
 *     which prints the path rather than running it. Reading the block's lines
 *     one at a time reports the second line as an executed command, so a
 *     workflow that had stopped calling the script satisfied the assertion whose
 *     whole job is to fail exactly then.
 *
 *   * `uses` is a mapping key, and a mapping key may be quoted. `"uses":
 *     actions/checkout@v7` is the same step to GitHub as `uses:
 *     actions/checkout@v7`, and an anchored `uses:` pattern does not see it —
 *     so the SHA-pin guard reported clean while a mutable external action ran
 *     first in a job holding `contents: write` and an OIDC token that mints
 *     real signatures.
 *
 * Neither is a special case to be patched. They are the same defect: a line
 * scanner deciding a question that only a parse can answer. So the answer is a
 * parse, from `yaml` — the version this repository already pins in
 * package.json, and the one `scripts/lint-composite-actions.ts` uses for the
 * same reason.
 *
 * ## Fail closed
 *
 * Every path that cannot answer the question exits non-zero with a diagnostic
 * rather than printing nothing: an unreadable file, a YAML error, a `jobs:`
 * that is not a mapping, a requested job that is not there, a `run:` or `uses:`
 * that is not a string. "No output" is a meaningful answer for both queries —
 * `mutable-uses` prints nothing when every action is pinned — so a parser that
 * degraded to silence would report the safest possible result for the least
 * intelligible input.
 */

import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";

/** Interpreters that run the script named as their first argument. */
const INTERPRETERS = new Set(["bash", "sh", "python", "python3"]);

/** A full-length git object name. Anything shorter is not a pin. */
const COMMIT_SHA = /^[0-9a-f]{40}$/;

/** `NAME=value` prefixes a command rather than being one. */
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

interface Step {
	run?: unknown;
	uses?: unknown;
}

interface Job {
	steps?: unknown;
	uses?: unknown;
	[key: string]: unknown;
}

class Unparseable extends Error {}

function fail(message: string): never {
	throw new Unparseable(message);
}

/**
 * The workflow's jobs, parsed.
 *
 * `doc.errors` is checked rather than trusting `toJS()` to throw: the `yaml`
 * package recovers from many syntax errors and hands back a partial document,
 * which is precisely the shape that would let a malformed workflow answer
 * "nothing unpinned here".
 */
function readJobs(file: string): Record<string, Job> {
	let source: string;
	try {
		source = readFileSync(file, "utf8");
	} catch (error) {
		fail(`cannot read ${file}: ${error instanceof Error ? error.message : String(error)}`);
	}

	const doc = parseDocument(source, { prettyErrors: false });
	if (doc.errors.length > 0) {
		fail(`${file} is not parseable YAML: ${doc.errors.map((e) => e.message).join("; ")}`);
	}

	const root: unknown = doc.toJS({ maxAliasCount: 100 });
	if (root === null || typeof root !== "object" || Array.isArray(root)) {
		fail(`${file} is not a workflow: its top level is not a mapping`);
	}

	const jobs: unknown = (root as Record<string, unknown>).jobs;
	if (jobs === null || jobs === undefined || typeof jobs !== "object" || Array.isArray(jobs)) {
		fail(`${file} has no jobs: mapping`);
	}

	return jobs as Record<string, Job>;
}

/** The jobs a query covers: one named job, or all of them. */
function selectJobs(file: string, jobs: Record<string, Job>, jobId: string | null): [string, Job][] {
	if (jobId === null) return Object.entries(jobs);

	const job = jobs[jobId];
	if (job === undefined) {
		fail(`${file} has no job named ${jobId} (jobs: ${Object.keys(jobs).join(", ") || "none"})`);
	}
	return [[jobId, job]];
}

function stepsOf(file: string, jobId: string, job: Job): Step[] {
	if (job === null || typeof job !== "object") fail(`${file}: job ${jobId} is not a mapping`);

	const steps: unknown = job.steps;
	if (steps === undefined) return [];
	if (!Array.isArray(steps)) fail(`${file}: job ${jobId} has a steps: that is not a sequence`);

	return steps.map((step, index) => {
		if (step === null || typeof step !== "object" || Array.isArray(step)) {
			fail(`${file}: job ${jobId} step ${index + 1} is not a mapping`);
		}
		return step as Step;
	});
}

/**
 * The shell commands one `run:` scalar executes, one per element.
 *
 * The parser has already applied the block style, which is the whole reason
 * this is a parse: a literal block (`|`) keeps its newlines and is several
 * commands, a folded block (`>`) joins its lines into one, and an inline scalar
 * is one. Splitting the RESULT on newlines therefore matches what the runner's
 * shell sees, for every style, including the indentation and chomping
 * indicators (`>-`, `|2+`) that change where those newlines land.
 */
function commandsOf(script: string): string[] {
	return script.split("\n");
}

/**
 * Does one shell command line run this script?
 *
 * The command word decides: the path itself runs it, so does an interpreter
 * given it as a first argument, and so does either behind `NAME=value`
 * assignments. Everything else that names it — `echo <path>`, `cat <path>`, a
 * `#` comment, a folded continuation that made it an argument — does not.
 *
 * Deliberately narrow. Splitting on whitespace is not shell word splitting, so
 * a quoted or substituted spelling reads as "not wired" — which fails the
 * suite rather than passing it, and that is the direction an error here has to
 * go.
 */
function commandExecutes(command: string, script: string): boolean {
	const words = command
		.trim()
		.split(/\s+/)
		.filter((word) => word.length > 0);

	let index = 0;
	while (index < words.length && ENV_ASSIGNMENT.test(words[index] as string)) index += 1;

	let word = words[index];
	if (word === undefined || word.startsWith("#")) return false;
	if (INTERPRETERS.has(word)) word = words[index + 1];
	if (word === undefined) return false;

	return word.replace(/^\.\//, "") === script.replace(/^\.\//, "");
}

/** The first of `scripts` that some step in `file` — or in one job — executes, or "". */
function runsScript(file: string, only: string | null, scripts: string[]): string {
	const jobs = readJobs(file);

	for (const [jobId, job] of selectJobs(file, jobs, only)) {
		for (const step of stepsOf(file, jobId, job)) {
			if (step.run === undefined) continue;
			if (typeof step.run !== "string") fail(`${file}: job ${jobId} has a run: that is not a string`);

			for (const command of commandsOf(step.run)) {
				for (const script of scripts) {
					if (commandExecutes(command, script)) return script;
				}
			}
		}
	}

	return "";
}

/**
 * Every `uses:` naming something outside this checkout without pinning it to a
 * commit. Empty means every external action is pinned.
 *
 * A tag is a mutable pointer in a repository nobody here controls, and these
 * workflows hand the steps that run first `contents: write` and an OIDC token
 * that mints real signatures. `# v7.0.1` after the SHA is what makes it
 * readable and what Dependabot bumps; the SHA is what runs.
 *
 * `./` and `./.github/actions/...` are this checkout: whatever the workflow was
 * checked out at is what runs, so there is nothing to pin them to.
 */
function mutableUses(file: string, jobId: string | null, expectUses: boolean): string[] {
	const jobs = readJobs(file);
	const mutable: string[] = [];
	let seen = 0;

	const consider = (where: string, value: unknown): void => {
		if (value === undefined) return;
		if (typeof value !== "string") fail(`${file}: ${where} has a uses: that is not a string`);

		seen += 1;
		if (value.startsWith("./")) return;

		const at = value.lastIndexOf("@");
		if (at > 0 && COMMIT_SHA.test(value.slice(at + 1))) return;
		mutable.push(value);
	};

	for (const [id, job] of selectJobs(file, jobs, jobId)) {
		// A job may call a reusable workflow instead of running steps, and that
		// reference is resolved the same way a step's is.
		consider(`job ${id}`, job.uses);
		stepsOf(file, id, job).forEach((step, index) => {
			consider(`job ${id} step ${index + 1}`, step.uses);
		});
	}

	// The guard against a query that passes because it looked at nothing: an
	// assertion over a scope with no actions in it is green for the wrong
	// reason, and this is called on a job block that is expected to have some.
	if (expectUses && seen === 0) {
		fail(`${file} has no uses: in ${jobId === null ? "any job" : `job ${jobId}`}`);
	}

	return mutable;
}

/** One scalar field of one job — `if:`, say — as written after parsing. */
function jobField(file: string, jobId: string, field: string): string {
	const jobs = readJobs(file);
	const [[, job]] = selectJobs(file, jobs, jobId) as [[string, Job]];

	const value: unknown = job[field];
	if (value === undefined) fail(`${file}: job ${jobId} has no ${field}:`);
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "boolean") return String(value);

	return fail(`${file}: job ${jobId} has a ${field}: that is not a scalar`);
}

function main(argv: string[]): number {
	const [command, file, ...rest] = argv;
	if (command === undefined || file === undefined) {
		process.stderr.write("usage: workflow-steps.ts <runs-script|mutable-uses|job-field> <file> ...\n");
		return 2;
	}

	try {
		switch (command) {
			case "runs-script": {
				let jobId: string | null = null;
				const scripts: string[] = [];
				for (let index = 0; index < rest.length; index += 1) {
					if (rest[index] === "--job") {
						jobId = rest[index + 1] ?? fail("--job needs a job id");
						index += 1;
					} else {
						scripts.push(rest[index] as string);
					}
				}
				if (scripts.length === 0) fail("runs-script needs at least one script path");
				const found = runsScript(file, jobId, scripts);
				if (found !== "") process.stdout.write(`${found}\n`);
				return 0;
			}
			case "mutable-uses": {
				let jobId: string | null = null;
				let expectUses = false;
				for (let index = 0; index < rest.length; index += 1) {
					if (rest[index] === "--job") {
						jobId = rest[index + 1] ?? fail("--job needs a job id");
						index += 1;
					} else if (rest[index] === "--expect-uses") {
						expectUses = true;
					} else {
						fail(`unknown option ${rest[index]}`);
					}
				}
				for (const reference of mutableUses(file, jobId, expectUses)) {
					process.stdout.write(`${reference}\n`);
				}
				return 0;
			}
			case "job-field": {
				const [jobId, field] = rest;
				if (jobId === undefined || field === undefined) fail("job-field needs a job id and a field");
				process.stdout.write(`${jobField(file, jobId, field)}\n`);
				return 0;
			}
			default:
				process.stderr.write(`workflow-steps.ts: unknown command ${command}\n`);
				return 2;
		}
	} catch (error) {
		if (error instanceof Unparseable) {
			process.stderr.write(`workflow-steps.ts: ${error.message}\n`);
			return 1;
		}
		throw error;
	}
}

process.exit(main(process.argv.slice(2)));
