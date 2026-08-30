#!/usr/bin/env bun
/**
 * Lints the shell embedded in composite GitHub Actions (`runs.steps[*].run`).
 *
 * Nothing else in this repo reads that shell. `task lint:actions` feeds
 * actionlint only `.github/workflows/**`, and actionlint has no composite-action
 * schema -- pointed at an `action.yml` it stops at `"jobs" section is missing in
 * workflow` and therefore never reaches its own ShellCheck integration.
 * `task lint:shell` globs `*.sh`, which an `action.yml` is not. So every
 * `run:` block under `.github/actions/` was unchecked, which is how both #124
 * bugs shipped.
 *
 * ShellCheck alone would not have caught either of them, which is why this is a
 * checker and not a two-line glob change:
 *
 *   * The runner executes `shell: bash` as `bash --noprofile --norc -e -o
 *     pipefail {0}`. Under `-e`, `VAR="$(cmd)"` inherits `cmd`'s status and
 *     aborts the step, so the `EXIT_CODE=$?` on the next statement is
 *     unreachable -- the job fails while reporting nothing. ShellCheck models
 *     errexit only loosely and stays silent on this shape even at
 *     `-o all --enable=all`; it reports SC2250 about brace style and nothing
 *     else. CA001 below is the rule that sees it.
 *   * `::notice:msg` is not a workflow command -- GitHub wants `::notice::msg`
 *     or `::notice title=x::msg` -- so it prints as literal text and the
 *     annotation silently never appears. No shell linter has an opinion about
 *     that string at all. CA002 is the rule that does.
 *
 * Checks, all deterministic and all reported as `file:line:col: [CODE] msg`:
 *
 *   CA001  `$?` read that errexit makes unreachable
 *   CA002  malformed or unknown `::workflow-command::`
 *   CA003  composite `run:` step with no `shell:` (the runner rejects it)
 *   SC####  ShellCheck, on bash/sh blocks, with runner flags prepended
 *
 * Positions come from the `yaml` package's node ranges, so a finding points at
 * the real line of the real `action.yml`, not at some extracted temporary.
 *
 * Usage:
 *   bun scripts/lint-composite-actions.ts [--list] [paths...]
 *
 * With no paths it walks the whole repository for `action.{yml,yaml}`, skipping
 * only trees that hold no source this repo owns (`.git`, `node_modules`, build
 * and coverage output). A composite action is a composite action wherever it
 * lives, and scoping discovery to `.github/actions/` meant one `git mv` could
 * take a file out of the gate silently. `--list` prints the blocks it found and
 * exits 0; that is the coverage assertion's hook, so a block dropping out of
 * scope is itself detectable.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { isMap, isSeq, LineCounter, parseDocument } from "yaml";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Finding {
	file: string;
	line: number;
	col: number;
	code: string;
	message: string;
}

interface RunBlock {
	/** Repo-relative path of the action file. */
	file: string;
	/** 1-based step index within `runs.steps`, for messages. */
	stepIndex: number;
	/** `name:` or `id:` of the step, when it has one. */
	stepName: string;
	/** Declared `shell:`, or `null` when the step omits it. */
	shell: string | null;
	/** The script itself. */
	script: string;
	/** 1-based source line of the script's first line. */
	startLine: number;
	/** 0-based column the script's lines are indented to in the source. */
	indent: number;
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

const ACTION_FILENAMES = new Set(["action.yml", "action.yaml"]);

/**
 * Directory names never descended into.
 *
 * This is a deny list rather than an allow list on purpose. An allow list is
 * what the first version of this gate had -- root plus `.github/actions/` --
 * and it made "is this file linted?" depend on where someone happened to put
 * it. A deny list can only ever fail by linting something extra, which is a
 * visible failure; an allow list fails by linting nothing, which is silent.
 *
 * Everything here is a tree this repo does not author: dependency and VCS
 * metadata, and generated output. `action.yml` files under `node_modules/`
 * belong to third-party actions and are their authors' to fix.
 */
const SKIP_DIRS = new Set([
	".git",
	".direnv",
	".venv",
	"node_modules",
	"vendor",
	"dist",
	"build",
	"out",
	"coverage",
	".wrangler",
	".turbo",
	".next",
	".cache",
]);

function discoverActionFiles(root: string): string[] {
	const found: string[] = [];
	walk(root, found);
	return found.sort();
}

function walk(dir: string, out: string[]): void {
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		// An unreadable directory is not a reason to fail the whole lint run;
		// the coverage assertion in test-composite-action-lint.sh is what
		// notices if something that should be linted stops being reachable.
		return;
	}

	for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) walk(full, out);
		} else if (ACTION_FILENAMES.has(entry.name) && !entry.isSymbolicLink()) {
			out.push(full);
		}
	}
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/**
 * Pulls every `runs.steps[*].run` out of one composite action.
 *
 * Deliberately a real YAML parse rather than a regex sweep: `setup-bun`'s steps
 * are a flow sequence of flow mappings on single lines, so anything keyed off
 * `^\s*run:` at line starts would miss its `bun install` outright.
 */
function extractRunBlocks(relPath: string, source: string): { blocks: RunBlock[]; errors: Finding[] } {
	const blocks: RunBlock[] = [];
	const errors: Finding[] = [];
	const lineCounter = new LineCounter();

	let doc: ReturnType<typeof parseDocument>;
	try {
		doc = parseDocument(source, { lineCounter });
	} catch (error) {
		errors.push({
			file: relPath,
			line: 1,
			col: 1,
			code: "CA000",
			message: `unparseable YAML: ${error instanceof Error ? error.message : String(error)}`,
		});
		return { blocks, errors };
	}

	for (const problem of doc.errors) {
		const pos = lineCounter.linePos(problem.pos[0]);
		errors.push({ file: relPath, line: pos.line, col: pos.col, code: "CA000", message: problem.message });
	}
	if (errors.length > 0) return { blocks, errors };

	const using = doc.getIn(["runs", "using"]);
	if (typeof using !== "string" || using.toLowerCase() !== "composite") return { blocks, errors };

	const steps = doc.getIn(["runs", "steps"], true);
	if (!isSeq(steps)) return { blocks, errors };

	let stepIndex = 0;
	for (const step of steps.items) {
		stepIndex += 1;
		if (!isMap(step)) continue;

		const runNode = step.get("run", true);
		if (runNode === undefined || runNode === null) continue;
		const script = (runNode as { value?: unknown }).value;
		if (typeof script !== "string") continue;

		const range = (runNode as { range?: [number, number, number] }).range;
		if (!range) continue;

		const { startLine, indent } = locateScriptStart(source, range[0], lineCounter);

		const shellValue = step.get("shell");
		const shell = typeof shellValue === "string" ? shellValue : null;

		const nameValue = step.get("name") ?? step.get("id");
		const stepName = typeof nameValue === "string" ? nameValue : `step ${stepIndex}`;

		if (shell === null) {
			errors.push({
				file: relPath,
				line: startLine,
				col: indent + 1,
				code: "CA003",
				message:
					`composite \`run:\` step "${stepName}" has no \`shell:\`; the runner rejects the action with ` +
					`"Required property is missing: shell"`,
			});
		}

		blocks.push({ file: relPath, stepIndex, stepName, shell, script, startLine, indent });
	}

	return { blocks, errors };
}

/**
 * Maps a `run:` scalar node's start offset to where its *content* starts.
 *
 * For a literal block scalar (`|`, `|-`, `>`, ...) the node begins at the
 * indicator and the script starts on the following line; for a plain or quoted
 * scalar the node start is the content start. Getting this right is what keeps
 * a reported line number clickable.
 */
function locateScriptStart(
	source: string,
	nodeStart: number,
	lineCounter: LineCounter,
): { startLine: number; indent: number } {
	const head = source[nodeStart];
	if (head !== "|" && head !== ">") {
		const pos = lineCounter.linePos(nodeStart);
		return { startLine: pos.line, indent: pos.col - 1 };
	}

	const newline = source.indexOf("\n", nodeStart);
	if (newline === -1) {
		const pos = lineCounter.linePos(nodeStart);
		return { startLine: pos.line, indent: pos.col - 1 };
	}

	const contentStart = newline + 1;
	const rest = source.slice(contentStart);
	const indentMatch = /^[ \t]*/.exec(rest.split("\n", 1)[0] ?? "");
	const pos = lineCounter.linePos(contentStart);
	return { startLine: pos.line, indent: indentMatch ? indentMatch[0].length : 0 };
}

// ---------------------------------------------------------------------------
// Shell tokenizing
// ---------------------------------------------------------------------------

/**
 * A run of script text delimited by the control operator in front of it.
 *
 * `op` is what *preceded* this segment, which is the whole point: `EXIT_CODE=$?`
 * after `||` reads a status the shell was allowed to survive, and the same text
 * after `;` reads one errexit already exited on.
 */
interface Segment {
	text: string;
	/** Offset of `text[0]` in the original script. */
	start: number;
	op: "" | ";" | "\n" | "&&" | "||" | "|" | "&" | ";;";
}

/**
 * Blanks out comments while preserving every offset, then splits into segments.
 *
 * Quote, `$(...)`, backtick and heredoc state are tracked so that a `#` inside a
 * string stays script and a `;` inside one does not end a statement. This is a
 * tokenizer for control operators, not a shell parser -- it does not need to
 * know what any command means, only where one stops.
 */
function tokenize(script: string): { masked: string; segments: Segment[] } {
	const masked = script.split("");
	const segments: Segment[] = [];

	let i = 0;
	let segStart = 0;
	let pendingOp: Segment["op"] = "";
	const pendingHeredocs: { tag: string; indented: boolean }[] = [];

	const push = (end: number, nextOp: Segment["op"]): void => {
		segments.push({ text: masked.slice(segStart, end).join(""), start: segStart, op: pendingOp });
		pendingOp = nextOp;
	};

	const blank = (from: number, to: number): void => {
		for (let k = from; k < to; k += 1) if (masked[k] !== "\n") masked[k] = " ";
	};

	while (i < script.length) {
		const ch = script[i] as string;

		// Escapes, including line continuations, are never operators.
		if (ch === "\\" && i + 1 < script.length) {
			i += 2;
			continue;
		}

		if (ch === "'") {
			const end = script.indexOf("'", i + 1);
			i = end === -1 ? script.length : end + 1;
			continue;
		}

		if (ch === '"' || ch === "`") {
			i = skipDelimited(script, i, ch);
			continue;
		}

		if (ch === "$" && script[i + 1] === "(") {
			i = skipParens(script, i + 1);
			continue;
		}

		// `#` only opens a comment at the start of a word.
		if (ch === "#" && isWordStart(script, i)) {
			let end = script.indexOf("\n", i);
			if (end === -1) end = script.length;
			blank(i, end);
			i = end;
			continue;
		}

		// Heredocs: everything from the next newline to the tag is data, not code.
		if (ch === "<" && script[i + 1] === "<" && script[i + 2] !== "<") {
			const header = /^<<(-?)\s*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z_][A-Za-z0-9_]*))/.exec(script.slice(i));
			if (header) {
				pendingHeredocs.push({
					tag: header[2] ?? header[3] ?? header[4] ?? "",
					indented: header[1] === "-",
				});
				i += header[0].length;
				continue;
			}
		}

		if (ch === "\n") {
			push(i, "\n");
			i += 1;
			if (pendingHeredocs.length > 0) i = skipHeredocs(script, i, pendingHeredocs);
			segStart = i;
			continue;
		}

		const two = script.slice(i, i + 2);
		if (two === "&&" || two === "||" || two === ";;") {
			push(i, two);
			i += 2;
			segStart = i;
			continue;
		}

		if (ch === ";" || ch === "|" || ch === "&") {
			push(i, ch as Segment["op"]);
			i += 1;
			segStart = i;
			continue;
		}

		i += 1;
	}

	push(script.length, "");
	return { masked: masked.join(""), segments };
}

function isWordStart(script: string, index: number): boolean {
	if (index === 0) return true;
	const prev = script[index - 1] as string;
	return /[\s;&|(){}]/.test(prev);
}

/** Skips a `"`- or backtick-delimited run, honouring backslash escapes. */
function skipDelimited(script: string, start: number, delim: string): number {
	let i = start + 1;
	while (i < script.length) {
		const ch = script[i];
		if (ch === "\\") {
			i += 2;
			continue;
		}
		if (delim === '"' && ch === "$" && script[i + 1] === "(") {
			i = skipParens(script, i + 1);
			continue;
		}
		if (ch === delim) return i + 1;
		i += 1;
	}
	return script.length;
}

/** Skips a balanced `(...)`, starting at the opening paren. */
function skipParens(script: string, start: number): number {
	let depth = 0;
	let i = start;
	while (i < script.length) {
		const ch = script[i];
		if (ch === "\\") {
			i += 2;
			continue;
		}
		if (ch === "'") {
			const end = script.indexOf("'", i + 1);
			i = end === -1 ? script.length : end + 1;
			continue;
		}
		if (ch === '"') {
			i = skipDelimited(script, i, '"');
			continue;
		}
		if (ch === "(") depth += 1;
		else if (ch === ")") {
			depth -= 1;
			if (depth === 0) return i + 1;
		}
		i += 1;
	}
	return script.length;
}

function skipHeredocs(script: string, start: number, pending: { tag: string; indented: boolean }[]): number {
	let i = start;
	while (pending.length > 0 && i < script.length) {
		let end = script.indexOf("\n", i);
		if (end === -1) end = script.length;
		const line = script.slice(i, end);
		const doc = pending[0] as { tag: string; indented: boolean };
		const candidate = doc.indented ? line.replace(/^[\t]+/, "") : line;
		i = end < script.length ? end + 1 : script.length;
		if (candidate === doc.tag) pending.shift();
	}
	pending.length = 0;
	return i;
}

// ---------------------------------------------------------------------------
// CA001 -- `$?` the runner's errexit makes unreachable
// ---------------------------------------------------------------------------

/** Segment texts after which `$?` is a live, meaningful status read. */
const COMPOUND_TERMINATORS = /(^|[\s;])(fi|done|esac|then|else|do|\}|\)|\{)\s*$/;

function checkErrexitStatusReads(block: RunBlock, segments: Segment[]): Finding[] {
	const findings: Finding[] = [];

	// A composite `shell: bash` step is run as `bash --noprofile --norc -e -o
	// pipefail {0}` and `shell: sh` as `sh -e {0}`; errexit is on before the
	// script's first line, whether or not the script says so.
	let errexit = true;
	let previous: Segment | null = null;

	for (const segment of segments) {
		const trimmed = segment.text.trim();

		// A trap body runs *after* the command that tripped errexit, so its `$?`
		// is the one status errexit guarantees is live -- `trap 'rc=$?; ...' ERR`
		// is the reporting idiom this rule exists to steer people towards.
		const statusIndex = /^\s*trap\b/.test(segment.text) ? -1 : segment.text.indexOf("$?");
		if (
			statusIndex !== -1 &&
			errexit &&
			previous !== null &&
			segment.op !== "&&" &&
			segment.op !== "||" &&
			segment.op !== "|" &&
			segment.op !== ";;" &&
			!COMPOUND_TERMINATORS.test(previous.text.trimEnd()) &&
			!/^\s*(if|while|until|case|elif)\b/.test(previous.text)
		) {
			const previousText = collapse(previous.text.trim());
			findings.push({
				file: block.file,
				line: 0,
				col: segment.start + statusIndex,
				code: "CA001",
				message:
					`\`$?\` is unreachable here: the runner executes this step with errexit, so \`${previousText}\` ` +
					`aborts the step on failure and never reaches this read. Guard the command instead, ` +
					`e.g. \`${previousText} || status=$?\`.`,
			});
		}

		const setFlags = /^set\s+((?:[-+][A-Za-z]+\s*)+|[-+]o\s+errexit)/.exec(trimmed);
		if (setFlags) {
			if (/[-]o\s+errexit/.test(trimmed) || /^set\s+-[A-Za-z]*e/.test(trimmed)) errexit = true;
			else if (/[+]o\s+errexit/.test(trimmed) || /^set\s+\+[A-Za-z]*e/.test(trimmed)) errexit = false;
		}

		if (trimmed !== "") previous = segment;
	}

	return findings;
}

function collapse(text: string): string {
	const flat = text.replace(/\s+/g, " ").trim();
	return flat.length > 60 ? `${flat.slice(0, 57)}...` : flat;
}

// ---------------------------------------------------------------------------
// CA002 -- workflow command syntax
// ---------------------------------------------------------------------------

const WORKFLOW_COMMANDS = new Set([
	"add-mask",
	"add-matcher",
	"add-path",
	"debug",
	"echo",
	"endgroup",
	"error",
	"group",
	"notice",
	"remove-matcher",
	"save-state",
	"set-env",
	"set-output",
	"stop-commands",
	"warning",
]);

/**
 * Flags `::` sequences that look like a workflow command but are not one.
 *
 * GitHub only accepts `::name::message` or `::name key=value,key=value::message`.
 * `::notice:API is up to date` matches neither, so the runner prints it as plain
 * text and the annotation is silently lost -- the exact typo #124 shipped.
 *
 * Anchored to a start-of-string, whitespace or quote boundary so that PowerShell
 * type literals like `[Text.Encoding]::UTF8` in the repo-root action, or any
 * `Foo::bar` in prose, are not mistaken for commands.
 */
function checkWorkflowCommands(block: RunBlock, masked: string): Finding[] {
	const findings: Finding[] = [];
	const pattern = /(?:^|[\s'"])::([a-z][a-z-]*)/g;

	for (const match of masked.matchAll(pattern)) {
		const name = match[1] as string;
		const nameEnd = (match.index ?? 0) + match[0].length;
		const rest = masked.slice(nameEnd);
		const lineEnd = rest.indexOf("\n");
		const tail = lineEnd === -1 ? rest : rest.slice(0, lineEnd);
		const commandStart = nameEnd - name.length - 2;

		if (!WORKFLOW_COMMANDS.has(name)) {
			findings.push({
				file: block.file,
				line: 0,
				col: commandStart,
				code: "CA002",
				message: `\`::${name}\` is not a GitHub workflow command; it will be printed verbatim instead of acted on.`,
			});
			continue;
		}

		if (tail.startsWith("::")) continue;
		if (/^\s+\S/.test(tail) && tail.includes("::")) continue;

		// Show only up to the string's closing quote, so the excerpt is the command
		// as it would be emitted rather than the rest of the shell line.
		const excerpt = collapse((/^[^'"]*/.exec(tail)?.[0] ?? tail).slice(0, 32));

		findings.push({
			file: block.file,
			line: 0,
			col: commandStart,
			code: "CA002",
			message:
				`malformed workflow command \`::${name}${excerpt}\`: the name must be closed with \`::\` ` +
				`(\`::${name}::message\`, or \`::${name} key=value::message\`). As written the runner prints it as text ` +
				`and the annotation never appears.`,
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// ShellCheck
// ---------------------------------------------------------------------------

interface ShellCheckComment {
	line: number;
	column: number;
	level: string;
	code: number;
	message: string;
}

/** Composite `shell:` values whose scripts ShellCheck can read. */
function shellDialect(shell: string | null): "bash" | "sh" | null {
	if (shell === null) return null;
	const head = shell.trim().split(/\s+/, 1)[0]?.toLowerCase() ?? "";
	if (head === "bash") return "bash";
	if (head === "sh") return "sh";
	return null;
}

/**
 * Replaces `${{ ... }}` with same-length filler before handing a block to
 * ShellCheck, so an expression cannot be read as shell syntax and every
 * remaining column still lines up with the source.
 */
function maskExpressions(script: string): string {
	return script.replace(/\$\{\{[\s\S]*?\}\}/g, (m) => "x".repeat(m.length));
}

function runShellCheck(block: RunBlock, dialect: "bash" | "sh"): Finding[] {
	// Records the shell the runner picks (ShellCheck reads the shebang) and the
	// flags it sets, but as comments only, never as a command: ShellCheck honours a file-level
	// `# shellcheck disable=...` directive only when nothing executable precedes
	// it, so a `set -e -o pipefail` here would silently demote every such
	// directive written at the top of a `run:` block. It bought nothing anyway --
	// ShellCheck's errexit-sensitive checks (SC2310-SC2312) are opt-in and this
	// gate does not enable them.
	const prelude =
		dialect === "bash"
			? "#!/usr/bin/env bash\n# runner: bash --noprofile --norc -e -o pipefail {0}\n"
			: "#!/bin/sh\n# runner: sh -e {0}\n";
	const preludeLines = prelude.split("\n").length - 1;

	let stdout: string;
	let stderr: string;
	let exitCode: number;
	try {
		const proc = Bun.spawnSync({
			cmd: ["shellcheck", `--shell=${dialect}`, "--format=json1", "--color=never", "-"],
			stdin: Buffer.from(prelude + maskExpressions(block.script)),
			stdout: "pipe",
			stderr: "pipe",
		});
		stdout = proc.stdout?.toString().trim() ?? "";
		stderr = proc.stderr?.toString().trim() ?? "";
		exitCode = proc.exitCode ?? 0;
	} catch {
		// Silently skipping would turn this gate into a no-op the day the tool is
		// missing, which is the failure mode the gate exists to prevent.
		throw new Error("shellcheck is not on PATH; run this through `task lint:actions:composite` (mise provides it)");
	}

	if (stdout === "") {
		if (exitCode !== 0) {
			throw new Error(`shellcheck failed on ${block.file} (${block.stepName}): ${stderr}`);
		}
		return [];
	}

	const parsed = JSON.parse(stdout) as { comments?: ShellCheckComment[] };
	return (parsed.comments ?? []).map((c) => ({
		file: block.file,
		line: block.startLine + (c.line - preludeLines - 1),
		col: block.indent + c.column,
		code: `SC${c.code}`,
		message: `${c.message} (${c.level})`,
	}));
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/** Turns an offset inside a block's script into a source line and column. */
function resolvePosition(block: RunBlock, offset: number): { line: number; col: number } {
	const before = block.script.slice(0, offset);
	const lineOffset = before.split("\n").length - 1;
	const lastNewline = before.lastIndexOf("\n");
	const column = offset - (lastNewline + 1);
	return {
		line: block.startLine + lineOffset,
		// Only the first line of a block scalar is already past the indent.
		col: block.indent + column + 1,
	};
}

function lintFile(absPath: string, root: string): { findings: Finding[]; blocks: RunBlock[] } {
	const relPath = relative(root, absPath) || absPath;
	const source = readFileSync(absPath, "utf8");
	const { blocks, errors } = extractRunBlocks(relPath, source);
	const findings = [...errors];

	for (const block of blocks) {
		const { masked, segments } = tokenize(block.script);
		const dialect = shellDialect(block.shell);

		// CA001 models `bash -e`. In a `shell: pwsh` step `$?` is PowerShell's
		// boolean success variable and reading it is the idiom, so the rule is
		// scoped to the shells it actually describes. CA002 stays shell-agnostic:
		// a workflow command is lost the same way whatever printed it.
		for (const finding of [
			...(dialect === null ? [] : checkErrexitStatusReads(block, segments)),
			...checkWorkflowCommands(block, masked),
		]) {
			const pos = resolvePosition(block, finding.col);
			findings.push({ ...finding, line: pos.line, col: pos.col });
		}

		if (dialect !== null) findings.push(...runShellCheck(block, dialect));
	}

	return { findings, blocks };
}

function main(): number {
	const args = process.argv.slice(2);
	const listOnly = args.includes("--list");
	const paths = args.filter((a) => !a.startsWith("--"));
	const root = process.env.COMPOSITE_ACTION_LINT_ROOT ?? process.cwd();

	const files = paths.length > 0 ? paths.map((p) => resolve(root, p)) : discoverActionFiles(root);

	if (files.length === 0) {
		process.stderr.write("no composite action files found\n");
		return 1;
	}

	const findings: Finding[] = [];
	const blocks: RunBlock[] = [];
	for (const file of files) {
		const result = lintFile(file, root);
		findings.push(...result.findings);
		blocks.push(...result.blocks);
	}

	if (listOnly) {
		for (const block of blocks) {
			const lines = block.script.replace(/\n$/, "").split("\n").length;
			process.stdout.write(
				`${block.file}:${block.startLine} shell=${block.shell ?? "<missing>"} lines=${lines} step=${block.stepName}\n`,
			);
		}
		process.stdout.write(`${blocks.length} run block(s) in ${files.length} action file(s)\n`);
		return 0;
	}

	findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.col - b.col);

	for (const f of findings) {
		process.stdout.write(`${f.file}:${f.line}:${f.col}: [${f.code}] ${f.message}\n`);
		if (process.env.GITHUB_ACTIONS === "true") {
			process.stdout.write(
				`::error file=${f.file},line=${f.line},col=${f.col},title=${f.code}::${f.message.replace(/\n/g, "%0A")}\n`,
			);
		}
	}

	if (findings.length > 0) {
		process.stdout.write(
			`\n${findings.length} problem(s) in ${blocks.length} composite-action run block(s) across ${files.length} file(s)\n`,
		);
		return 1;
	}

	process.stdout.write(`composite-action shell OK: ${blocks.length} run block(s) in ${files.length} action file(s)\n`);
	return 0;
}

process.exit(main());
