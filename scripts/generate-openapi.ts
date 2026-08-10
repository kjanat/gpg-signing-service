#!/usr/bin/env bun
/// <reference types="bun" />

import path from "node:path";
import app from "#gpg-signing-service";
import { buildOpenAPIDocument } from "#lib/openapi";

// Same builder the `/doc` route serves, so the checked-in spec and the
// deployed one cannot drift apart.
const doc = buildOpenAPIDocument(app);

const output = Bun.file(path.resolve(import.meta.dir, "..", "client/openapi.json"));

try {
	const bytes = await Bun.write(output, JSON.stringify(doc, null, 2));
	console.log(`OpenAPI spec generated at ${output.name} (${(bytes / 1024).toFixed(2)} KB)`);
} catch (error) {
	console.error("Failed to write OpenAPI spec:", error);
}
