#!/usr/bin/env bun
/// <reference types="bun" />

import path from "node:path";
import app from "#gpg-signing-service";
import { openApiConfig } from "#lib/openapi";

const doc = app.getOpenAPIDocument(openApiConfig);

const output = Bun.file(path.resolve(import.meta.dir, "..", "client/openapi.json"));

try {
	const bytes = await Bun.write(output, JSON.stringify(doc, null, 2));
	console.log(`OpenAPI spec generated at ${output.name} (${(bytes / 1024).toFixed(2)} KB)`);
} catch (error) {
	console.error("Failed to write OpenAPI spec:", error);
}
