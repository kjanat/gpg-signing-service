#!/usr/bin/env bun
/// <reference types="bun" />

import path from "node:path";

// Bun cannot load `cloudflare:workers`, which exists only inside workerd.
Bun.plugin({
	name: "cloudflare-workers",
	setup(build) {
		build.module("cloudflare:workers", () => ({ exports: { WorkerEntrypoint: class {} }, loader: "object" }));
	},
});

const { default: app } = await import("#gpg-signing-service");
const { openApiConfig } = await import("#lib/openapi");

const doc = app.getOpenAPIDocument(openApiConfig);

const output = Bun.file(path.resolve(import.meta.dir, "..", "client/openapi.json"));

try {
	const bytes = await Bun.write(output, JSON.stringify(doc, null, 2));
	console.log(`OpenAPI spec generated at ${output.name} (${(bytes / 1024).toFixed(2)} KB)`);
} catch (error) {
	console.error("Failed to write OpenAPI spec:", error);
}
