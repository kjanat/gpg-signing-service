import { writeFileSync } from "node:fs";
import app from "gpg-signing-service";
import { openApiConfig } from "~/lib/openapi";

const doc = app.getOpenAPIDocument(openApiConfig);

writeFileSync("client/openapi.json", JSON.stringify(doc, null, 2));
console.log("OpenAPI spec generated at client/openapi.json");
