import { writeFileSync } from "node:fs";
import app from "gpg-signing-service";

const doc = app.getOpenAPIDocument({
  openapi: "3.1.0",
  info: {
    version: "1.0.0",
    title: "GPG Signing Service API",
  },
});

writeFileSync("client/openapi.json", JSON.stringify(doc, null, 2));
console.log("OpenAPI spec generated at client/openapi.json");
