declare module "cloudflare:test" {
  // ProvidedEnv controls the type of `import("cloudflare:test").env`
  interface ProvidedEnv extends Env {
    /** Token for admin endpoints */
    ADMIN_TOKEN: string;

    /** Passphrase for encrypted private key */
    KEY_PASSPHRASE: string;

    /** Comma-separated list of allowed issuers */
    ALLOWED_ISSUERS: string;

    /** ID of the signing key */
    KEY_ID: string;
  }
}
