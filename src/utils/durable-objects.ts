import type { Env } from "~/types";

/**
 * Durable Object helper functions to eliminate duplication
 */

/**
 * Fetch from KEY_STORAGE Durable Object
 * @param env - Environment bindings
 * @param endpoint - API endpoint path (e.g., "/get-key?keyId=...")
 * @param options - Optional RequestInit options
 */
export async function fetchKeyStorage(
  env: Env,
  endpoint: string,
  options?: RequestInit,
): Promise<Response> {
  const id = env.KEY_STORAGE.idFromName("global");
  const storage = env.KEY_STORAGE.get(id);
  return storage.fetch(new Request(`http://internal${endpoint}`, options));
}

/**
 * Fetch from RATE_LIMITER Durable Object
 * @param env - Environment bindings
 * @param identity - Identity string to rate limit
 */
export async function fetchRateLimiter(
  env: Env,
  identity: string,
): Promise<Response> {
  const id = env.RATE_LIMITER.idFromName("global");
  const limiter = env.RATE_LIMITER.get(id);
  return limiter.fetch(
    new Request(
      `http://internal/consume?identity=${encodeURIComponent(identity)}`,
    ),
  );
}

/**
 * Generic DO response parser with Zod validation
 * Eliminates unsafe type assertions
 */
export async function parseDOResponse<T>(
  response: Response,
  parser: (data: unknown) => T,
): Promise<T> {
  if (!response.ok) {
    const error = (await response.json()) as { error?: string };
    throw new Error(error.error || `DO request failed: ${response.status}`);
  }

  const data = await response.json();
  return parser(data);
}
