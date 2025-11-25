/**
 * @fileoverview Durable Object for secure GPG private key storage.
 *
 * This module implements a Cloudflare Durable Object that provides strongly
 * consistent storage for GPG private keys. Each key is stored encrypted
 * with its associated metadata (fingerprint, algorithm, creation date).
 *
 * Storage characteristics:
 * - Strong consistency: No split-brain scenarios
 * - ACID transactions: Atomic key create/update/delete
 * - Global uniqueness: Single logical instance per key ID
 * - SQLite backend: Unlimited reads, 1000 writes/day on free tier
 *
 * @see {@link https://developers.cloudflare.com/durable-objects/} - Durable Objects docs
 *
 * @module durable-objects/key-storage
 */

import type { StoredKey } from "~/schemas/keys";
import { HTTP, MediaType } from "~/types";

/**
 * Durable Object class for secure GPG private key storage.
 *
 * Provides HTTP endpoints for key management operations:
 * - `GET /get-key?keyId=X` - Retrieve a stored key
 * - `POST /store-key` - Store a new key
 * - `GET /list-keys` - List all stored keys (metadata only)
 * - `DELETE /delete-key?keyId=X` - Delete a key
 * - `GET /health` - Health check with key count
 *
 * @example
 * ```typescript
 * // Fetch a key from the Durable Object
 * const response = await env.KEY_STORAGE.get(id).fetch('/get-key?keyId=my-key');
 * const key = await response.json();
 * ```
 */
export class KeyStorage implements DurableObject {
  private state: DurableObjectState;

  /**
   * Creates a new KeyStorage Durable Object instance.
   *
   * @param state - Durable Object state provided by Cloudflare runtime
   */
  constructor(state: DurableObjectState) {
    this.state = state;
  }

  /**
   * Handles incoming HTTP requests to the Durable Object.
   *
   * Routes requests to appropriate handlers based on URL path.
   *
   * @param request - Incoming HTTP request
   * @returns Response with JSON body or error message
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case "/get-key":
          return await this.getKey(url.searchParams.get("keyId") || "default");

        case "/store-key":
          if (request.method !== "POST") {
            return new Response("Method not allowed", {
              status: HTTP.MethodNotAllowed,
            });
          }
          return await this.storeKey(await request.json());

        case "/list-keys":
          return await this.listKeys();

        case "/delete-key":
          if (request.method !== "DELETE") {
            return new Response("Method not allowed", {
              status: HTTP.MethodNotAllowed,
            });
          }
          return await this.deleteKey(url.searchParams.get("keyId") || "");

        case "/health":
          return await this.healthCheck();

        default:
          return new Response("Not found", { status: HTTP.NotFound });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return new Response(JSON.stringify({ error: message }), {
        status: HTTP.InternalServerError,
        headers: { "Content-Type": MediaType.ApplicationJson },
      });
    }
  }

  /**
   * Retrieves a stored key by ID.
   *
   * @param keyId - Unique identifier for the key
   * @returns Response with key data or 404 if not found
   */
  private async getKey(keyId: string): Promise<Response> {
    const key = await this.state.storage.get<StoredKey>(`key:${keyId}`);

    if (!key) {
      return new Response(JSON.stringify({ error: "Key not found" }), {
        status: HTTP.NotFound,
        headers: { "Content-Type": MediaType.ApplicationJson },
      });
    }

    return new Response(JSON.stringify(key), {
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }

  /**
   * Stores a new key in the Durable Object.
   *
   * @param data - Key data including armored private key and metadata
   * @returns Response with success status and key metadata
   */
  private async storeKey(data: StoredKey): Promise<Response> {
    if (!data.armoredPrivateKey || !data.keyId) {
      return new Response(
        JSON.stringify({ error: "Missing required fields" }),
        {
          status: HTTP.BadRequest,
          headers: { "Content-Type": MediaType.ApplicationJson },
        },
      );
    }

    await this.state.storage.put(`key:${data.keyId}`, data);

    return new Response(
      JSON.stringify({
        success: true,
        keyId: data.keyId,
        fingerprint: data.fingerprint,
      }),
      {
        status: HTTP.Created,
        headers: { "Content-Type": MediaType.ApplicationJson },
      },
    );
  }

  /**
   * Lists all stored keys (metadata only, no private keys exposed).
   *
   * @returns Response with array of key metadata objects
   */
  private async listKeys(): Promise<Response> {
    const keys = await this.state.storage.list<StoredKey>({ prefix: "key:" });
    const keyList = Array.from(keys.values()).map((key) => ({
      keyId: key.keyId,
      fingerprint: key.fingerprint,
      createdAt: key.createdAt,
      algorithm: key.algorithm,
    }));

    return new Response(JSON.stringify({ keys: keyList }), {
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }

  /**
   * Permanently deletes a stored key.
   *
   * @param keyId - Unique identifier for the key to delete
   * @returns Response indicating whether key existed and was deleted
   */
  private async deleteKey(keyId: string): Promise<Response> {
    if (!keyId) {
      return new Response(JSON.stringify({ error: "Key ID required" }), {
        status: HTTP.BadRequest,
        headers: { "Content-Type": MediaType.ApplicationJson },
      });
    }

    const existed = await this.state.storage.delete(`key:${keyId}`);

    return new Response(JSON.stringify({ success: true, deleted: existed }), {
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }

  /**
   * Performs a health check on the Durable Object.
   *
   * @returns Response with health status and stored key count
   */
  private async healthCheck(): Promise<Response> {
    const keyCount = (await this.state.storage.list({ prefix: "key:" })).size;

    return new Response(JSON.stringify({ healthy: true, keyCount }), {
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }
}
