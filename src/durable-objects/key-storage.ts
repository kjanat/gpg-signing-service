import type { StoredKey } from "~/schemas/keys";
import { HTTP, MediaType } from "~/types";

export class KeyStorage implements DurableObject {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

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

  private async healthCheck(): Promise<Response> {
    const keyCount = (await this.state.storage.list({ prefix: "key:" })).size;

    return new Response(JSON.stringify({ healthy: true, keyCount }), {
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }
}
