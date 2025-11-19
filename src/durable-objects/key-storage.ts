import type { StoredKey } from "../types";

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
          return this.getKey(url.searchParams.get("keyId") || "default");

        case "/store-key":
          if (request.method !== "POST") {
            return new Response("Method not allowed", { status: 405 });
          }
          return this.storeKey(await request.json());

        case "/list-keys":
          return this.listKeys();

        case "/delete-key":
          if (request.method !== "DELETE") {
            return new Response("Method not allowed", { status: 405 });
          }
          return this.deleteKey(url.searchParams.get("keyId") || "");

        case "/health":
          return this.healthCheck();

        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  private async getKey(keyId: string): Promise<Response> {
    const key = await this.state.storage.get<StoredKey>(`key:${keyId}`);

    if (!key) {
      return new Response(JSON.stringify({ error: "Key not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify(key), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  private async storeKey(data: StoredKey): Promise<Response> {
    if (!data.armoredPrivateKey || !data.keyId) {
      return new Response(
        JSON.stringify({ error: "Missing required fields" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    await this.state.storage.put(`key:${data.keyId}`, data);

    return new Response(
      JSON.stringify({
        success: true,
        keyId: data.keyId,
        fingerprint: data.fingerprint,
      }),
      { status: 201, headers: { "Content-Type": "application/json" } },
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
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  private async deleteKey(keyId: string): Promise<Response> {
    if (!keyId) {
      return new Response(JSON.stringify({ error: "Key ID required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const existed = await this.state.storage.delete(`key:${keyId}`);

    return new Response(JSON.stringify({ success: true, deleted: existed }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  private async healthCheck(): Promise<Response> {
    const keyCount = (await this.state.storage.list({ prefix: "key:" })).size;

    return new Response(JSON.stringify({ healthy: true, keyCount }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
}
