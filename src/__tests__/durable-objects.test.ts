import { describe, expect, it, vi } from "vitest";
import type { Env } from "~/types";
import {
  fetchKeyStorage,
  fetchRateLimiter,
  parseDOResponse,
} from "~/utils/durable-objects";

describe("Durable Object Helpers", () => {
  describe("fetchKeyStorage - Happy Path", () => {
    it("should fetch from KEY_STORAGE and return response", async () => {
      const mockResponse = new Response(JSON.stringify({ success: true }));
      const mockFetch = vi.fn().mockResolvedValue(mockResponse);
      const mockStub = { fetch: mockFetch };
      const mockGet = vi.fn().mockReturnValue(mockStub);
      const mockIdFromName = vi.fn().mockReturnValue("storage-id");

      const env = {
        KEY_STORAGE: {
          idFromName: mockIdFromName,
          get: mockGet,
        },
      } as unknown as Env;

      const result = await fetchKeyStorage(env, "/get-key?keyId=ABC");

      expect(mockIdFromName).toHaveBeenCalledWith("global");
      expect(mockGet).toHaveBeenCalledWith("storage-id");
      expect(mockFetch).toHaveBeenCalled();
      expect(result).toBe(mockResponse);
    });

    it("should construct correct internal URL", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "/list-keys");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toBe("http://internal/list-keys");
    });

    it("should pass RequestInit options through", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "/store", {
        method: "POST",
        body: "test",
      });

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.method).toBe("POST");
      expect(await callArg.text()).toBe("test");
    });
  });

  describe("fetchKeyStorage - Error Cases", () => {
    it("should propagate fetch errors", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("Fetch failed"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({
            fetch: mockFetch,
          }),
        },
      } as unknown as Env;

      await expect(fetchKeyStorage(env, "/test")).rejects.toThrow(
        "Fetch failed",
      );
    });

    it("should propagate idFromName errors", async () => {
      const env = {
        KEY_STORAGE: {
          idFromName: () => {
            throw new Error("Name error");
          },
          get: () => ({ fetch: vi.fn() }),
        },
      } as unknown as Env;

      await expect(fetchKeyStorage(env, "/test")).rejects.toThrow("Name error");
    });

    it("should handle null stub from get()", async () => {
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => null,
        },
      } as unknown as Env;

      await expect(fetchKeyStorage(env, "/test")).rejects.toThrow();
    });

    it("should handle undefined stub from get()", async () => {
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => undefined,
        },
      } as unknown as Env;

      await expect(fetchKeyStorage(env, "/test")).rejects.toThrow();
    });
  });

  describe("fetchKeyStorage - Edge Cases", () => {
    it("should handle empty endpoint", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      // URL constructor adds trailing slash for empty path
      expect(callArg.url).toBe("http://internal/");
    });

    it("should handle endpoint with query params", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "/keys?limit=10&offset=5");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toBe("http://internal/keys?limit=10&offset=5");
    });

    it("should handle endpoint with hash", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "/page#section");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toBe("http://internal/page#section");
    });

    it("should handle DELETE method", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "/delete", { method: "DELETE" });

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.method).toBe("DELETE");
    });

    it("should handle custom headers", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchKeyStorage(env, "/test", {
        headers: { "X-Custom": "value" },
      });

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.headers.get("X-Custom")).toBe("value");
    });
  });

  describe("fetchRateLimiter - Happy Path", () => {
    it("should fetch from RATE_LIMITER with identity", async () => {
      const mockResponse = new Response(
        JSON.stringify({ allowed: true, remaining: 10 }),
      );
      const mockFetch = vi.fn().mockResolvedValue(mockResponse);
      const env = {
        RATE_LIMITER: {
          idFromName: () => "limiter-id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      const result = await fetchRateLimiter(env, "user:123");

      expect(mockFetch).toHaveBeenCalled();
      expect(result).toBe(mockResponse);

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toContain("consume?identity=");
      expect(callArg.url).toContain("user%3A123");
    });

    it("should URL-encode identity with special chars", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchRateLimiter(env, "id@host.com/path?key=val");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toContain("id%40host.com%2Fpath%3Fkey%3Dval");
    });
  });

  describe("fetchRateLimiter - Error Cases", () => {
    it("should propagate DO errors", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("DO unavailable"));
      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => ({
            fetch: mockFetch,
          }),
        },
      } as unknown as Env;

      await expect(fetchRateLimiter(env, "test")).rejects.toThrow(
        "DO unavailable",
      );
    });

    it("should handle get() null", async () => {
      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => null,
        },
      } as unknown as Env;

      await expect(fetchRateLimiter(env, "test")).rejects.toThrow();
    });
  });

  describe("fetchRateLimiter - Edge Cases", () => {
    it("should handle empty identity", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchRateLimiter(env, "");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toBe("http://internal/consume?identity=");
    });

    it("should handle unicode identity", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      await fetchRateLimiter(env, "用户:测试");

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url).toContain("consume?identity=");
    });

    it("should handle very long identity (2000+ chars)", async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      const longId = "x".repeat(2500);
      await fetchRateLimiter(env, longId);

      const callArg = mockFetch.mock.calls[0]?.[0] as Request;
      expect(callArg.url.length).toBeGreaterThan(2500);
    });
  });

  describe("parseDOResponse - Happy Path", () => {
    it("should parse successful JSON response", async () => {
      const response = new Response(JSON.stringify({ key: "value" }), {
        status: 200,
      });

      const parser = (data: unknown) => data as { key: string };
      const result = await parseDOResponse(response, parser);

      expect(result).toEqual({ key: "value" });
    });

    it("should parse with transformation", async () => {
      const response = new Response(JSON.stringify({ count: "42" }), {
        status: 200,
      });

      const parser = (data: unknown) => ({
        count: Number.parseInt((data as { count: string }).count, 10),
      });

      const result = await parseDOResponse(response, parser);
      expect(result).toEqual({ count: 42 });
    });

    it("should parse 201 Created responses", async () => {
      const response = new Response(JSON.stringify({ created: true }), {
        status: 201,
      });

      const result = await parseDOResponse(response, (d) => d);
      expect(result).toEqual({ created: true });
    });
  });

  describe("parseDOResponse - Error Cases", () => {
    it("should throw on 404 with error message", async () => {
      const response = new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
      });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "Not found",
      );
    });

    it("should throw on 500 with generic message", async () => {
      const response = new Response(JSON.stringify({}), { status: 500 });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "DO request failed: 500",
      );
    });

    it("should throw on 503 Service Unavailable", async () => {
      const response = new Response(JSON.stringify({ error: "Service down" }), {
        status: 503,
      });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "Service down",
      );
    });

    it("should throw on 400 Bad Request", async () => {
      const response = new Response(JSON.stringify({ error: "Bad input" }), {
        status: 400,
      });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "Bad input",
      );
    });

    it("should propagate parser errors", async () => {
      const response = new Response(JSON.stringify({ data: "test" }), {
        status: 200,
      });

      const strictParser = () => {
        throw new Error("Parser validation failed");
      };

      await expect(parseDOResponse(response, strictParser)).rejects.toThrow(
        "Parser validation failed",
      );
    });

    it("should handle malformed JSON", async () => {
      const response = new Response("not json{", { status: 200 });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow();
    });
  });

  describe("parseDOResponse - Edge Cases", () => {
    it("should parse null JSON", async () => {
      const response = new Response("null", { status: 200 });

      const result = await parseDOResponse(response, (d) => d);
      expect(result).toBeNull();
    });

    it("should parse array responses", async () => {
      const response = new Response(JSON.stringify([1, 2, 3]), {
        status: 200,
      });

      const result = await parseDOResponse(response, (d) => d as number[]);
      expect(result).toEqual([1, 2, 3]);
    });

    it("should parse empty object", async () => {
      const response = new Response("{}", { status: 200 });

      const result = await parseDOResponse(response, (d) => d);
      expect(result).toEqual({});
    });

    it("should parse nested objects", async () => {
      const data = {
        level1: { level2: { level3: { value: "deep" } } },
      };
      const response = new Response(JSON.stringify(data), { status: 200 });

      const result = await parseDOResponse(response, (d) => d);
      expect(result).toEqual(data);
    });

    it("should handle 401 Unauthorized", async () => {
      const response = new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
      });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "Unauthorized",
      );
    });

    it("should handle 429 Too Many Requests", async () => {
      const response = new Response(JSON.stringify({ error: "Rate limited" }), {
        status: 429,
      });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "Rate limited",
      );
    });

    it("should handle error field as object instead of string", async () => {
      const response = new Response(
        JSON.stringify({ error: { code: 500, msg: "Error" } }),
        { status: 500 },
      );

      // When error is object, toString() gives "[object Object]"
      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "[object Object]",
      );
    });

    it("should handle empty error string", async () => {
      const response = new Response(JSON.stringify({ error: "" }), {
        status: 500,
      });

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "DO request failed: 500",
      );
    });

    it("should use parser with type guards", async () => {
      const response = new Response(
        JSON.stringify({ id: "123", active: true }),
        { status: 200 },
      );

      interface TypedData {
        id: string;
        active: boolean;
      }

      const parser = (data: unknown): TypedData => {
        const obj = data as TypedData;
        if (typeof obj.id !== "string") throw new Error("Invalid id");
        if (typeof obj.active !== "boolean") throw new Error("Invalid active");
        return obj;
      };

      const result = await parseDOResponse(response, parser);
      expect(result).toEqual({ id: "123", active: true });
    });

    it("should fail parser type guards", async () => {
      const response = new Response(
        JSON.stringify({ id: 123 }), // id is number
        { status: 200 },
      );

      const parser = (data: unknown) => {
        const obj = data as { id: string };
        if (typeof obj.id !== "string") throw new Error("id must be string");
        return obj;
      };

      await expect(parseDOResponse(response, parser)).rejects.toThrow(
        "id must be string",
      );
    });
  });

  describe("Integration Scenarios", () => {
    it("should handle key retrieval workflow", async () => {
      const keyData = {
        armoredPrivateKey: "-----BEGIN PGP...",
        keyId: "ABC123",
        fingerprint: "DEADBEEF",
      };

      const mockFetch = vi
        .fn()
        .mockResolvedValue(new Response(JSON.stringify(keyData)));

      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      const response = await fetchKeyStorage(env, "/get-key?keyId=ABC123");

      const result = await parseDOResponse(response, (d) => d);
      expect(result).toEqual(keyData);
    });

    it("should handle key not found workflow", async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "Key not found" }), {
          status: 404,
        }),
      );

      const env = {
        KEY_STORAGE: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      const response = await fetchKeyStorage(env, "/get-key?keyId=MISSING");

      await expect(parseDOResponse(response, (d) => d)).rejects.toThrow(
        "Key not found",
      );
    });

    it("should handle rate limit check workflow", async () => {
      const limitData = { allowed: false, remaining: 0, resetAt: 1234567890 };

      const mockFetch = vi
        .fn()
        .mockResolvedValue(new Response(JSON.stringify(limitData)));

      const env = {
        RATE_LIMITER: {
          idFromName: () => "id",
          get: () => ({ fetch: mockFetch }),
        },
      } as unknown as Env;

      const response = await fetchRateLimiter(
        env,
        "https://github.com:repo:org/name",
      );

      const result = await parseDOResponse(response, (d) => d);
      expect(result).toEqual(limitData);
    });
  });
});
