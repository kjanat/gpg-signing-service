import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchJsonWithTimeout, fetchWithTimeout } from "~/utils/fetch";

describe("fetchWithTimeout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should return response for successful fetch", async () => {
    const mockResponse = new Response(JSON.stringify({ data: "test" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    const response = await fetchWithTimeout("https://example.com/api");

    expect(response.status).toBe(200);
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/api",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });

  it("should pass options to fetch", async () => {
    const mockResponse = new Response("ok");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    await fetchWithTimeout("https://example.com/api", {
      method: "POST",
      headers: { "X-Custom": "header" },
    });

    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/api",
      expect.objectContaining({
        method: "POST",
        headers: { "X-Custom": "header" },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("should throw timeout error when request exceeds timeout", async () => {
    const abortError = new Error("Aborted");
    abortError.name = "AbortError";

    vi.spyOn(globalThis, "fetch").mockRejectedValue(abortError);

    await expect(
      fetchWithTimeout("https://example.com/slow", {}, 5000),
    ).rejects.toThrow(
      "Request to https://example.com/slow timed out after 5000ms",
    );
  });

  it("should re-throw non-abort errors", async () => {
    const networkError = new Error("Network failure");
    vi.spyOn(globalThis, "fetch").mockRejectedValue(networkError);

    await expect(fetchWithTimeout("https://example.com/api")).rejects.toThrow(
      "Network failure",
    );
  });

  it("should accept URL object", async () => {
    const mockResponse = new Response("ok");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    const url = new URL("https://example.com/api");
    await fetchWithTimeout(url);

    expect(fetch).toHaveBeenCalledWith(url, expect.any(Object));
  });
});

describe("fetchJsonWithTimeout", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should return parsed JSON for successful response", async () => {
    const mockData = { name: "test", value: 123 };
    const mockResponse = new Response(JSON.stringify(mockData), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    const result = await fetchJsonWithTimeout<{ name: string; value: number }>(
      "https://example.com/api",
    );

    expect(result).toEqual(mockData);
  });

  it("should throw error for non-OK response", async () => {
    const mockResponse = new Response("Not Found", {
      status: 404,
      statusText: "Not Found",
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    await expect(
      fetchJsonWithTimeout("https://example.com/missing"),
    ).rejects.toThrow("HTTP 404: Not Found");
  });

  it("should throw error for 500 response", async () => {
    const mockResponse = new Response("Server Error", {
      status: 500,
      statusText: "Internal Server Error",
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    await expect(
      fetchJsonWithTimeout("https://example.com/error"),
    ).rejects.toThrow("HTTP 500: Internal Server Error");
  });

  it("should use custom timeout", async () => {
    const mockData = { test: true };
    const mockResponse = new Response(JSON.stringify(mockData), {
      status: 200,
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(mockResponse);

    const result = await fetchJsonWithTimeout(
      "https://example.com/api",
      {},
      30000,
    );

    expect(result).toEqual(mockData);
  });
});
