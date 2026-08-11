import { vi, describe, it, expect } from "vitest";
import {
  generateNonce,
  REQUEST_COMPONENTS,
  signatureHeaders,
  validateNonce,
  NONCE_LENGTH_IN_BYTES,
  SIGNATURE_AGENT_HEADER,
  verify,
  recommendedComponents,
  type Signer,
  type VerificationParams,
  type Verify,
} from "../src/index";
import { signerFromJWK, verifier, verifierFromJWK } from "../src/crypto";
import { b64Tou8, u8ToB64 } from "../src/base64";

import vectors1 from "./test_data/web_bot_auth_architecture_v1.json";
import vectors2 from "./test_data/web_bot_auth_architecture_v2.json";

const vectors = [...vectors1, ...vectors2];
type Vectors = (typeof vectors)[number];

function ed25519Verifier<T>(
  callback: (
    data: string,
    signature: Uint8Array,
    params: VerificationParams
  ) => T | Promise<T>
): Verify<T> {
  return Object.assign(callback, {
    alg: "ed25519",
  } satisfies Pick<Verify<T>, "alg">);
}

describe.each(vectors)("Web-bot-auth-ed25519-Vector-%#", (v: Vectors) => {
  it("should pass IETF draft test vectors", async () => {
    const signer = await signerFromJWK(v.key);

    const headers = new Headers();
    if (v.signature_agent) {
      headers.append(SIGNATURE_AGENT_HEADER, v.signature_agent);
    }
    const signatureAgentKey =
      "signature_agent_key" in v && typeof v.signature_agent_key === "string"
        ? v.signature_agent_key
        : undefined;
    const request = new Request(v.target_url, { headers });
    const signedHeaders = await signatureHeaders(request, signer, {
      components:
        signatureAgentKey !== undefined
          ? recommendedComponents(signatureAgentKey)
          : v.signature_agent
            ? ["@authority", "signature-agent"]
            : recommendedComponents(),
      created: new Date(v.created_ms),
      expires: new Date(v.expires_ms),
      nonce: v.nonce,
      key: v.label,
    });

    expect(signedHeaders["Signature-Input"]).toBe(v.signature_input);

    // Appending signed header to the request, given that's what the origin receives
    headers.append("Signature", signedHeaders["Signature"]);
    headers.append("Signature-Input", signedHeaders["Signature-Input"]);
    const signedRequest = new Request(request.url, {
      headers,
    });

    vi.setSystemTime(new Date(v.created_ms));
    expect(
      await verify(signedRequest, await verifierFromJWK(v.key))
    ).toBeUndefined();
    vi.useRealTimers();
  });
});

describe("custom components", () => {
  const ed25519Key =
    vectors.find((v) => v.key.kty === "OKP")?.key ?? vectors[0].key;

  it("should sign with custom components including additional headers", async () => {
    const signer = await signerFromJWK(ed25519Key);

    const headers = new Headers();
    headers.append(SIGNATURE_AGENT_HEADER, "https://example.bot.com");
    headers.append("accept", "text/html");
    const request = new Request("https://example.com", { headers });

    const signedHeaders = await signatureHeaders(request, signer, {
      created: new Date(1735689600000),
      expires: new Date(1735693200000),
      components: [...REQUEST_COMPONENTS, "accept"],
    });

    // Verify that the Signature-Input includes the custom component
    expect(signedHeaders["Signature-Input"]).toContain('"accept"');
    expect(signedHeaders["Signature-Input"]).toContain('"@authority"');
    expect(signedHeaders["Signature-Input"]).toContain('"signature-agent"');
  });

  it("should reject custom components missing signature-agent when header is present", async () => {
    const signer = await signerFromJWK(ed25519Key);

    const headers = new Headers();
    headers.append(SIGNATURE_AGENT_HEADER, "https://example.bot.com");
    const request = new Request("https://example.com", { headers });

    expect(() =>
      signatureHeaders(request, signer, {
        created: new Date(1735689600000),
        expires: new Date(1735693200000),
        components: ["@authority"], // missing signature-agent
      })
    ).toThrow(`${SIGNATURE_AGENT_HEADER} is required in params.component`);
  });

  it("accepts a case-insensitive signature-agent component", async () => {
    const signer = await signerFromJWK(ed25519Key);
    const request = new Request("https://example.com", {
      headers: { [SIGNATURE_AGENT_HEADER]: "https://example.bot.com" },
    });

    expect(() =>
      signatureHeaders(request, signer, {
        created: new Date(1735689600000),
        expires: new Date(1735693200000),
        components: ["@authority", "Signature-Agent"],
      })
    ).not.toThrow();
  });

  it("should allow custom components without signature-agent when header is absent", async () => {
    const signer = await signerFromJWK(ed25519Key);

    const request = new Request("https://example.com");

    const signedHeaders = await signatureHeaders(request, signer, {
      created: new Date(1735689600000),
      expires: new Date(1735693200000),
      components: ["@authority"],
    });

    expect(signedHeaders["Signature-Input"]).toContain('"@authority"');
    expect(signedHeaders["Signature-Input"]).not.toContain('"signature-agent"');
  });

  it.each(["req", "tr"])(
    "rejects signature-agent;%s before signing",
    (parameter) => {
      let calls = 0;
      const signer: Signer = {
        keyid: "key",
        alg: "ed25519",
        sign() {
          calls += 1;
          return new Uint8Array([1]);
        },
      };
      const request = new Request("https://example.com", {
        headers: { [SIGNATURE_AGENT_HEADER]: "https://example.bot" },
      });
      expect(() =>
        signatureHeaders(request, signer, {
          created: new Date(1735689600000),
          expires: new Date(1735693200000),
          components: [
            "@authority",
            {
              name: SIGNATURE_AGENT_HEADER,
              parameters: new Map([[parameter, true]]),
            },
          ],
        })
      ).toThrow("target header section");
      expect(calls).toBe(0);
    }
  );
});

describe("covered component enforcement (GHSA-x9cc-346q-g27m)", () => {
  const ed25519Key =
    vectors.find((v) => v.key.kty === "OKP")?.key ?? vectors[0].key;
  const created = new Date(1735689600000);
  const expires = new Date(1735693200000);

  async function signedRequestWith(components: string[]): Promise<Request> {
    const signer = await signerFromJWK(ed25519Key);
    const request = new Request("https://example.com/public");
    const signedHeaders = await signatureHeaders(request, signer, {
      created,
      expires,
      components,
    });
    const headers = new Headers();
    headers.append("Signature", signedHeaders["Signature"]);
    headers.append("Signature-Input", signedHeaders["Signature-Input"]);
    return new Request(request.url, { headers });
  }

  it("rejects a signature that covers no request components", async () => {
    const signedRequest = await signedRequestWith([]);
    vi.setSystemTime(created);
    await expect(
      verify(signedRequest, await verifierFromJWK(ed25519Key))
    ).rejects.toThrow("signature must cover @authority or @target-uri");
    vi.useRealTimers();
  });

  it("accepts a signature covering @authority", async () => {
    const signedRequest = await signedRequestWith(["@authority"]);
    vi.setSystemTime(created);
    await expect(
      verify(signedRequest, await verifierFromJWK(ed25519Key))
    ).resolves.toBeUndefined();
    vi.useRealTimers();
  });

  it("accepts a signature covering @target-uri", async () => {
    const signedRequest = await signedRequestWith(["@target-uri"]);
    vi.setSystemTime(created);
    await expect(
      verify(signedRequest, await verifierFromJWK(ed25519Key))
    ).resolves.toBeUndefined();
    vi.useRealTimers();
  });

  it("rejects a signature algorithm that conflicts with the verifier", async () => {
    const signer = await signerFromJWK(ed25519Key);
    const mislabeledSigner: Signer = {
      keyid: signer.keyid,
      alg: "hmac-sha256",
      sign: (data) => signer.sign(data),
    };
    const request = new Request("https://example.com/public");
    const signedHeaders = await signatureHeaders(request, mislabeledSigner, {
      created,
      expires,
      components: ["@authority"],
    });
    const headers = new Headers();
    headers.set("Signature", signedHeaders.Signature);
    headers.set("Signature-Input", signedHeaders["Signature-Input"]);
    const signedRequest = new Request(request, { headers });

    vi.setSystemTime(created);
    await expect(
      verify(signedRequest, await verifierFromJWK(ed25519Key))
    ).rejects.toThrow("does not match verifier algorithm ed25519");
    vi.useRealTimers();
  });
});

describe("verifier algorithm metadata", () => {
  it("rejects RSA-PSS keys that do not use SHA-512", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,
      ["sign", "verify"]
    );

    expect(() => verifier(keyPair.publicKey)).toThrow(
      "Unsupported RSA-PSS hash algorithm: SHA-256"
    );
  });
});

describe("verification timestamps", () => {
  const maxDateSeconds = 8_640_000_000_000;
  const rfcIntegerExtreme = 999_999_999_999_999;
  const message = (created: number, expires: number) => ({
    method: "GET",
    url: "https://example.com/",
    headers: {
      "signature-input": `sig1=("@authority");created=${created};expires=${expires};keyid="key";alg="ed25519";tag="web-bot-auth"`,
      signature: "sig1=:AQ==:",
    },
  });

  it.each([
    ["created", maxDateSeconds + 1, 0],
    ["created", -maxDateSeconds - 1, 0],
    ["created", rfcIntegerExtreme, 0],
    ["expires", 0, -rfcIntegerExtreme],
  ])(
    "rejects unrepresentable %s before the verifier callback",
    async (name, created, expires) => {
      let calls = 0;
      await expect(
        verify(
          message(created, expires),
          ed25519Verifier(() => {
            calls += 1;
          })
        )
      ).rejects.toThrow(`${name} timestamp is outside JavaScript Date range`);
      expect(calls).toBe(0);
    }
  );

  it("applies future and expiry policy at the Date boundaries", async () => {
    let calls = 0;
    vi.useFakeTimers();
    vi.setSystemTime(new Date(0));
    await expect(
      verify(
        message(maxDateSeconds, maxDateSeconds),
        ed25519Verifier(() => {
          calls += 1;
        })
      )
    ).rejects.toThrow("created in the future");
    await expect(
      verify(
        message(-maxDateSeconds, -maxDateSeconds),
        ed25519Verifier(() => {
          calls += 1;
        })
      )
    ).rejects.toThrow("Signature expired");
    vi.useRealTimers();
    expect(calls).toBe(0);
  });
});

describe("verification snapshots", () => {
  it("rejects oversized signature fields through its Promise", async () => {
    const reads = new Map<string, number>();
    const message = {
      method: "GET",
      url: "https://example.com/",
      headers: {
        get(name: string): string | null {
          const normalized = name.toLowerCase();
          reads.set(normalized, (reads.get(normalized) ?? 0) + 1);
          return normalized === "signature-input" ? "x".repeat(128) : null;
        },
        set(): void {},
      },
    };
    const result = verify(
      message,
      ed25519Verifier(() => undefined),
      {
        limits: { maxSignatureInputBytes: 16 },
      }
    );
    expect(result).toBeInstanceOf(Promise);
    await expect(result).rejects.toThrow("signature-input byte limit");
    expect(reads.get("signature")).toBeUndefined();
  });

  it.each(["req", "tr"])(
    "rejects signature-agent;%s before verification callbacks",
    async (parameter) => {
      let calls = 0;
      const message = {
        method: "GET",
        url: "https://example.com/",
        headers: {
          "signature-input": `sig1=("@authority" "signature-agent";${parameter});created=1735689600;expires=1735693200;keyid="key";tag="web-bot-auth"`,
          signature: "sig1=:AQ==:",
          [SIGNATURE_AGENT_HEADER]: "https://example.bot",
        },
      };
      await expect(
        verify(
          message,
          ed25519Verifier(() => {
            calls += 1;
          })
        )
      ).rejects.toThrow("target header section");
      expect(calls).toBe(0);
    }
  );

  it("reads each attacker-controlled field once", async () => {
    const created = new Date(1735689600000);
    const expires = new Date(1735693200000);
    const signer: Signer = {
      keyid: "key",
      alg: "ed25519",
      sign: () => new Uint8Array([1]),
    };
    const unsigned = {
      method: "GET",
      url: "https://example.com/resource",
      headers: { "x-covered": "original" },
      trailers: { "x-trailer": "trailer" },
    };
    const signed = await signatureHeaders(unsigned, signer, {
      created,
      expires,
      components: [
        "@authority",
        "x-covered",
        { name: "x-trailer", parameters: new Map([["tr", true]]) },
      ],
    });
    const values = new Map([
      ["signature", signed.Signature],
      ["signature-input", signed["Signature-Input"]],
      ["signature-agent", ""],
      ["x-covered", "original"],
      ["host", ""],
    ]);
    const trailerValues = new Map([["x-trailer", "trailer"]]);
    const reads = new Map<string, number>();
    const oneShotHeaders = (source: ReadonlyMap<string, string>) => ({
      get(name: string): string | null {
        const normalized = name.toLowerCase();
        const count = (reads.get(normalized) ?? 0) + 1;
        reads.set(normalized, count);
        if (count > 1) throw new Error(`re-read ${normalized}`);
        return source.get(normalized) ?? null;
      },
      set(): void {},
    });
    const message = {
      method: unsigned.method,
      url: unsigned.url,
      headers: oneShotHeaders(values),
      trailers: oneShotHeaders(trailerValues),
    };

    vi.setSystemTime(created);
    await expect(
      verify(
        message,
        ed25519Verifier((data) => data)
      )
    ).resolves.toContain('"x-covered": original');
    vi.useRealTimers();
    expect(reads).toEqual(
      new Map([
        ["signature-input", 1],
        ["signature", 1],
        ["signature-agent", 1],
        ["x-covered", 1],
        ["host", 1],
        ["x-trailer", 1],
      ])
    );
  });

  it("snapshots response and related-request headers and trailers", async () => {
    const created = new Date(1735689600000);
    const signer: Signer = {
      keyid: "key",
      alg: "ed25519",
      sign: () => new Uint8Array([1]),
    };
    const pair = {
      response: {
        status: 200,
        headers: { "x-response": "response" },
        trailers: { "x-response-trailer": "response-trailer" },
      },
      request: {
        method: "GET",
        url: "https://example.com/resource",
        headers: { "x-request": "request" },
        trailers: { "x-request-trailer": "request-trailer" },
      },
    };
    const req = new Map([["req", true]]);
    const reqTrailer = new Map([
      ["req", true],
      ["tr", true],
    ]);
    const signed = await signatureHeaders(pair, signer, {
      created,
      expires: new Date(1735693200000),
      components: [
        { name: "@authority", parameters: req },
        { name: "x-request", parameters: req },
        { name: "x-request-trailer", parameters: reqTrailer },
        "x-response",
        { name: "x-response-trailer", parameters: new Map([["tr", true]]) },
      ],
    });
    const signedPair = {
      ...pair,
      response: {
        ...pair.response,
        headers: {
          ...pair.response.headers,
          Signature: signed.Signature,
          "Signature-Input": signed["Signature-Input"],
        },
      },
    };

    vi.setSystemTime(created);
    const data = await verify(
      signedPair,
      ed25519Verifier((signedData) => signedData)
    );
    vi.useRealTimers();
    expect(data).toContain('"x-request";req: request');
    expect(data).toContain('"x-request-trailer";req;tr: request-trailer');
    expect(data).toContain('"x-response": response');
    expect(data).toContain('"x-response-trailer";tr: response-trailer');
  });

  it("preserves bs occurrence bytes through the verification snapshot", async () => {
    const created = new Date(1735689600000);
    const signer: Signer = {
      keyid: "key",
      alg: "ed25519",
      sign: () => new Uint8Array([1]),
    };
    const unsigned = {
      method: "GET",
      url: "https://example.com/resource",
      headers: { "x-bytes": ["é", "ÿ"] },
    };
    const signed = await signatureHeaders(unsigned, signer, {
      created,
      expires: new Date(1735693200000),
      components: [
        "@authority",
        { name: "x-bytes", parameters: new Map([["bs", true]]) },
      ],
    });
    const message = {
      ...unsigned,
      headers: {
        ...unsigned.headers,
        Signature: signed.Signature,
        "Signature-Input": signed["Signature-Input"],
      },
    };

    vi.setSystemTime(created);
    const data = await verify(
      message,
      ed25519Verifier((signedData) => signedData)
    );
    vi.useRealTimers();
    expect(data).toContain('"x-bytes";bs: :6Q==:, :/w==:');
  });

  it("stops reading covered fields when the field budget is exhausted", async () => {
    const created = new Date(1735689600000);
    const signer: Signer = {
      keyid: "key",
      alg: "ed25519",
      sign: () => new Uint8Array([1]),
    };
    const unsigned = {
      method: "GET",
      url: "https://example.com/resource",
      headers: { "x-large": "small", "x-after": "after" },
    };
    const signed = await signatureHeaders(unsigned, signer, {
      created,
      expires: new Date(1735693200000),
      components: ["@authority", "x-large", "x-after"],
    });
    const values = new Map([
      ["signature-input", signed["Signature-Input"]],
      ["signature", signed.Signature],
      ["x-large", "x".repeat(2_000)],
      ["x-after", "after"],
    ]);
    const reads = new Map<string, number>();
    const message = {
      method: unsigned.method,
      url: unsigned.url,
      headers: {
        get(name: string): string | null {
          const normalized = name.toLowerCase();
          reads.set(normalized, (reads.get(normalized) ?? 0) + 1);
          return values.get(normalized) ?? null;
        },
        set(): void {},
      },
    };
    await expect(
      verify(
        message,
        ed25519Verifier(() => undefined),
        {
          limits: { maxFieldBytes: 1_000 },
        }
      )
    ).rejects.toThrow("field byte limit");
    expect(reads.get("x-after")).toBeUndefined();
  });
});

describe("nonce", () => {
  describe("generateNonce", () => {
    it("should generate a base64 string", () => {
      const nonce = generateNonce();
      expect(typeof nonce).toBe("string");
      // Base64 regex pattern
      expect(() => b64Tou8(nonce)).not.toThrowError();
    });

    it("should generate nonce with correct length when decoded", () => {
      const nonce = generateNonce();
      const decoded = b64Tou8(nonce);
      expect(decoded.length).toBe(NONCE_LENGTH_IN_BYTES);
    });

    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      const nonce3 = generateNonce();
      expect(nonce1).not.toBe(nonce2);
      expect(nonce2).not.toBe(nonce3);
      expect(nonce1).not.toBe(nonce3);
    });
  });

  describe("validateNonce", () => {
    it("should validate correctly generated nonces", () => {
      const nonce = generateNonce();
      expect(validateNonce(nonce)).toBe(true);
    });

    it("should reject invalid base64 strings", () => {
      expect(validateNonce("not-base64!@#$")).toBe(false);
    });

    it("should reject empty string", () => {
      expect(validateNonce("")).toBe(false);
    });

    it("should reject nonces of incorrect length", () => {
      // Create a small base64 string
      const shortNonce = btoa("too short");
      expect(validateNonce(shortNonce)).toBe(false);

      // Create a long base64 string
      const longArray = new Uint8Array(NONCE_LENGTH_IN_BYTES + 10);
      crypto.getRandomValues(longArray);
      const longNonce = u8ToB64(longArray);
      expect(validateNonce(longNonce)).toBe(false);
    });

    it.each([[null], [undefined], [123], [{}], [[]], [true]])(
      "should handle invalid input type: %s",
      (invalidInput: unknown) => {
        expect(validateNonce(invalidInput as string)).toBe(false);
      }
    );

    it("should validate multiple generated nonces", () => {
      for (let i = 0; i < 10; i++) {
        const nonce = generateNonce();
        expect(validateNonce(nonce)).toBe(true);
      }
    });
  });
});
