import { describe, expect, it } from "vitest";

import * as webBotAuth from "../src/index";
import { verifierFromJWK } from "../src/crypto";
import architectureVectors from "./test_data/web_bot_auth_architecture_v2.json";

const vNext = webBotAuth;

const request = {
  method: "POST",
  url: "https://example.com/path",
  headers: { "content-type": "application/json" },
};

describe("architecture vectors", () => {
  for (const vector of architectureVectors) {
    it(`verifies ${vector.key.kty} ${vector.label}`, async () => {
      const headers: Record<string, string> = {
        signature: vector.signature,
        "signature-input": vector.signature_input,
      };
      if (vector.signature_agent !== undefined) {
        headers["signature-agent"] = vector.signature_agent;
      }
      await expect(
        webBotAuth.verify(
          { method: "GET", url: vector.target_url, headers },
          await verifierFromJWK(vector.key),
          { label: vector.label }
        )
      ).resolves.toMatchObject({ keyid: expect.any(String) });
    });
  }
});

describe("custom parameters", () => {
  it("rejects empty asymmetric signer output", async () => {
    const now = new Date();
    await expect(
      vNext.signatureHeaders(
        request,
        {
          keyid: "test-key",
          alg: "ed25519",
          sign: () => new Uint8Array(),
        },
        {
          created: now,
          expires: new Date(now.getTime() + 60_000),
          components: ["@authority"],
        }
      )
    ).rejects.toThrow("Signature bytes must not be empty");
  });

  it("returns every authenticated extension value", async () => {
    const now = new Date();
    const fields = await vNext.signatureHeaders(
      request,
      {
        keyid: "test-key",
        alg: "ed25519",
        sign: () => new Uint8Array([1, 2, 3]),
      },
      {
        created: now,
        expires: new Date(now.getTime() + 60_000),
        components: ["@method", "@authority", "@path"],
        signatureInputProfile: "rfc9651-extension",
        extensions: [
          { name: "integer", value: 1 },
          { name: "decimal", value: vNext.decimal(1.5) },
          { name: "string", value: "value" },
          { name: "token", value: vNext.token("value") },
          { name: "bytes", value: new Uint8Array([1, 2]) },
          { name: "boolean", value: false },
          { name: "date", value: vNext.date(1) },
          { name: "display", value: vNext.displayString("cafe") },
        ],
      }
    );
    const verified = await vNext.verify(
      {
        ...request,
        headers: {
          ...request.headers,
          signature: fields.Signature,
          "signature-input": fields["Signature-Input"],
        },
      },
      {
        keyid: "test-key",
        alg: "ed25519",
        verify: () => true,
      },
      {
        signatureInputProfile: "rfc9651-extension",
        transform: (params: webBotAuth.VerificationParams) => params.extensions,
      }
    );
    expect(verified.map(({ name }) => name)).toEqual([
      "integer",
      "decimal",
      "string",
      "token",
      "bytes",
      "boolean",
      "date",
      "display",
    ]);
  });

  it("rejects reserved custom parameter collisions", async () => {
    const now = new Date();
    await expect(
      vNext.signatureHeaders(
        request,
        {
          keyid: "test-key",
          alg: "ed25519",
          sign: () => new Uint8Array(),
        },
        {
          created: now,
          expires: new Date(now.getTime() + 60_000),
          components: ["@authority"],
          extensions: [{ name: "keyid", value: "collision" }],
        }
      )
    ).rejects.toThrow("collides with a reserved parameter");
  });

  it("supports an ECDSA provider with an omitted alg parameter", async () => {
    const now = new Date();
    const fields = await vNext.signatureHeaders(
      request,
      {
        keyid: "test-key",
        alg: "ecdsa-p256-sha256",
        sign: () => new Uint8Array([1, 2, 3]),
      },
      {
        created: now,
        expires: new Date(now.getTime() + 60_000),
        components: ["@authority"],
      }
    );
    expect(fields["Signature-Input"]).not.toContain(";alg=");
    await expect(
      vNext.verify(
        {
          ...request,
          headers: {
            ...request.headers,
            signature: fields.Signature,
            "signature-input": fields["Signature-Input"],
          },
        },
        {
          keyid: "test-key",
          alg: "ecdsa-p256-sha256",
          verify: () => true,
        },
        { transform: () => "verified" }
      )
    ).resolves.toBe("verified");
  });

  it("rejects a claimed algorithm that differs from the provider", async () => {
    let calls = 0;
    const now = new Date();
    await expect(
      vNext.signatureHeaders(
        request,
        {
          keyid: "test-key",
          alg: "ecdsa-p256-sha256",
          sign() {
            calls += 1;
            return new Uint8Array([1, 2, 3]);
          },
        },
        {
          created: now,
          expires: new Date(now.getTime() + 60_000),
          alg: "ed25519",
          components: ["@authority"],
        }
      )
    ).rejects.toThrow(
      "claimed algorithm ed25519 does not match ecdsa-p256-sha256"
    );
    expect(calls).toBe(0);
  });

  it("rejects a verified claim that differs from the provider", async () => {
    const now = new Date();
    const fields = await vNext.signatureHeaders(
      request,
      {
        keyid: "test-key",
        alg: "ed25519",
        sign: () => new Uint8Array([1, 2, 3]),
      },
      {
        created: now,
        expires: new Date(now.getTime() + 60_000),
        alg: "ed25519",
        components: ["@authority"],
      }
    );
    let calls = 0;
    await expect(
      vNext.verify(
        {
          ...request,
          headers: {
            ...request.headers,
            signature: fields.Signature,
            "signature-input": fields["Signature-Input"],
          },
        },
        {
          keyid: "test-key",
          alg: "ecdsa-p256-sha256",
          verify: () => {
            calls += 1;
            return true;
          },
        }
      )
    ).rejects.toThrow("verifier algorithm does not match");
    expect(calls).toBe(0);
  });
});

describe("replay protection", () => {
  function signatureAgentComponent(
    key = "sig1"
  ): webBotAuth.ComponentIdentifier {
    return { name: "signature-agent", parameters: [["key", key]] };
  }

  async function signed(
    components: ReadonlyArray<webBotAuth.ComponentIdentifier>,
    headers: Readonly<Record<string, string>> = {}
  ): Promise<{
    readonly method: string;
    readonly url: string;
    readonly headers: Readonly<Record<string, string>>;
  }> {
    const now = new Date();
    const message = {
      method: "GET",
      url: "https://example.com/path",
      headers,
    };
    const fields = await vNext.signatureHeaders(
      message,
      {
        keyid: "test-key",
        alg: "ed25519",
        sign: () => new Uint8Array([1, 2, 3]),
      },
      {
        created: now,
        expires: new Date(now.getTime() + 60_000),
        components,
      }
    );
    return {
      ...message,
      headers: {
        ...headers,
        signature: fields.Signature,
        "signature-input": fields["Signature-Input"],
      },
    };
  }

  const accept: webBotAuth.Verifier = {
    keyid: "test-key",
    alg: "ed25519",
    verify: () => true,
  };

  it("rejects unsupported synchronous signing algorithms", () => {
    const now = new Date();
    expect(() =>
      Reflect.apply(vNext.signatureHeadersSync, undefined, [
        request,
        {
          keyid: "test-key",
          alg: "hmac-sha256",
          signSync: () => new Uint8Array([1, 2, 3]),
        },
        {
          created: now,
          expires: new Date(now.getTime() + 60_000),
          components: ["@authority"],
        },
      ])
    ).toThrow("algorithm hmac-sha256 is not allowed by Web Bot Auth");
  });

  it("binds the claimed keyid to the verifier key", async () => {
    let calls = 0;
    await expect(
      vNext.verify(await signed(["@target-uri"]), {
        keyid: "different-key",
        alg: "ed25519",
        verify: () => {
          calls += 1;
          return true;
        },
      })
    ).rejects.toMatchObject({ code: "unknown_key" });
    expect(calls).toBe(0);
  });

  it("resolves a trusted verifier from signed metadata", async () => {
    await expect(
      vNext.verify(await signed(["@target-uri"]), (params) => ({
        keyid: params.keyid,
        alg: "ed25519",
        verify: () => true,
      }))
    ).resolves.toMatchObject({ keyid: "test-key" });
  });

  it("rejects signatures without authority or target URI", async () => {
    const valid = await signed(["@target-uri"]);
    const message = {
      ...valid,
      headers: {
        ...valid.headers,
        "signature-input": valid.headers["signature-input"].replace(
          '"@target-uri"',
          '"@method"'
        ),
      },
    };
    await expect(vNext.verify(message, accept)).rejects.toThrow(
      "signature must cover @authority or @target-uri"
    );
  });

  it("rejects an uncovered Signature-Agent field", async () => {
    const signedWithoutAgent = await signed(["@authority"]);
    await expect(
      vNext.verify(
        {
          ...signedWithoutAgent,
          headers: {
            ...signedWithoutAgent.headers,
            "signature-agent": 'sig1="https://example.com/agent"',
          },
        },
        accept
      )
    ).rejects.toThrow(
      "signature with signature-agent header must cover signature-agent"
    );
  });

  it("accepts target and Signature-Agent coverage", async () => {
    await expect(
      vNext.verify(
        await signed(["@target-uri", signatureAgentComponent()], {
          "signature-agent": 'sig1="https://example.com/agent"',
        }),
        (params) => {
          expect(params.signatureAgentKey).toBe("sig1");
          return accept;
        }
      )
    ).resolves.toMatchObject({ keyid: "test-key", tag: "web-bot-auth" });
  });

  it("rejects false verification without running the result transform", async () => {
    let transforms = 0;
    await expect(
      vNext.verify(
        await signed(["@target-uri"]),
        { keyid: "test-key", alg: "ed25519", verify: () => false },
        {
          transform: () => {
            transforms += 1;
            return "verified";
          },
        }
      )
    ).rejects.toMatchObject({ code: "signature_mismatch" });
    expect(transforms).toBe(0);
  });

  it("runs the result transform after true verification", async () => {
    await expect(
      vNext.verify(
        await signed(["@target-uri"]),
        { keyid: "test-key", alg: "ed25519", verify: () => true },
        { transform: ({ keyid }) => keyid }
      )
    ).resolves.toBe("test-key");
  });

  it.each(["req", "tr"])(
    "rejects Signature-Agent coverage from the %s field section",
    async (section) => {
      let calls = 0;
      const valid = await signed(["@target-uri", signatureAgentComponent()], {
        "signature-agent": 'sig1="https://example.com/agent"',
      });
      const message = {
        ...valid,
        headers: {
          ...valid.headers,
          "signature-input": valid.headers["signature-input"].replace(
            '"signature-agent";key="sig1"',
            `"signature-agent";key="sig1";${section}`
          ),
        },
      };
      await expect(
        vNext.verify(message, {
          keyid: "test-key",
          alg: "ed25519",
          verify: () => {
            calls += 1;
            return true;
          },
        })
      ).rejects.toThrow(
        "signature-agent coverage must target the message header field section"
      );
      expect(calls).toBe(0);
    }
  );

  it("rejects Signature-Agent coverage without a dictionary key", async () => {
    let calls = 0;
    const valid = await signed(["@target-uri", signatureAgentComponent()], {
      "signature-agent": 'sig1="https://example.com/agent"',
    });
    const message = {
      ...valid,
      headers: {
        ...valid.headers,
        "signature-input": valid.headers["signature-input"].replace(
          ';key="sig1"',
          ""
        ),
      },
    };
    await expect(
      vNext.verify(message, {
        keyid: "test-key",
        alg: "ed25519",
        verify: () => {
          calls += 1;
          return true;
        },
      })
    ).rejects.toThrow("signature-agent coverage must select a dictionary key");
    expect(calls).toBe(0);
  });

  it.each([
    ["uncovered", ["@target-uri"]],
    ["whole field", ["@target-uri", "signature-agent"]],
    [
      "request field section",
      [
        "@target-uri",
        {
          name: "signature-agent",
          parameters: [
            ["key", "sig1"],
            ["req", true],
          ],
        },
      ],
    ],
    ["missing dictionary key", ["@target-uri", "signature-agent"]],
  ] satisfies ReadonlyArray<
    readonly [string, ReadonlyArray<webBotAuth.ComponentIdentifier>]
  >)("rejects %s Signature-Agent signing coverage", async (_, components) => {
    let calls = 0;
    const now = new Date();
    await expect(
      vNext.signatureHeaders(
        {
          method: "GET",
          url: "https://example.com/path",
          headers: { "signature-agent": 'sig1="https://example.com/agent"' },
        },
        {
          keyid: "test-key",
          alg: "ed25519",
          sign: () => {
            calls += 1;
            return new Uint8Array([1, 2, 3]);
          },
        },
        {
          created: now,
          expires: new Date(now.getTime() + 60_000),
          components,
        }
      )
    ).rejects.toThrow(/signature-agent coverage|must cover signature-agent/);
    expect(calls).toBe(0);
  });

  it("signs and verifies independent signature and member labels", async () => {
    const now = new Date();
    const message = {
      method: "GET",
      url: "https://example.com/path",
      headers: { "signature-agent": 'agent2="https://example.com/agent"' },
    };
    const fields = await vNext.signatureHeaders(
      message,
      {
        keyid: "test-key",
        alg: "ed25519",
        sign: () => new Uint8Array([1, 2, 3]),
      },
      {
        key: "sig2",
        created: now,
        expires: new Date(now.getTime() + 60_000),
        components: ["@target-uri", signatureAgentComponent("agent2")],
      }
    );
    expect(fields["Signature-Input"]).toContain(
      'sig2=("@target-uri" "signature-agent";key="agent2")'
    );
    await expect(
      vNext.verify(
        {
          ...message,
          headers: {
            ...message.headers,
            signature: fields.Signature,
            "signature-input": fields["Signature-Input"],
          },
        },
        accept,
        { label: "sig2" }
      )
    ).resolves.toMatchObject({ keyid: "test-key" });
  });

  it("enumerates signature labels before selection", () => {
    const created = Math.floor(Date.now() / 1000);
    const parameters = `;created=${created};expires=${created + 60};keyid="test-key";tag="web-bot-auth"`;
    const signatures = vNext.getSignatures({
      method: "GET",
      url: "https://example.com/path",
      headers: {
        "signature-input": `first=("@target-uri")${parameters}, second=("@target-uri")${parameters}`,
        signature: "first=:AQ==:, second=:Ag==:",
      },
    });
    expect(signatures.map(({ label }) => label)).toEqual(["first", "second"]);
  });

  it("rejects policy failures before invoking the consumer verifier", async () => {
    let calls = 0;
    const valid = await signed(["@target-uri"]);
    const message = {
      ...valid,
      headers: {
        ...valid.headers,
        "signature-input": valid.headers["signature-input"].replace(
          '"@target-uri"',
          '"@method"'
        ),
      },
    };
    await expect(
      vNext.verify(message, {
        keyid: "test-key",
        alg: "ed25519",
        verify: () => {
          calls += 1;
          return true;
        },
      })
    ).rejects.toThrow("signature must cover @authority or @target-uri");
    expect(calls).toBe(0);
  });

  it("rejects parameter failures before invoking the consumer verifier", async () => {
    let calls = 0;
    const valid = await signed(["@target-uri"]);
    const message = {
      ...valid,
      headers: {
        ...valid.headers,
        "signature-input": valid.headers["signature-input"].replace(
          ';tag="web-bot-auth"',
          ""
        ),
      },
    };
    await expect(
      vNext.verify(message, {
        keyid: "test-key",
        alg: "ed25519",
        verify: () => {
          calls += 1;
          return true;
        },
      })
    ).rejects.toThrow("tag MUST be defined");
    expect(calls).toBe(0);
  });

  it("rejects empty signatures before invoking the consumer verifier", async () => {
    let calls = 0;
    const valid = await signed(["@target-uri"]);
    await expect(
      vNext.verify(
        {
          ...valid,
          headers: { ...valid.headers, signature: "sig1=::" },
        },
        {
          keyid: "test-key",
          alg: "ed25519",
          verify: () => {
            calls += 1;
            return true;
          },
        }
      )
    ).rejects.toThrow("Signature bytes must not be empty");
    expect(calls).toBe(0);
  });

  it("authenticates mutations of the target Signature-Agent header", async () => {
    let signedData = "";
    const headers = { "signature-agent": 'sig1="https://example.com/agent"' };
    const now = new Date();
    const fields = await vNext.signatureHeaders(
      { method: "GET", url: "https://example.com/path", headers },
      {
        keyid: "test-key",
        alg: "ed25519",
        sign(data) {
          signedData = data;
          return new Uint8Array([1, 2, 3]);
        },
      },
      {
        created: now,
        expires: new Date(now.getTime() + 60_000),
        components: ["@target-uri", signatureAgentComponent()],
      }
    );
    await expect(
      vNext.verify(
        {
          method: "GET",
          url: "https://example.com/path",
          headers: {
            "signature-agent": 'sig1="https://example.com/other"',
            signature: fields.Signature,
            "signature-input": fields["Signature-Input"],
          },
        },
        {
          keyid: "test-key",
          alg: "ed25519",
          verify: (data) => {
            if (data !== signedData) throw new Error("signature mismatch");
            return true;
          },
        }
      )
    ).rejects.toThrow("Failed to verify HTTP message signature");
  });
});
