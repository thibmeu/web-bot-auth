import { describe, expect, it } from "vitest";

import {
  VerificationError,
  createSignature,
  createSignatureSync,
  date,
  getSignatures,
  verify,
} from "../src";
import { crossRealmDate } from "./cross-realm-date.mjs";

const message = {
  method: "GET",
  url: "https://example.com/",
  headers: {
    "signature-input": 'sig1=("@method");alg="ed25519";keyid="key-1"',
    signature: "sig1=:AQID:",
  },
};

const policy = {
  requiredComponents: [],
  requiredParameters: ["keyid"],
  algorithms: ["ed25519"],
};

describe("root API", () => {
  it("rejects empty signatures", async () => {
    await expect(
      createSignature(
        { method: "GET", url: "https://example.com/", headers: {} },
        {
          components: ["@method"],
          signer: () => ({ alg: "ed25519", sign: () => new Uint8Array() }),
        }
      )
    ).rejects.toThrow("Signature bytes must not be empty");
  });

  it("uses the same default created timestamp for sync and async signing", async () => {
    const unsigned = {
      method: "GET",
      url: "https://example.com/",
      headers: {},
    };
    const now = new Date("2025-01-01T00:00:00Z");
    let asyncBase: Uint8Array | undefined;
    let syncBase: Uint8Array | undefined;
    const asyncFields = await createSignature(unsigned, {
      components: ["@method"],
      now,
      signer: () => ({
        alg: "ed25519",
        sign(data) {
          asyncBase = data;
          return new Uint8Array([1]);
        },
      }),
    });
    const syncFields = createSignatureSync(unsigned, {
      components: ["@method"],
      now,
      signer: () => ({
        alg: "ed25519",
        sign(data) {
          syncBase = data;
          return new Uint8Array([1]);
        },
      }),
    });

    expect(syncFields.signatureInput).toBe(asyncFields.signatureInput);
    expect(syncBase).toEqual(asyncBase);
    expect(syncFields.parameters).toContainEqual(["created", 1_735_689_600]);
  });

  it("defaults an explicitly undefined sync created parameter", () => {
    const fields = createSignatureSync(
      { method: "GET", url: "https://example.com/", headers: {} },
      {
        components: ["@method"],
        now: 1_735_689_600,
        parameters: [["created", undefined]],
        signer: () => ({
          alg: "ed25519",
          sign: () => new Uint8Array([1]),
        }),
      }
    );

    expect(fields.parameters).toContainEqual(["created", 1_735_689_600]);
  });

  it("accepts a cross-realm Date as the sync clock", () => {
    expect(() =>
      createSignatureSync(
        { method: "GET", url: "https://example.com/", headers: {} },
        {
          components: ["@method"],
          now: crossRealmDate,
          signer: () => ({
            alg: "ed25519",
            sign: () => new Uint8Array([1]),
          }),
        }
      )
    ).not.toThrow();
  });

  it("uses strict RFC 9421 parameters by default", async () => {
    await expect(
      createSignature(
        { method: "GET", url: "https://example.com/", headers: {} },
        {
          components: ["@method"],
          parameters: [["extension", date(1)]],
          signer: () => ({ alg: "ed25519", sign: () => new Uint8Array([1]) }),
        }
      )
    ).rejects.toThrow(
      'date requires signatureInputProfile "rfc9651-extension"'
    );
  });

  it("accepts an explicit RFC 9651 extension profile", () => {
    expect(() =>
      getSignatures(
        {
          method: "GET",
          url: "https://example.com/",
          headers: {
            "signature-input": 'sig1=("@method");extension=@1',
            signature: "sig1=:AQID:",
          },
        },
        "rfc9651-extension"
      )
    ).not.toThrow();
  });

  it("requires a label for multiple signatures", async () => {
    await expect(
      verify(
        {
          method: "GET",
          url: "https://example.com/",
          headers: {
            "signature-input":
              'a=("@method");alg="ed25519";keyid="key-1", b=("@method");alg="ed25519";keyid="key-1"',
            signature: "a=:AQID:, b=:AQID:",
          },
        },
        {
          verifier: () => ({
            alg: "ed25519",
            keyid: "key-1",
            verify: () => true,
          }),
          policy,
        }
      )
    ).rejects.toThrow("label");
  });

  it("binds the claimed keyid to the verifier key", async () => {
    await expect(
      verify(message, {
        verifier: () => ({
          alg: "ed25519",
          keyid: "different-key",
          verify: () => true,
        }),
        policy,
      })
    ).rejects.toMatchObject({ code: "unknown_key" });
  });

  it("binds the claimed algorithm to the verifier algorithm", async () => {
    await expect(
      verify(message, {
        verifier: () => ({
          alg: "rsa-pss-sha512",
          keyid: "key-1",
          verify: () => true,
        }),
        policy: { ...policy, algorithms: ["ed25519", "rsa-pss-sha512"] },
      })
    ).rejects.toMatchObject({ code: "algorithm_unsupported" });
  });

  it("returns authenticated signature metadata", async () => {
    await expect(
      verify(message, {
        verifier: () => ({
          alg: "ed25519",
          keyid: "key-1",
          verify: () => true,
        }),
        policy,
      })
    ).resolves.toMatchObject({
      label: "sig1",
      algorithm: "ed25519",
    });
  });

  it("preserves verifier factory errors", async () => {
    await expect(
      verify(message, {
        verifier: () => {
          throw new VerificationError("unknown_key", "unknown key");
        },
        policy,
      })
    ).rejects.toMatchObject({ code: "unknown_key" });
  });

  it("preserves verifier implementation errors", async () => {
    await expect(
      verify(message, {
        verifier: () => ({
          alg: "ed25519",
          keyid: "key-1",
          verify() {
            throw new VerificationError("policy_rejected", "key revoked");
          },
        }),
        policy,
      })
    ).rejects.toMatchObject({
      code: "policy_rejected",
      message: "key revoked",
    });
  });
});
