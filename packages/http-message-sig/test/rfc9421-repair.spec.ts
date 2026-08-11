import { describe, expect, it, vi } from "vitest";

import {
  appendSignature,
  appendAcceptSignature,
  buildSignatureBase,
  componentValue,
  parseSignatureFields,
  parseAcceptSignatureField,
  parseSignatureInputField,
  selectAcceptSignature,
  serializeSignatureParams,
  snapshotMessage,
  signMessage,
  verifyMessageSignatures,
  type FieldOccurrence,
  type HttpRequest,
  type CoveredComponent,
  type SignatureFields,
  type SignatureInput,
  type SigningAlgorithmProvider,
  type VerificationAlgorithmProvider,
} from "../src/rfc9421";
import type { SfParameter } from "../src/structured-fields";

const request: HttpRequest = {
  kind: "request",
  method: "GET",
  targetUri: "https://EXAMPLE.com:0443/a/../b/%2e%2E?q=a%2Fb+x",
  fields: [],
};

const inputWithoutAlgorithm: SignatureInput = {
  label: "sig1",
  components: [{ name: "@method", parameters: [] }],
  parameters: [{ name: "keyid", value: { type: "string", value: "key" } }],
};

const signingProvider: SigningAlgorithmProvider = {
  algorithm: "ed25519",
  sign: () => new Uint8Array([1, 2, 3]),
};

const verificationProvider: VerificationAlgorithmProvider = {
  algorithm: "ed25519",
  verify: (_data, signature) => signature[0] === 1,
};

describe("RFC 9421 repair regressions", () => {
  it("derives components from raw target URI text", () => {
    expect(
      componentValue(request, { name: "@authority", parameters: [] })
    ).toBe("example.com");
    expect(componentValue(request, { name: "@scheme", parameters: [] })).toBe(
      "https"
    );
    expect(componentValue(request, { name: "@path", parameters: [] })).toBe(
      "/a/../b/%2e%2E"
    );
    expect(
      componentValue(request, { name: "@request-target", parameters: [] })
    ).toBe("/a/../b/%2e%2E?q=a%2Fb+x");
    expect(componentValue(request, { name: "@query", parameters: [] })).toBe(
      "?q=a%2Fb+x"
    );
    expect(
      componentValue(request, {
        name: "@query-param",
        parameters: [{ name: "name", value: { type: "string", value: "q" } }],
      })
    ).toBe("a%2Fb%20x");
  });

  it("preserves target URI percent encoding and rejects fragments", () => {
    expect(
      componentValue(request, { name: "@target-uri", parameters: [] })
    ).toBe(request.targetUri);
    expect(() =>
      buildSignatureBase(
        { ...request, targetUri: "https://example.com/a#fragment" },
        [{ name: "@method", parameters: [] }],
        []
      )
    ).toThrow("fragment");
  });

  it.each([
    ["https://[2001:DB8::1]:443/a/../%2e%2E", "[2001:db8::1]"],
    ["https://[2001:DB8::1]:8443/a", "[2001:db8::1]:8443"],
    ["http://192.0.2.1:80/a", "192.0.2.1"],
    ["http://192.0.2.1:8080/a", "192.0.2.1:8080"],
    ["https://XN--BCHER-KVA.example/a", "xn--bcher-kva.example"],
    ["https://EX%41MPLE.com/a", "ex%41mple.com"],
    ["https://[v1.example]/", "[v1.example]"],
  ])("validates and derives authority from %s", (targetUri, authority) => {
    expect(
      componentValue(
        { ...request, targetUri },
        { name: "@authority", parameters: [] }
      )
    ).toBe(authority);
  });

  it("validates authority without normalizing the raw path", () => {
    const targetUri = "https://[2001:DB8::1]/a/../b/%2e%2E//c";
    expect(
      componentValue(
        { ...request, targetUri },
        { name: "@path", parameters: [] }
      )
    ).toBe("/a/../b/%2e%2E//c");
  });

  it.each([
    "https://[example.com]/",
    "https://[2001:db8::1/",
    "https://[2001:::1]/",
    "https://[v.example]/",
    "https://2001:db8::1/",
    "https://example.com:/",
    "https://example.com:abc/",
    "https://example.com:65536/",
    "https://256.0.0.1/",
    "https://01.2.3.4/",
    "https://example|com/",
    "https://user@example.com/",
  ])("rejects invalid target URI authority %s", (targetUri) => {
    expect(() =>
      componentValue(
        { ...request, targetUri },
        { name: "@authority", parameters: [] }
      )
    ).toThrow();
  });

  it.each([
    ["origin", "GET", "/raw/%2f?q=a+b"],
    ["absolute", "GET", "https://example.com/raw/%2f?q=a+b"],
    ["authority", "CONNECT", "example.com:443"],
    ["asterisk", "OPTIONS", "*"],
  ])("preserves %s-form request targets", (_form, method, requestTarget) => {
    expect(
      componentValue(
        { ...request, method, requestTarget },
        { name: "@request-target", parameters: [] }
      )
    ).toBe(requestTarget);
  });

  it("rejects malformed raw request targets", () => {
    expect(() =>
      componentValue(
        { ...request, requestTarget: "/bad%xx" },
        { name: "@request-target", parameters: [] }
      )
    ).toThrow("percent encoding");
    expect(() =>
      componentValue(
        { ...request, requestTarget: "not-an-authority" },
        { name: "@request-target", parameters: [] }
      )
    ).toThrow("request target form");
  });

  it("validates CONNECT authority-form hosts and ports", () => {
    expect(
      componentValue(
        { ...request, method: "CONNECT", requestTarget: "[2001:DB8::1]:443" },
        { name: "@request-target", parameters: [] }
      )
    ).toBe("[2001:DB8::1]:443");
    for (const requestTarget of [
      "[example.com]:443",
      "[2001:::1]:443",
      "256.0.0.1:443",
      "example.com:65536",
    ]) {
      expect(() =>
        componentValue(
          { ...request, method: "CONNECT", requestTarget },
          { name: "@request-target", parameters: [] }
        )
      ).toThrow();
    }
  });

  it.each([
    ["GET", "example.com:443"],
    ["CONNECT", "/tunnel"],
    ["CONNECT", "https://example.com/"],
    ["GET", "*"],
    ["POST", "*"],
  ])("rejects %s with request target %s", (method, requestTarget) => {
    expect(() =>
      componentValue(
        { ...request, method, requestTarget },
        { name: "@request-target", parameters: [] }
      )
    ).toThrow();
  });

  it("encodes bs components from HTTP bytes, not UTF-8 text", () => {
    expect(
      componentValue(
        { ...request, fields: [{ name: "x-value", value: "é" }] },
        {
          name: "x-value",
          parameters: [{ name: "bs", value: { type: "boolean", value: true } }],
        }
      )
    ).toBe(":6Q==:");
    expect(
      componentValue(
        {
          ...request,
          fields: [
            {
              name: "x-value",
              value: "display value",
              bytes: new Uint8Array([0, 255]),
            },
          ],
        },
        {
          name: "x-value",
          parameters: [{ name: "bs", value: { type: "boolean", value: true } }],
        }
      )
    ).toBe(":AP8=:");
  });

  it("normalizes OWS and obs-fold before bs encoding", () => {
    const component: CoveredComponent = {
      name: "x-value",
      parameters: [{ name: "bs", value: { type: "boolean", value: true } }],
    };
    expect(
      componentValue(
        {
          ...request,
          fields: [{ name: "x-value", value: " \tfoo\r\n\tbar\t " }],
        },
        component
      )
    ).toBe(":Zm9vIGJhcg==:");
    expect(
      componentValue(
        {
          ...request,
          fields: [
            {
              name: "x-value",
              value: "ignored",
              bytes: new Uint8Array([
                0x20, 0x09, 0xe9, 0x0d, 0x0a, 0x09, 0xff, 0x09,
              ]),
            },
          ],
        },
        component
      )
    ).toBe(":6SD/:");
  });

  it("normalizes structured field occurrences before sf and key parsing", () => {
    const message: HttpRequest = {
      ...request,
      fields: [
        {
          name: "example-dict",
          value: "\t key=value \t",
          structuredType: "dictionary",
        },
        {
          name: "example-list",
          value: "\t token;flag \t",
          structuredType: "list",
        },
      ],
    };
    expect(
      componentValue(message, {
        name: "example-dict",
        parameters: [{ name: "sf", value: { type: "boolean", value: true } }],
      })
    ).toBe("key=value");
    expect(
      componentValue(message, {
        name: "example-dict",
        parameters: [{ name: "key", value: { type: "string", value: "key" } }],
      })
    ).toBe("value");
    expect(
      componentValue(message, {
        name: "example-list",
        parameters: [{ name: "sf", value: { type: "boolean", value: true } }],
      })
    ).toBe("token;flag");
  });

  it("allows bare created/expires only in Accept-Signature", () => {
    const source = 'sig1=("@method");created;expires';
    const parsed = parseAcceptSignatureField(source);
    expect(parsed[0]?.parameters).toEqual([
      { name: "created", value: { type: "boolean", value: true } },
      { name: "expires", value: { type: "boolean", value: true } },
    ]);
    expect(() => parseSignatureInputField(source)).toThrow(
      "created must be integer"
    );
    const input = parsed[0];
    if (input === undefined) throw new Error("missing Accept-Signature input");
    const appended = appendAcceptSignature(undefined, input);
    expect(parseAcceptSignatureField(appended)).toEqual(parsed);
    expect(() =>
      appendSignature(undefined, input, new Uint8Array([1]))
    ).toThrow("created must be integer");
    expect(() =>
      parseAcceptSignatureField('sig1=("@method");created=1')
    ).toThrow("bare true");
    expect(() =>
      parseAcceptSignatureField('sig1=("@method");expires=?0')
    ).toThrow("bare true");
  });

  it("allows CONNECT authority coverage without a request target", () => {
    expect(
      buildSignatureBase(
        { ...request, method: "CONNECT", targetUri: "https://example.com/" },
        [{ name: "@authority", parameters: [] }],
        []
      )
    ).toContain('"@authority": example.com');
  });

  it("rejects empty signature sets", () => {
    expect(() =>
      parseSignatureFields({ signatureInput: "", signature: "" })
    ).toThrow("empty");
  });

  it("allows an omitted alg and derives it from providers", async () => {
    const fields = await signMessage(
      request,
      inputWithoutAlgorithm,
      signingProvider
    );
    await expect(
      verifyMessageSignatures(request, fields, () => verificationProvider)
    ).resolves.toEqual(["sig1"]);
  });

  it.each([
    ["created", 8_640_000_000_001],
    ["created", -999_999_999_999_999],
    ["expires", 999_999_999_999_999],
    ["expires", -8_640_000_000_001],
  ])(
    "rejects unrepresentable %s before the signer callback",
    async (name, value) => {
      let calls = 0;
      const invalidInput: SignatureInput = {
        ...inputWithoutAlgorithm,
        parameters: [{ name, value: { type: "integer", value } }],
      };
      await expect(
        signMessage(request, invalidInput, {
          algorithm: "ed25519",
          sign() {
            calls += 1;
            return new Uint8Array([1]);
          },
        })
      ).rejects.toThrow(`${name} timestamp is outside JavaScript Date range`);
      expect(calls).toBe(0);
      expect(() =>
        appendSignature(undefined, invalidInput, new Uint8Array([1]))
      ).toThrow(`${name} timestamp is outside JavaScript Date range`);
    }
  );

  it("rejects unresolved requested timestamps before signing", async () => {
    const requested = selectAcceptSignature(
      'sig1=("@method");created;expires',
      "sig1"
    );
    let calls = 0;
    await expect(
      signMessage(request, requested, {
        algorithm: "ed25519",
        sign() {
          calls += 1;
          return new Uint8Array([1]);
        },
      })
    ).rejects.toThrow("created must be integer");
    expect(calls).toBe(0);
  });

  it("signs and verifies representable requested timestamp boundaries", async () => {
    const requested = selectAcceptSignature(
      'sig1=("@method");created;expires',
      "sig1"
    );
    const resolved: SignatureInput = {
      ...requested,
      parameters: [
        {
          name: "created",
          value: { type: "integer", value: -8_640_000_000_000 },
        },
        {
          name: "expires",
          value: { type: "integer", value: 8_640_000_000_000 },
        },
      ],
    };
    let signerCalls = 0;
    const fields = await signMessage(request, resolved, {
      algorithm: "ed25519",
      sign() {
        signerCalls += 1;
        return new Uint8Array([1]);
      },
    });
    await expect(
      verifyMessageSignatures(request, fields, () => verificationProvider)
    ).resolves.toEqual(["sig1"]);
    expect(signerCalls).toBe(1);
  });

  it("rejects unrepresentable existing timestamps before signing", async () => {
    let calls = 0;
    await expect(
      signMessage(
        request,
        inputWithoutAlgorithm,
        {
          algorithm: "ed25519",
          sign() {
            calls += 1;
            return new Uint8Array([1]);
          },
        },
        {
          signatureInput: 'old=("@method");created=999999999999999',
          signature: "old=:AQ==:",
        }
      )
    ).rejects.toThrow("created timestamp is outside JavaScript Date range");
    expect(calls).toBe(0);
  });

  it("copies explicit field bytes before asynchronous verification", async () => {
    const bytes = new Uint8Array([0xe9]);
    const message: HttpRequest = {
      ...request,
      fields: [{ name: "x-value", value: "é", bytes }],
    };
    const input: SignatureInput = {
      label: "sig1",
      components: [
        {
          name: "x-value",
          parameters: [{ name: "bs", value: { type: "boolean", value: true } }],
        },
      ],
      parameters: [],
    };
    const fields = await signMessage(message, input, signingProvider);
    await expect(
      verifyMessageSignatures(message, fields, async () => {
        bytes[0] = 0;
        return verificationProvider;
      })
    ).resolves.toEqual(["sig1"]);
  });

  it("precomputes bases before exposing immutable metadata", async () => {
    const custom = new Uint8Array([1, 2]);
    let signedBase = new Uint8Array();
    const input: SignatureInput = {
      label: "sig1",
      components: [{ name: "@method", parameters: [] }],
      parameters: [{ name: "custom", value: { type: "bytes", value: custom } }],
    };
    const fields = await signMessage(request, input, {
      algorithm: "ed25519",
      sign(data) {
        signedBase = data.slice();
        custom[0] = 9;
        return new Uint8Array([1]);
      },
    });
    await expect(
      verifyMessageSignatures(
        request,
        fields,
        (exposed) => {
          const parameter = exposed.parameters[0];
          if (parameter?.value.type === "bytes") {
            expect(parameter.value.value[0]).toBe(1);
            parameter.value.value[0] = 7;
          }
          return {
            algorithm: "ed25519",
            verify: (data) =>
              data.length === signedBase.length &&
              data.every((byte, index) => byte === signedBase[index]),
          };
        },
        {
          beforeCrypto(exposed) {
            expect(Object.isFrozen(exposed)).toBe(true);
            expect(Object.isFrozen(exposed.components)).toBe(true);
            expect(Reflect.deleteProperty(exposed, "label")).toBe(false);
            const parameter = exposed.parameters[0];
            if (parameter?.value.type === "bytes") parameter.value.value[0] = 8;
          },
          afterCrypto(exposed) {
            const parameter = exposed.parameters[0];
            if (parameter?.value.type === "bytes")
              expect(parameter.value.value[0]).toBe(1);
          },
        }
      )
    ).resolves.toEqual(["sig1"]);
  });

  it("rejects oversized snapshots before copying bytes or reading fields", async () => {
    let copies = 0;
    class TrackedBytes extends Uint8Array {
      override slice(start?: number, end?: number): Uint8Array<ArrayBuffer> {
        copies += 1;
        return super.slice(start, end);
      }
    }
    expect(() =>
      snapshotMessage(
        {
          ...request,
          fields: [{ name: "x", value: "", bytes: new TrackedBytes(64) }],
        },
        { maxFieldBytes: 8 }
      )
    ).toThrow("field byte limit");
    expect(copies).toBe(0);

    const logicalBytes = new Proxy(new Uint8Array([1]), {
      get(target, property) {
        if (property === "length") return Number.MAX_SAFE_INTEGER;
        if (property === "slice") copies += 1;
        return Reflect.get(target, property, target);
      },
    });
    expect(() =>
      snapshotMessage(
        {
          ...request,
          fields: [{ name: "x", value: "small", bytes: logicalBytes }],
        },
        { maxFieldBytes: 128 }
      )
    ).toThrow("field byte limit");
    expect(copies).toBe(0);

    expect(() =>
      snapshotMessage(
        {
          ...request,
          fields: [
            { name: "x", value: "x".repeat(64), bytes: new TrackedBytes(1) },
          ],
        },
        { maxFieldBytes: 32 }
      )
    ).toThrow("field byte limit");
    expect(copies).toBe(0);

    await expect(
      signMessage(
        request,
        {
          label: "sig1",
          components: [{ name: "@method", parameters: [] }],
          parameters: [
            {
              name: "large",
              value: { type: "bytes", value: new TrackedBytes(64) },
            },
          ],
        },
        signingProvider,
        undefined,
        { limits: { maxSignatureInputBytes: 8 } }
      )
    ).rejects.toThrow("Signature-Input byte limit");
    expect(copies).toBe(0);

    let reads = 0;
    const observed = {
      get name(): string {
        reads += 1;
        return "x";
      },
      value: "value",
    };
    const logicalFields = new Proxy([observed], {
      get(target, property) {
        if (property === "length") return Number.MAX_SAFE_INTEGER;
        return Reflect.get(target, property, target);
      },
    });
    expect(() =>
      snapshotMessage(
        { ...request, fields: logicalFields },
        { maxFieldOccurrences: 1 }
      )
    ).toThrow("field occurrence limit");
    expect(reads).toBe(0);
    expect(() =>
      snapshotMessage(
        { ...request, fields: [observed, observed] },
        { maxFieldOccurrences: 1 }
      )
    ).toThrow("field occurrence limit");
    expect(reads).toBe(0);
  });

  it("rejects sparse field arrays before copying", () => {
    const sparse: FieldOccurrence[] = [];
    sparse.length = 2;
    sparse[1] = { name: "x", value: "value" };
    expect(() => snapshotMessage({ ...request, fields: sparse })).toThrow(
      "sparse array"
    );
  });

  it("bounds target URIs and signature bases", () => {
    expect(() => snapshotMessage(request, { maxTargetUriBytes: 8 })).toThrow(
      "target URI byte limit"
    );
    expect(() =>
      buildSignatureBase(
        {
          ...request,
          fields: [{ name: "x", value: "x".repeat(128) }],
        },
        [{ name: "x", parameters: [] }],
        [],
        { limits: { maxSignatureBaseBytes: 32 } }
      )
    ).toThrow("signature base byte limit");
  });

  it("does not build later signature bases before earlier callbacks", async () => {
    let fields = appendSignature(
      undefined,
      {
        label: "first",
        components: [{ name: "@method", parameters: [] }],
        parameters: [],
      },
      new Uint8Array([1])
    );
    fields = appendSignature(
      fields,
      {
        label: "second",
        components: [{ name: "x-missing", parameters: [] }],
        parameters: [],
      },
      new Uint8Array([1])
    );
    await expect(
      verifyMessageSignatures(request, fields, () => verificationProvider, {
        beforeCrypto() {
          throw new Error("stop after first base");
        },
      })
    ).rejects.toThrow("stop after first base");
  });

  it.each([
    ["created", 999_999_999_999_999],
    ["created", -999_999_999_999_999],
    ["expires", 8_640_000_000_001],
    ["expires", -8_640_000_000_001],
  ])(
    "rejects unrepresentable %s before vNext policy and provider callbacks",
    async (name, value) => {
      const fields: SignatureFields = {
        signatureInput: `sig1=("@method");${name}=${value}`,
        signature: "sig1=:AQ==:",
      };
      let policyCalls = 0;
      let providerCalls = 0;
      await expect(
        verifyMessageSignatures(
          request,
          fields,
          () => {
            providerCalls += 1;
            return verificationProvider;
          },
          {
            beforeCrypto() {
              policyCalls += 1;
            },
          }
        )
      ).rejects.toThrow(`${name} timestamp is outside JavaScript Date range`);
      expect({ policyCalls, providerCalls }).toEqual({
        policyCalls: 0,
        providerCalls: 0,
      });
    }
  );

  it("accepts representable vNext timestamp boundaries", async () => {
    const fields = appendSignature(
      undefined,
      {
        label: "sig1",
        components: [{ name: "@method", parameters: [] }],
        parameters: [
          {
            name: "created",
            value: { type: "integer", value: -8_640_000_000_000 },
          },
          {
            name: "expires",
            value: { type: "integer", value: 8_640_000_000_000 },
          },
        ],
      },
      new Uint8Array([1])
    );
    let policyCalls = 0;
    await expect(
      verifyMessageSignatures(request, fields, () => verificationProvider, {
        beforeCrypto() {
          policyCalls += 1;
        },
      })
    ).resolves.toEqual(["sig1"]);
    expect(policyCalls).toBe(1);
  });

  it("rejects a declared algorithm mismatch", async () => {
    const input: SignatureInput = {
      ...inputWithoutAlgorithm,
      parameters: [
        ...inputWithoutAlgorithm.parameters,
        { name: "alg", value: { type: "string", value: "hmac-sha256" } },
      ],
    };
    await expect(signMessage(request, input, signingProvider)).rejects.toThrow(
      "mismatch"
    );
  });

  it.each([1, 2, 4, 8, 16, 32])(
    "parses and compares %i signatures with one field read",
    async (count) => {
      let generated: SignatureFields | undefined;
      for (let index = 0; index < count; index += 1) {
        generated = appendSignature(
          generated,
          {
            label: `sig${index}`,
            components: [{ name: "@method", parameters: [] }],
            parameters: [],
          },
          new Uint8Array([1])
        );
      }
      if (generated === undefined) throw new Error("missing generated fields");
      let signatureReads = 0;
      let inputReads = 0;
      const observed: SignatureFields = {
        get signature() {
          signatureReads += 1;
          return generated.signature;
        },
        get signatureInput() {
          inputReads += 1;
          return generated.signatureInput;
        },
      };
      let providerCalls = 0;
      await expect(
        verifyMessageSignatures(request, observed, () => {
          providerCalls += 1;
          return verificationProvider;
        })
      ).resolves.toHaveLength(count);
      expect({ signatureReads, inputReads, providerCalls }).toEqual({
        signatureReads: 1,
        inputReads: 1,
        providerCalls: count,
      });
    }
  );

  it("enforces configurable signature, component, and field limits", () => {
    expect(() =>
      parseSignatureFields(
        { signatureInput: 'a=("@method")', signature: "a=:AQ==:" },
        "rfc9421",
        { maxSignatureInputBytes: 4 }
      )
    ).toThrow("byte limit");
    expect(() =>
      parseSignatureFields(
        { signatureInput: 'a=("@method" "@path")', signature: "a=:AQ==:" },
        "rfc9421",
        { maxComponentsPerSignature: 1 }
      )
    ).toThrow("component limit");
    expect(() =>
      parseSignatureFields(
        {
          signatureInput: 'a=("@method"), b=("@path")',
          signature: "a=:AQ==:, b=:Ag==:",
        },
        "rfc9421",
        { maxSignatures: 1 }
      )
    ).toThrow("signature count limit");
    expect(() =>
      buildSignatureBase(
        {
          ...request,
          fields: [
            { name: "x-a", value: "1" },
            { name: "x-b", value: "2" },
          ],
        },
        [{ name: "@method", parameters: [] }],
        [],
        { limits: { maxFieldOccurrences: 1 } }
      )
    ).toThrow("field occurrence limit");
  });

  it("threads raised limits through parsing and serialization", () => {
    const components = Array.from(
      { length: 65 },
      (_, index) => `"x-${index}"`
    ).join(" ");
    const source = `a=(${components})`;
    expect(() => parseSignatureInputField(source)).toThrow("component limit");
    expect(
      parseSignatureInputField(source, "rfc9421", {
        maxComponentsPerSignature: 65,
      })[0]?.components
    ).toHaveLength(65);

    const large = `a=("@method");nonce="${"x".repeat(66_000)}"`;
    expect(() => parseSignatureInputField(large)).toThrow("byte limit");
    expect(
      parseSignatureInputField(large, "rfc9421", {
        maxSignatureInputBytes: 70_000,
      })
    ).toHaveLength(1);

    const parameters: SfParameter[] = Array.from(
      { length: 33 },
      (_, index) => ({
        name: `custom${index}`,
        value: { type: "boolean", value: true },
      })
    );
    expect(() => serializeSignatureParams([], parameters)).toThrow(
      "signature parameter limit"
    );
    expect(
      serializeSignatureParams([], parameters, "rfc9421", {
        maxParametersPerSignature: 33,
      })
    ).toContain(";custom32");
  });

  it("rejects uppercase field component names in strict parsing", () => {
    expect(() => parseSignatureInputField('a=("Content-Type")')).toThrow(
      "lowercase"
    );
    expect(parseSignatureInputField('a=("content-type")')).toHaveLength(1);
  });

  it("rejects code-unit oversize before UTF-8 scanning", () => {
    const scan = vi.spyOn(String.prototype, "charCodeAt");
    try {
      expect(() =>
        parseSignatureInputField("x".repeat(1_000_000), "rfc9421", {
          maxSignatureInputBytes: 16,
        })
      ).toThrow("byte limit");
      expect(scan).not.toHaveBeenCalled();
    } finally {
      scan.mockRestore();
    }
  });
});
