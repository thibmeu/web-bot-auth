import { describe, expect, it } from "vitest";
import {
  appendSignature,
  component,
  componentIdentity,
  createSignature,
  createSignatureSync,
  isSignatureError,
  SignatureErrorCode,
  Token,
  verifySignature,
  webcrypto,
  type RequestDescriptor,
  type SignatureFields,
  type SignatureMessage,
  type Verifier,
  type VerificationPolicy,
} from "../src";

const request: RequestDescriptor = {
  kind: "request",
  method: "POST",
  targetUri: "https://example.com/foo?param=Value&Pet=dog",
  requestTarget: "/foo?param=Value&Pet=dog",
  fields: [
    { name: "Host", value: "example.com" },
    { name: "Date", value: "Tue, 20 Apr 2021 02:07:55 GMT" },
    { name: "Content-Type", value: "application/json" },
    {
      name: "Content-Digest",
      value: "sha-512=:U0dWc2JHOGdkMjl5YkdRPTo=: ",
    },
    { name: "Content-Length", value: "18" },
  ],
};

const permittedPolicy: VerificationPolicy = {
  algorithms: ["test-alg"],
  requiredComponents: [],
  requiredParameters: [],
  now: 1_618_884_500,
};

function descriptorWithSignature(
  message: RequestDescriptor,
  fields: SignatureFields
): RequestDescriptor {
  return {
    ...message,
    fields: [
      ...message.fields,
      { name: "Signature", value: fields.signature },
      { name: "Signature-Input", value: fields.signatureInput },
    ],
  };
}

function replacingFields(
  message: RequestDescriptor,
  signature: string,
  signatureInput: string
): RequestDescriptor {
  return {
    ...message,
    fields: [
      ...message.fields.filter(
        ({ name }) =>
          name.toLowerCase() !== "signature" &&
          name.toLowerCase() !== "signature-input"
      ),
      { name: "signature", value: signature },
      { name: "signature-input", value: signatureInput },
    ],
  };
}

async function signed(
  message: SignatureMessage = request,
  components = ["@method", "@authority", "@path", "content-type"]
): Promise<{
  readonly fields: SignatureFields;
  readonly base: Uint8Array;
}> {
  let base = new Uint8Array();
  const fields = await createSignature(message, {
    components,
    parameters: { created: 1_618_884_475, alg: "test-alg", keyid: "key" },
    signer: {
      algorithm: "test-alg",
      sign(data) {
        base = data.slice();
        return new Uint8Array([1, 2, 3]);
      },
    },
  });
  return { fields, base };
}

function verifierFor(expectedBase: Uint8Array): Verifier {
  return {
    algorithm: "test-alg",
    verify(data, signature) {
      expect(data).toEqual(expectedBase);
      expect(signature).toEqual(new Uint8Array([1, 2, 3]));
      return true;
    },
  };
}

describe("createSignature", () => {
  it("builds the applicable RFC 9421 Appendix B request base", async () => {
    let base = "";
    const fields = await createSignature(request, {
      label: "sig-b24",
      components: [
        "@method",
        "@authority",
        "@path",
        "content-digest",
        "content-length",
        "content-type",
      ],
      parameters: { created: 1_618_884_475, keyid: "test-key-rsa-pss" },
      signer: {
        algorithm: "rsa-pss-sha512",
        sign(data) {
          base = new TextDecoder().decode(data);
          return new Uint8Array([1, 2, 3]);
        },
      },
    });

    expect(base).toBe(
      [
        '"@method": POST',
        '"@authority": example.com',
        '"@path": /foo',
        '"content-digest": sha-512=:U0dWc2JHOGdkMjl5YkdRPTo=:',
        '"content-length": 18',
        '"content-type": application/json',
        '"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884475;keyid="test-key-rsa-pss"',
      ].join("\n")
    );
    expect(fields).toEqual({
      signature: "sig-b24=:AQID:",
      signatureInput:
        'sig-b24=("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884475;keyid="test-key-rsa-pss"',
    });
  });

  it("supports native Request observable values", async () => {
    const native = new Request("https://example.com/resource", {
      method: "PATCH",
      headers: { "x-empty": "" },
    });
    let base = "";
    await createSignature(native, {
      components: ["@method", "@target-uri", "x-empty"],
      parameters: {},
      signer: {
        algorithm: "test-alg",
        sign(data) {
          base = new TextDecoder().decode(data);
          return new Uint8Array();
        },
      },
    });
    expect(base).toBe(
      '"@method": PATCH\n"@target-uri": https://example.com/resource\n"x-empty": \n"@signature-params": ("@method" "@target-uri" "x-empty")'
    );
  });

  it("uses the last duplicate Structured Field member and parameter", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        fields: [
          ...request.fields,
          { name: "Example", value: "a=1, a=2, b=3;p=old;p=new" },
        ],
      },
      {
        components: [
          component("example", { key: "a" }),
          component("example", { key: "b" }),
        ],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );

    expect(base).toBe(
      [
        '"example";key="a": 2',
        '"example";key="b": 3;p=new',
        '"@signature-params": ("example";key="a" "example";key="b")',
      ].join("\n")
    );
  });

  it.each(["a=@1, a=2", "a=1;p=@1;p=2", 'a=%"old", a=2'])(
    "rejects overwritten RFC 9651 syntax in %s",
    async (value) => {
      await expect(
        createSignature(
          {
            ...request,
            fields: [...request.fields, { name: "Example", value }],
          },
          {
            components: [component("example", { key: "a" })],
            parameters: {},
            signer: {
              algorithm: "test-alg",
              sign: () => new Uint8Array(),
            },
          }
        )
      ).rejects.toMatchObject({ code: SignatureErrorCode.UnsupportedFeature });
    }
  );

  it("does not confuse RFC 8941 strings and tokens with extensions", async () => {
    await expect(
      createSignature(
        {
          ...request,
          fields: [
            ...request.fields,
            { name: "Example", value: 'a="user@example.com", b=percent%token' },
          ],
        },
        {
          components: [
            component("example", { key: "a" }),
            component("example", { key: "b" }),
          ],
          parameters: {},
          signer: {
            algorithm: "test-alg",
            sign: () => new Uint8Array(),
          },
        }
      )
    ).resolves.toBeDefined();
  });

  it("preserves descriptor method case and uses ? for an absent query", async () => {
    let base = "";
    await createSignature(
      {
        kind: "request",
        method: "cUsToM",
        targetUri: "https://example.com/path",
        fields: [],
      },
      {
        components: ["@method", "@query", "@target-uri"],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"@method": cUsToM');
    expect(base).toContain('"@query": ?');
    expect(base).toContain('"@target-uri": https://example.com/path');
  });

  it("preserves descriptor target URI and request target without normalization", async () => {
    let base = "";
    await createSignature(
      {
        kind: "request",
        method: "GET",
        targetUri: "https://example.com/a/../b/%7e?q=%2f",
        requestTarget: "/a/../b/%7e?q=%2f",
        fields: [],
      },
      {
        components: ["@target-uri", "@path", "@query", "@request-target"],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain(
      '"@target-uri": https://example.com/a/../b/%7e?q=%2f'
    );
    expect(base).toContain('"@path": /a/../b/%7e');
    expect(base).toContain('"@query": ?q=%2f');
    expect(base).toContain('"@request-target": /a/../b/%7e?q=%2f');
  });

  it("rejects @request-target when Fetch cannot provide it", async () => {
    await expect(
      createSignature(new Request("https://example.com/path"), {
        components: ["@request-target"],
        parameters: {},
        signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.UnsupportedFeature });
  });

  it("rejects descriptor injection and invalid status values", async () => {
    await expect(
      createSignature(
        { ...request, fields: [{ name: "x", value: 'ok\n"@method": DELETE' }] },
        {
          components: ["x"],
          parameters: {},
          signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
        }
      )
    ).rejects.toMatchObject({ code: SignatureErrorCode.MalformedField });

    await expect(
      createSignature(
        { kind: "response", status: 42, fields: [] },
        {
          components: ["@status"],
          parameters: {},
          signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
        }
      )
    ).rejects.toMatchObject({ code: SignatureErrorCode.InvalidComponent });
  });

  it("distinguishes an empty field from a missing field", async () => {
    await expect(
      createSignature(request, {
        components: ["x-empty"],
        parameters: {},
        signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.MissingField });

    let base = "not called";
    await createSignature(
      {
        ...request,
        fields: [...request.fields, { name: "x-empty", value: "" }],
      },
      {
        components: ["x-empty"],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"x-empty": \n');
  });

  it("combines ordered field occurrences and selects an SF dictionary member", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        fields: [
          ...request.fields,
          { name: "x-list", value: "first" },
          { name: "X-List", value: "second" },
          { name: "example-dict", value: 'a=1, b=("x" 2);p' },
        ],
      },
      {
        components: ["x-list", component("example-dict", { key: "b" })],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"x-list": first, second');
    expect(base).toContain('"example-dict";key="b": ("x" 2);p');
  });

  it("strictly serializes known Structured Field types", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        fields: [
          ...request.fields,
          {
            name: "example-dict",
            value: "a=1",
            structuredType: "dictionary",
          },
          {
            name: "example-dict",
            value: "b=2;x=1, c=(a   b)",
            structuredType: "dictionary",
          },
          { name: "example-list", value: "a", structuredType: "list" },
          {
            name: "example-list",
            value: '  "b";q=1',
            structuredType: "list",
          },
          { name: "example-item", value: "42; x", structuredType: "item" },
        ],
      },
      {
        components: [
          component("example-dict", { sf: true }),
          component("example-list", { sf: true }),
          component("example-item", { sf: true }),
        ],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"example-dict";sf: a=1, b=2;x=1, c=(a b)');
    expect(base).toContain('"example-list";sf: a, "b";q=1');
    expect(base).toContain('"example-item";sf: 42;x');
  });

  it("uses Structured Field duplicate last-value semantics", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        fields: [
          ...request.fields,
          {
            name: "duplicate-dict",
            value: "a=1, a=2",
            structuredType: "dictionary",
          },
          {
            name: "duplicate-item",
            value: "42;x=1;x=2",
            structuredType: "item",
          },
        ],
      },
      {
        components: [
          component("duplicate-dict", { sf: true }),
          component("duplicate-item", { sf: true }),
        ],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"duplicate-dict";sf: a=2');
    expect(base).toContain('"duplicate-item";sf: 42;x=2');
  });

  it("binary-wraps individual raw field occurrences", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        fields: [
          ...request.fields,
          {
            name: "example-header",
            value: new TextEncoder().encode(" value, with, lots "),
          },
          {
            name: "example-header",
            value: new TextEncoder().encode("of, commas"),
          },
        ],
      },
      {
        components: [component("example-header", { bs: true })],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain(
      '"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:'
    );
  });

  it("selects trailers independently from header fields", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        fields: [...request.fields, { name: "expires", value: "header" }],
        trailers: [{ name: "expires", value: "trailer" }],
      },
      {
        components: ["expires", component("expires", { tr: true })],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"expires": header');
    expect(base).toContain('"expires";tr: trailer');
  });

  it("canonicalizes form query parameters", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        targetUri:
          "https://example.com/path?param=value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A+=something&qux=",
      },
      {
        components: [
          component("@query-param", { name: "bar" }),
          component("@query-param", { name: "fa%C3%A7ade%22%3A%20" }),
          component("@query-param", { name: "qux" }),
        ],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain(
      '"@query-param";name="bar": with%20plus%20whitespace'
    );
    expect(base).toContain(
      '"@query-param";name="fa%C3%A7ade%22%3A%20": something'
    );
    expect(base).toContain('"@query-param";name="qux": \n');
  });

  it("rejects duplicate query parameter names", async () => {
    await expect(
      createSignature(
        { ...request, targetUri: "https://example.com/?a=1&a=2" },
        {
          components: [component("@query-param", { name: "a" })],
          parameters: {},
          signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
        }
      )
    ).rejects.toMatchObject({ code: SignatureErrorCode.InvalidComponent });
  });

  it("uses HTML UTF-8 decoding without stripping BOM", async () => {
    let base = "";
    await createSignature(
      {
        ...request,
        targetUri: "https://example.com/?%EF%BB%BFa=%EF%BB%BFx&invalid=%FF",
      },
      {
        components: [
          component("@query-param", { name: "%EF%BB%BFa" }),
          component("@query-param", { name: "invalid" }),
        ],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"@query-param";name="%EF%BB%BFa": %EF%BB%BFx');
    expect(base).toContain('"@query-param";name="invalid": %EF%BF%BD');
  });

  it("supports response and related request components", async () => {
    let base = "";
    await createSignature(
      {
        kind: "response",
        status: 201,
        fields: [{ name: "content-type", value: "text/plain" }],
        request,
      },
      {
        components: ["@status", component("@authority", { req: true })],
        parameters: {},
        signer: {
          algorithm: "test-alg",
          sign(data) {
            base = new TextDecoder().decode(data);
            return new Uint8Array();
          },
        },
      }
    );
    expect(base).toContain('"@status": 201');
    expect(base).toContain('"@authority";req: example.com');
  });

  it("provides the straightforward synchronous API", () => {
    const result = createSignatureSync(request, {
      components: ["@method"],
      parameters: { alg: "test-alg" },
      signer: { algorithm: "test-alg", sign: () => new Uint8Array([1]) },
    });
    expect(result.signature).toBe("sig1=:AQ==:");
  });

  it("binds a claimed algorithm to the signer", async () => {
    await expect(
      createSignature(request, {
        components: [],
        parameters: { alg: "other" },
        signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.AlgorithmMismatch });
  });
});

describe("webcrypto", () => {
  it("creates algorithm-bound Ed25519 providers", async () => {
    const keys = await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ]);
    const signer = webcrypto.signer(keys.privateKey);
    const verifier = webcrypto.verifier(keys.publicKey);
    const data = new Uint8Array([1, 2, 3]);
    const signature = await signer.sign(data);

    expect(signer.algorithm).toBe("ed25519");
    expect(verifier.algorithm).toBe("ed25519");
    await expect(verifier.verify(data, signature)).resolves.toBe(true);
  });
});

describe("component identities", () => {
  it("returns the exact serialized component identity", () => {
    expect(
      componentIdentity(component("Example", { key: "a", req: true }))
    ).toBe('"example";key="a";req');
  });

  it("rejects equivalent duplicates regardless of parameter order", async () => {
    await expect(
      createSignature(
        {
          kind: "response",
          status: 200,
          fields: [],
          request,
        },
        {
          components: [
            component("x", { key: "a", req: true }),
            component("X", { req: true, key: "a" }),
          ],
          parameters: {},
          signer: { algorithm: "test-alg", sign: () => new Uint8Array() },
        }
      )
    ).rejects.toMatchObject({ code: SignatureErrorCode.DuplicateComponent });
  });

  it("rejects component confusion and unsupported features", () => {
    expect(() => component("@authority", { key: "host" })).toThrowError(
      expect.objectContaining({ code: SignatureErrorCode.InvalidComponent })
    );
    for (const value of [
      () => component("x", { bs: true, sf: true }),
      () => component("x", { name: "a" }),
      () => component("@query-param"),
      () => component("@status", { req: true }),
    ]) {
      expect(value).toThrowError(
        expect.objectContaining({ code: SignatureErrorCode.InvalidComponent })
      );
    }
    expect(() => component("@unknown")).toThrowError(
      expect.objectContaining({ code: SignatureErrorCode.UnsupportedFeature })
    );
  });
});

describe("appendSignature", () => {
  it("clones and merges multiple signatures", async () => {
    const first = await signed();
    const second = await createSignature(request, {
      label: "sig2",
      components: ["@path"],
      parameters: {},
      signer: { algorithm: "test-alg", sign: () => new Uint8Array([4]) },
    });
    const original = new Headers({ untouched: "yes" });
    const once = appendSignature(original, first.fields);
    const twice = appendSignature(once, second);

    expect(original.has("signature")).toBe(false);
    expect(twice.get("signature")).toBe("sig1=:AQID:, sig2=:BA==:");
    expect(twice.get("signature-input")).toContain("sig1=");
    expect(twice.get("signature-input")).toContain("sig2=");
  });

  it("rejects duplicate labels", async () => {
    const value = await signed();
    const headers = appendSignature(new Headers(), value.fields);
    expect(() => appendSignature(headers, value.fields)).toThrowError(
      expect.objectContaining({ code: SignatureErrorCode.DuplicateLabel })
    );
  });

  it("is atomic when an existing dictionary is malformed", async () => {
    const value = await signed();
    const headers = new Headers({
      signature: "sig1=not-bytes",
      "signature-input": 'sig1=("@method")',
    });
    expect(() => appendSignature(headers, value.fields)).toThrowError(
      expect.objectContaining({ code: SignatureErrorCode.MalformedField })
    );
    expect(headers.get("signature")).toBe("sig1=not-bytes");
    expect(headers.get("signature-input")).toBe('sig1=("@method")');
  });
});

describe("verifySignature", () => {
  it("returns authenticated data and the selected verifier", async () => {
    const value = await signed();
    const verifier = verifierFor(value.base);
    const result = await verifySignature(
      descriptorWithSignature(request, value.fields),
      {
        policy: {
          ...permittedPolicy,
          requiredComponents: ["@method", "content-type"],
          requiredParameters: ["created", "keyid"],
          maxAge: 60,
        },
        resolveVerifier(untrustedCandidate, context) {
          expect(untrustedCandidate.label).toBe("sig1");
          expect(untrustedCandidate.algorithm).toBe("test-alg");
          expect(context).toEqual({ now: 1_618_884_500 });
          return verifier;
        },
      }
    );
    expect(result.verifier).toBe(verifier);
    expect(result.label).toBe("sig1");
    expect(result.algorithm).toBe("test-alg");
    expect(result.parameters.keyid).toBe("key");
    expect(result.signature).toEqual(new Uint8Array([1, 2, 3]));
    expect(Object.keys(result)).not.toContain("snapshot");
  });

  it("requires a label for multiple signatures", async () => {
    const first = await signed();
    const second = await createSignature(request, {
      label: "sig2",
      components: ["@path"],
      parameters: { alg: "test-alg" },
      signer: { algorithm: "test-alg", sign: () => new Uint8Array([4]) },
    });
    const headers = appendSignature(
      appendSignature(new Headers(), first.fields),
      second
    );
    const message = {
      ...request,
      fields: [
        ...request.fields,
        { name: "signature", value: headers.get("signature") ?? "" },
        {
          name: "signature-input",
          value: headers.get("signature-input") ?? "",
        },
      ],
    };
    await expect(
      verifySignature(message, {
        policy: permittedPolicy,
        resolveVerifier: () => verifierFor(first.base),
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.LabelRequired });
  });

  it("rejects mismatched label sets even with an explicit common label", async () => {
    const value = await signed();
    const message = replacingFields(
      descriptorWithSignature(request, value.fields),
      `${value.fields.signature}, extra=:BA==:`,
      value.fields.signatureInput
    );
    await expect(
      verifySignature(message, {
        policy: permittedPolicy,
        resolveVerifier: () => verifierFor(value.base),
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.LabelMismatch });

    await expect(
      verifySignature(message, {
        label: "sig1",
        policy: permittedPolicy,
        resolveVerifier: () => verifierFor(value.base),
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.LabelMismatch });
  });

  it("rejects non-lowercase parsed component identifiers", async () => {
    const value = await signed();
    await expect(
      verifySignature(
        replacingFields(
          descriptorWithSignature(request, value.fields),
          value.fields.signature,
          'sig1=("@METHOD");alg="test-alg"'
        ),
        {
          label: "sig1",
          policy: permittedPolicy,
          resolveVerifier: () => verifierFor(value.base),
        }
      )
    ).rejects.toMatchObject({ code: SignatureErrorCode.MalformedField });
  });

  it("strictly rejects duplicate labels, duplicate parameters, and RFC 9651 values", async () => {
    const value = await signed();
    const baseMessage = descriptorWithSignature(request, value.fields);
    for (const message of [
      replacingFields(
        baseMessage,
        "sig1=:AQID:, sig1=:BA==:",
        value.fields.signatureInput
      ),
      replacingFields(
        baseMessage,
        value.fields.signature,
        'sig1=("@method");created=1;created=2;alg="test-alg"'
      ),
      replacingFields(
        baseMessage,
        value.fields.signature,
        'sig1=("@method");created=1;x=@2;alg="test-alg"'
      ),
    ]) {
      await expect(
        verifySignature(message, {
          label: "sig1",
          policy: permittedPolicy,
          resolveVerifier: () => verifierFor(value.base),
        })
      ).rejects.toSatisfy(isSignatureError);
    }
  });

  it("rejects malformed component parameters and equivalent parsed duplicates", async () => {
    const value = await signed();
    for (const signatureInput of [
      'sig1=("@authority";key="host");alg="test-alg"',
      'sig1=("@method";req=?0);alg="test-alg"',
      'sig1=("X";key="a";req "x";req;key="a");alg="test-alg"',
    ]) {
      await expect(
        verifySignature(
          replacingFields(
            descriptorWithSignature(request, value.fields),
            value.fields.signature,
            signatureInput
          ),
          {
            label: "sig1",
            policy: permittedPolicy,
            resolveVerifier: () => verifierFor(value.base),
          }
        )
      ).rejects.toSatisfy(isSignatureError);
    }
  });

  it("binds the claimed algorithm to the selected verifier", async () => {
    const value = await signed();
    await expect(
      verifySignature(descriptorWithSignature(request, value.fields), {
        policy: { ...permittedPolicy, algorithms: ["test-alg", "other"] },
        resolveVerifier: () => ({ algorithm: "other", verify: () => true }),
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.AlgorithmMismatch });
  });

  it("captures message data before awaiting the resolver", async () => {
    const mutableFields: { name: string; value: string }[] = request.fields.map(
      ({ name, value }) => {
        if (value instanceof Uint8Array) throw new Error("expected text field");
        return { name, value };
      }
    );
    const mutableMessage: RequestDescriptor = {
      ...request,
      fields: mutableFields,
    };
    const value = await signed(mutableMessage);
    mutableFields.push(
      { name: "signature", value: value.fields.signature },
      { name: "signature-input", value: value.fields.signatureInput }
    );

    await expect(
      verifySignature(mutableMessage, {
        policy: permittedPolicy,
        async resolveVerifier() {
          mutableFields[2].value = "text/plain";
          await Promise.resolve();
          return verifierFor(value.base);
        },
      })
    ).resolves.toMatchObject({ label: "sig1" });
  });

  it("rejects a false verifier result and does not run validate", async () => {
    const value = await signed();
    let validated = false;
    await expect(
      verifySignature(descriptorWithSignature(request, value.fields), {
        policy: {
          ...permittedPolicy,
          validate() {
            validated = true;
          },
        },
        resolveVerifier: () => ({
          algorithm: "test-alg",
          verify: () => false,
        }),
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.VerificationFailed });
    expect(validated).toBe(false);
  });

  it("enforces timing and coverage before cryptography", async () => {
    const value = await signed();
    let resolved = false;
    await expect(
      verifySignature(descriptorWithSignature(request, value.fields), {
        policy: {
          algorithms: ["test-alg"],
          requiredComponents: ["@status"],
          requiredParameters: ["created"],
          maxAge: 1,
          now: 1_618_884_500,
        },
        resolveVerifier() {
          resolved = true;
          return verifierFor(value.base);
        },
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.PolicyViolation });
    expect(resolved).toBe(false);
  });

  it("runs custom policy validation only after cryptographic success", async () => {
    const value = await signed();
    const order: string[] = [];
    await expect(
      verifySignature(descriptorWithSignature(request, value.fields), {
        policy: {
          ...permittedPolicy,
          validate(authenticated) {
            order.push(`validate:${authenticated.label}`);
            return false;
          },
        },
        resolveVerifier: () => ({
          algorithm: "test-alg",
          verify() {
            order.push("verify");
            return true;
          },
        }),
      })
    ).rejects.toMatchObject({ code: SignatureErrorCode.PolicyViolation });
    expect(order).toEqual(["verify", "validate:sig1"]);
  });

  it("preserves unknown RFC 8941 signature metadata", async () => {
    const value = await createSignature(request, {
      components: ["@method"],
      parameters: {
        alg: "test-alg",
        extension: new Token("custom-token"),
        bytes: new Uint8Array([4, 5]).buffer,
      },
      signer: { algorithm: "test-alg", sign: () => new Uint8Array([1, 2, 3]) },
    });
    const result = await verifySignature(
      descriptorWithSignature(request, value),
      {
        policy: permittedPolicy,
        resolveVerifier: () => ({ algorithm: "test-alg", verify: () => true }),
      }
    );
    expect(String(result.parameters.extension)).toBe("custom-token");
    expect(result.parameters.bytes).toBeInstanceOf(ArrayBuffer);
  });
});
