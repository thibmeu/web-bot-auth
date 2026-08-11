import { describe, expect, it } from "vitest";

import { HeaderValue, RequestLike, ResponseLike, verify, Verify } from "../src";
import { encode as base64Encode } from "../src/base64";

const hash = new Uint8Array([
  227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36,
  39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
]);
const hashBase64 = base64Encode(hash);

const sampleRequestHeaders: Record<string, HeaderValue> = {
  "content-type": "application/json",
  digest: "SHA-256=abcdef",
  signature: `sig1=:${hashBase64}:`,
  "signature-input":
    'sig1=("@method" "@path" "@query" "@authority" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
};
const sampleRequest: RequestLike = {
  method: "POST",
  url: "https://example.com/path?query=string",
  headers: sampleRequestHeaders,
};
const sampleResponse: ResponseLike = {
  status: 200,
  headers: {
    "content-type": "text/plain",
    "x-Total": "200",
    digest: "SHA-256=abcdef",
    signature: `sig1=:${hashBase64}:`,
    "signature-input":
      'sig1=("@status" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
  },
};

describe("verify", () => {
  it("returns a rejected Promise for preprocessing errors", async () => {
    const result = verify({ ...sampleRequest, headers: {} }, () => "unused");
    expect(result).toBeInstanceOf(Promise);
    await expect(result).rejects.toThrow("Signature-Input");
  });

  describe("request", () => {
    const expectedData = [
      '"@method": POST',
      '"@path": /path',
      '"@query": ?query=string',
      '"@authority": example.com',
      '"content-type": application/json',
      '"digest": SHA-256=abcdef',
      '"@signature-params": ("@method" "@path" "@query" "@authority" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
    ].join("\n");

    const verifySignature: Verify<string> = async (data, signature, params) => {
      expect(data).to.equal(expectedData);
      expect(signature).to.deep.equal(hash);
      expect(params).to.deep.equal({
        alg: "hmac-sha256",
        keyid: "test-key",
        created: new Date(1681004344 * 1000),
      });
      return "success";
    };

    it("should verify a request", async () => {
      const result = await verify(sampleRequest, verifySignature);
      expect(result).to.eq("success");
    });

    it("rejects a declared algorithm that conflicts with the verifier", async () => {
      let calls = 0;
      const metadata: Pick<Verify<void>, "alg"> = { alg: "ed25519" };
      const verifier: Verify<void> = Object.assign(() => {
        calls += 1;
      }, metadata);

      await expect(verify(sampleRequest, verifier)).rejects.toThrow(
        "hmac-sha256 does not match verifier algorithm ed25519"
      );
      expect(calls).toBe(0);
    });

    it("should throw an error if the request is not signed", async () => {
      delete sampleRequestHeaders.signature;

      try {
        await verify(sampleRequest, verifySignature);
        expect.fail("Expected an error to be thrown");
      } catch (err) {
        expect(err instanceof Error ? err.message : String(err)).to.eq(
          "Message does not contain Signature header"
        );
      }
    });

    it("should throw an error on a key mismatch", async () => {
      sampleRequestHeaders.signature = `sig2=:${hashBase64}:`;

      try {
        await verify(sampleRequest, verifySignature);
        expect.fail("Expected an error to be thrown");
      } catch (err) {
        expect(err instanceof Error ? err.message : String(err)).to.eq(
          "Invalid Signature header. Key mismatch sig2 !== sig1"
        );
      }
    });

    it("should throw an error if Signature-Input header is missing", async () => {
      delete sampleRequestHeaders["signature-input"];

      try {
        await verify(sampleRequest, verifySignature);
        expect.fail("Expected an error to be thrown");
      } catch (err) {
        expect(err instanceof Error ? err.message : String(err)).to.eq(
          "Message does not contain Signature-Input header"
        );
      }
    });
  });

  describe("response", () => {
    const verifySignature: Verify<string> = async (_, signature, params) => {
      expect(signature).to.deep.equal(hash);
      expect(params).to.deep.equal({
        alg: "hmac-sha256",
        keyid: "test-key",
        created: new Date(1681004344 * 1000),
      });
      return "success";
    };

    it("should verify a response", async () => {
      const result = await verify(sampleResponse, verifySignature);
      expect(result).to.eq("success");
    });
  });
});
