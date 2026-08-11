import { describe, expect, it } from "vitest";

import {
  webCryptoProvider,
  webCryptoSigningProvider,
  webCryptoVerificationProvider,
} from "../src/webcrypto";
import type { Algorithm } from "../src/types";

interface KeyPair {
  readonly signing: CryptoKey;
  readonly verification: CryptoKey;
}

async function asymmetric(
  algorithm: RsaHashedKeyGenParams | EcKeyGenParams | AlgorithmIdentifier
): Promise<KeyPair> {
  const generated = await crypto.subtle.generateKey(algorithm, false, [
    "sign",
    "verify",
  ]);
  if (!("privateKey" in generated)) throw new Error("expected key pair");
  return { signing: generated.privateKey, verification: generated.publicKey };
}

function keys(algorithm: Algorithm): Promise<KeyPair> {
  switch (algorithm) {
    case "rsa-pss-sha512":
      return asymmetric({
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-512",
      });
    case "rsa-v1_5-sha256":
      return asymmetric({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      });
    case "hmac-sha256":
      return crypto.subtle
        .generateKey({ name: "HMAC", hash: "SHA-256" }, false, [
          "sign",
          "verify",
        ])
        .then((key) => {
          if ("privateKey" in key) throw new Error("expected secret key");
          return { signing: key, verification: key };
        });
    case "ecdsa-p256-sha256":
      return asymmetric({ name: "ECDSA", namedCurve: "P-256" });
    case "ecdsa-p384-sha384":
      return asymmetric({ name: "ECDSA", namedCurve: "P-384" });
    case "ed25519":
      return asymmetric("Ed25519");
  }
}

const algorithms: readonly Algorithm[] = [
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
  "hmac-sha256",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ed25519",
];

describe("WebCrypto algorithm providers", () => {
  it.each(algorithms)("roundtrips %s", async (algorithm) => {
    const { signing, verification } = await keys(algorithm);
    const provider = webCryptoProvider(algorithm, signing, verification);
    const data = new TextEncoder().encode("RFC 9421");
    const signature = await provider.sign(data);
    await expect(provider.verify(data, signature)).resolves.toBe(true);
    await expect(
      provider.verify(new TextEncoder().encode("modified"), signature)
    ).resolves.toBe(false);
  });

  it("rejects algorithm/key inconsistency", async () => {
    const { signing, verification } = await keys("ed25519");
    expect(() =>
      webCryptoProvider("rsa-pss-sha512", signing, verification)
    ).toThrow("inconsistent");
  });

  it("supports private-only signing and public-only verification", async () => {
    const { signing, verification } = await keys("ed25519");
    const signer = webCryptoSigningProvider("ed25519", signing);
    const verifier = webCryptoVerificationProvider("ed25519", verification);
    const data = new TextEncoder().encode("operation-specific keys");
    const signature = await signer.sign(data);
    await expect(verifier.verify(data, signature)).resolves.toBe(true);
  });

  it("rejects operation/key usage mismatch", async () => {
    const { signing, verification } = await keys("ed25519");
    expect(() => webCryptoSigningProvider("ed25519", verification)).toThrow(
      "cannot sign"
    );
    expect(() => webCryptoVerificationProvider("ed25519", signing)).toThrow(
      "cannot verify"
    );
  });
});
