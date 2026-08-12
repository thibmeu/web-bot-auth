import type { Algorithm } from "./types";
import type {
  AlgorithmProvider,
  SigningAlgorithmProvider,
  VerificationAlgorithmProvider,
} from "./rfc9421";

function hashName(algorithm: KeyAlgorithm): string | undefined {
  if (!("hash" in algorithm)) return undefined;
  const hash = algorithm.hash;
  return typeof hash === "object" &&
    hash !== null &&
    "name" in hash &&
    typeof hash.name === "string"
    ? hash.name
    : undefined;
}

function curveName(algorithm: KeyAlgorithm): string | undefined {
  if (!("namedCurve" in algorithm)) return undefined;
  return typeof algorithm.namedCurve === "string"
    ? algorithm.namedCurve
    : undefined;
}

function operation(
  algorithm: Algorithm
): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  switch (algorithm) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", saltLength: 64 };
    case "rsa-v1_5-sha256":
      return "RSASSA-PKCS1-v1_5";
    case "hmac-sha256":
      return "HMAC";
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", hash: "SHA-384" };
    case "ed25519":
      return "Ed25519";
  }
}

function keyMatches(key: CryptoKey, algorithm: Algorithm): boolean {
  switch (algorithm) {
    case "rsa-pss-sha512":
      return (
        key.algorithm.name === "RSA-PSS" &&
        hashName(key.algorithm) === "SHA-512"
      );
    case "rsa-v1_5-sha256":
      return (
        key.algorithm.name === "RSASSA-PKCS1-v1_5" &&
        hashName(key.algorithm) === "SHA-256"
      );
    case "hmac-sha256":
      return (
        key.algorithm.name === "HMAC" && hashName(key.algorithm) === "SHA-256"
      );
    case "ecdsa-p256-sha256":
      return (
        key.algorithm.name === "ECDSA" && curveName(key.algorithm) === "P-256"
      );
    case "ecdsa-p384-sha384":
      return (
        key.algorithm.name === "ECDSA" && curveName(key.algorithm) === "P-384"
      );
    case "ed25519":
      return key.algorithm.name === "Ed25519";
  }
}

export function webCryptoKeyAlgorithm(
  key: CryptoKey,
  allowed: readonly Algorithm[] = [
    "rsa-pss-sha512",
    "rsa-v1_5-sha256",
    "hmac-sha256",
    "ecdsa-p256-sha256",
    "ecdsa-p384-sha384",
    "ed25519",
  ]
): Algorithm {
  const algorithm = allowed.find((candidate) => keyMatches(key, candidate));
  if (algorithm === undefined)
    throw new Error("key is inconsistent with supported algorithms");
  return algorithm;
}

export function webCryptoProvider(
  algorithm: Algorithm,
  signingKey: CryptoKey,
  verificationKey: CryptoKey,
  subtle: SubtleCrypto = crypto.subtle
): AlgorithmProvider {
  const signer = webCryptoSigningProvider(algorithm, signingKey, subtle);
  const verifier = webCryptoVerificationProvider(
    algorithm,
    verificationKey,
    subtle
  );
  return {
    algorithm,
    sign: signer.sign,
    verify: verifier.verify,
  };
}

export function webCryptoSigningProvider(
  algorithm: Algorithm,
  key: CryptoKey,
  subtle: SubtleCrypto = crypto.subtle
): SigningAlgorithmProvider {
  if (!keyMatches(key, algorithm))
    throw new Error(`key is inconsistent with ${algorithm}`);
  if (!key.usages.includes("sign")) throw new Error("key cannot sign");
  const parameters = operation(algorithm);
  return {
    algorithm,
    async sign(data) {
      return new Uint8Array(
        await subtle.sign(parameters, key, Uint8Array.from(data))
      );
    },
  };
}

export function webCryptoVerificationProvider(
  algorithm: Algorithm,
  key: CryptoKey,
  subtle: SubtleCrypto = crypto.subtle
): VerificationAlgorithmProvider {
  if (!keyMatches(key, algorithm))
    throw new Error(`key is inconsistent with ${algorithm}`);
  if (!key.usages.includes("verify")) throw new Error("key cannot verify");
  const parameters = operation(algorithm);
  return {
    algorithm,
    verify(data, signature) {
      return subtle.verify(
        parameters,
        key,
        Uint8Array.from(signature),
        Uint8Array.from(data)
      );
    },
  };
}
