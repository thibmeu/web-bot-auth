import {
  Component,
  Parameters,
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
  SignatureHeaders,
  SignOptions,
  SignSyncOptions,
} from "./types";
import {
  buildSignatureInputString,
  buildSignedData,
  resolveMessageKind,
  validateMessageRequestTarget,
} from "./build";
import { encode as base64Encode } from "./base64";
import {
  boundedUtf8ByteLength,
  resolveSignatureLimits,
  type SignatureLimits,
} from "./rfc9421";

const defaultRequestComponents: Component[] = [
  "@method",
  "@path",
  "@query",
  "@authority",
  "content-type",
  "digest",
];

const defaultResponseComponents: Component[] = [
  "@status",
  "content-type",
  "digest",
];

function isTaggable(
  value: object
): value is { [Symbol.toStringTag]: () => string } {
  return (
    Symbol.toStringTag in value &&
    typeof value[Symbol.toStringTag] === "function"
  );
}

function addParameters(
  target: Parameters,
  values: Readonly<Record<string, unknown>>
): void {
  for (const [name, value] of Object.entries(values)) {
    if (value === undefined) continue;
    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value instanceof Date ||
      value instanceof Uint8Array ||
      (typeof value === "object" && value !== null && isTaggable(value))
    ) {
      target[name] = value;
      continue;
    }
    throw new Error(`Invalid signature parameter ${name}`);
  }
}

function signatureField(
  key: string,
  signature: Uint8Array,
  limits: SignatureLimits
): string {
  if (signature.length > limits.maxSignatureBytes)
    throw new Error("Signature byte limit exceeded");
  const encodedBytes = Math.ceil(signature.length / 3) * 4;
  const keyBudget = limits.maxSignatureBytes - encodedBytes - 3;
  if (keyBudget < 0) throw new Error("Signature field byte limit exceeded");
  boundedUtf8ByteLength(key, keyBudget, "Signature field byte limit exceeded");
  const field = `${key}=:${base64Encode(signature)}:`;
  boundedUtf8ByteLength(
    field,
    limits.maxSignatureBytes,
    "Signature field byte limit exceeded"
  );
  return field;
}

function signatureInputField(
  key: string,
  value: string,
  limits: SignatureLimits
): string {
  const field = `${key}=${value}`;
  boundedUtf8ByteLength(
    field,
    limits.maxSignatureInputBytes,
    "Signature-Input byte limit exceeded"
  );
  return field;
}

export async function signatureHeaders<
  T extends RequestLike | ResponseLike | ResponseRequestPair,
>(message: T, opts: SignOptions): Promise<SignatureHeaders> {
  validateMessageRequestTarget(message, opts.limits);
  const {
    signer,
    components: _components,
    key: _key,
    parameters: orderedParameters,
    signatureInputProfile = "rfc9421",
    limits,
    ...params
  } = opts;
  const configured = resolveSignatureLimits(limits);

  const components =
    _components ??
    ("status" in resolveMessageKind(message)
      ? defaultResponseComponents
      : defaultRequestComponents);
  const key = _key ?? "sig1";

  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
  };
  addParameters(signParams, params);

  const signatureInputString = buildSignatureInputString(
    components,
    signParams,
    orderedParameters,
    signatureInputProfile === "rfc9421" ? "rfc8941" : "rfc9651",
    limits
  );
  const serializedSignatureInput = signatureInputField(
    key,
    signatureInputString,
    configured
  );
  const dataToSign = buildSignedData(
    message,
    components,
    signatureInputString,
    limits
  );

  const signature = await signer.sign(dataToSign);
  const serializedSignature = signatureField(key, signature, configured);

  return {
    Signature: serializedSignature,
    "Signature-Input": serializedSignatureInput,
  };
}

export function signatureHeadersSync<
  T extends RequestLike | ResponseLike | ResponseRequestPair,
>(message: T, opts: SignSyncOptions): SignatureHeaders {
  validateMessageRequestTarget(message, opts.limits);
  const {
    signer,
    components: _components,
    key: _key,
    parameters: orderedParameters,
    signatureInputProfile = "rfc9421",
    limits,
    ...params
  } = opts;
  const configured = resolveSignatureLimits(limits);

  const components =
    _components ??
    ("status" in resolveMessageKind(message)
      ? defaultResponseComponents
      : defaultRequestComponents);
  const key = _key ?? "sig1";

  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
  };
  addParameters(signParams, params);

  const signatureInputString = buildSignatureInputString(
    components,
    signParams,
    orderedParameters,
    signatureInputProfile === "rfc9421" ? "rfc8941" : "rfc9651",
    limits
  );
  const serializedSignatureInput = signatureInputField(
    key,
    signatureInputString,
    configured
  );
  const dataToSign = buildSignedData(
    message,
    components,
    signatureInputString,
    limits
  );

  const signature = signer.signSync(dataToSign);
  const serializedSignature = signatureField(key, signature, configured);

  return {
    Signature: serializedSignature,
    "Signature-Input": serializedSignatureInput,
  };
}
