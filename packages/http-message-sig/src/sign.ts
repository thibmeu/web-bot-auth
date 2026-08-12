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
  values: Readonly<Record<string, unknown>>,
  excluded: ReadonlySet<string> = new Set()
): void {
  for (const name of Object.keys(values)) {
    if (excluded.has(name)) continue;
    const value = values[name];
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

interface PreparedSignature {
  readonly configured: SignatureLimits;
  readonly key: string;
  readonly serializedSignatureInput: string;
  readonly dataToSign: string;
}

const SIGN_OPTION_NAMES = new Set([
  "signer",
  "components",
  "key",
  "parameters",
  "signatureInputProfile",
  "limits",
]);

function prepareSignature(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  opts: SignOptions | SignSyncOptions,
  signer: SignOptions["signer"] | SignSyncOptions["signer"]
): PreparedSignature {
  validateMessageRequestTarget(message, opts.limits);
  const requestedComponents = opts.components;
  const requestedKey = opts.key;
  const orderedParameters = opts.parameters;
  const signatureInputProfile = opts.signatureInputProfile ?? "rfc9421";
  const limits = opts.limits;
  const configured = resolveSignatureLimits(limits);
  const components =
    requestedComponents ??
    ("status" in resolveMessageKind(message)
      ? defaultResponseComponents
      : defaultRequestComponents);
  const key = requestedKey ?? "sig1";
  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
  };
  addParameters(signParams, opts, SIGN_OPTION_NAMES);
  const signatureInputString = buildSignatureInputString(
    components,
    signParams,
    orderedParameters,
    signatureInputProfile === "rfc9421" ? "rfc8941" : "rfc9651",
    limits
  );
  return {
    configured,
    key,
    serializedSignatureInput: signatureInputField(
      key,
      signatureInputString,
      configured
    ),
    dataToSign: buildSignedData(
      message,
      components,
      signatureInputString,
      limits
    ),
  };
}

export async function signatureHeaders<
  T extends RequestLike | ResponseLike | ResponseRequestPair,
>(message: T, opts: SignOptions): Promise<SignatureHeaders> {
  const signer = opts.signer;
  const prepared = prepareSignature(message, opts, signer);
  const signature = await signer.sign(prepared.dataToSign);

  return {
    Signature: signatureField(prepared.key, signature, prepared.configured),
    "Signature-Input": prepared.serializedSignatureInput,
  };
}

export function signatureHeadersSync<
  T extends RequestLike | ResponseLike | ResponseRequestPair,
>(message: T, opts: SignSyncOptions): SignatureHeaders {
  const signer = opts.signer;
  const prepared = prepareSignature(message, opts, signer);
  const signature = signer.signSync(prepared.dataToSign);

  return {
    Signature: signatureField(prepared.key, signature, prepared.configured),
    "Signature-Input": prepared.serializedSignatureInput,
  };
}
