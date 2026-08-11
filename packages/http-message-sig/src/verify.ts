import {
  Component,
  Parameters,
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
  Verify,
} from "./types";
import { parseSignatureHeader, parseSignatureInputHeader } from "./parse";
import {
  buildSignedData,
  extractHeader,
  resolveMessageKind,
  validateMessageRequestTarget,
} from "./build";
import {
  resolveSignatureLimits,
  type SignatureInputProfile,
  type SignatureLimits,
} from "./rfc9421";

export interface VerifyOptions {
  readonly signatureInputProfile?: SignatureInputProfile;
  readonly limits?: Partial<SignatureLimits>;
}

function immutableParameters(parameters: Parameters): Parameters {
  const stable: Parameters = {};
  for (const [name, value] of Object.entries(parameters)) {
    stable[name] =
      value instanceof Date
        ? new Date(value)
        : value instanceof Uint8Array
          ? value.slice()
          : value;
  }
  return Object.freeze(stable);
}

function immutableComponents(components: Component[]): Component[] {
  const stable = components.map((component): Component => {
    if (typeof component === "string") return component;
    const parameters =
      component.parameters === undefined
        ? undefined
        : Object.freeze(new Map(component.parameters));
    return Object.freeze(
      "header" in component
        ? { header: component.header, key: component.key, parameters }
        : { name: component.name, parameters: parameters ?? new Map() }
    );
  });
  Object.freeze(stable);
  return stable;
}

export async function verify<T>(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  verifier: Verify<T>,
  options: VerifyOptions = {}
): Promise<T> {
  const limits = resolveSignatureLimits(options.limits);
  validateMessageRequestTarget(message, options.limits);
  const signatureInputHeader = extractHeader(
    resolveMessageKind(message),
    "signature-input",
    limits.maxSignatureInputBytes
  );
  if (!signatureInputHeader)
    throw new Error("Message does not contain Signature-Input header");
  const { key, components, parameters } = parseSignatureInputHeader(
    signatureInputHeader,
    options.signatureInputProfile,
    options.limits
  );

  if (
    parameters.alg !== undefined &&
    verifier.alg !== undefined &&
    parameters.alg !== verifier.alg
  ) {
    throw new Error(
      `Signature algorithm ${parameters.alg} does not match verifier algorithm ${verifier.alg}`
    );
  }

  if (parameters.expires && parameters.expires < new Date())
    throw new Error("Signature expired");

  const signatureHeader = extractHeader(
    resolveMessageKind(message),
    "signature",
    limits.maxSignatureBytes
  );
  if (!signatureHeader)
    throw new Error("Message does not contain Signature header");
  const signature = parseSignatureHeader(key, signatureHeader, options.limits);

  const signatureInputString = signatureInputHeader
    .toString()
    .replace(/^[^=]+=/, "");
  const signedData = buildSignedData(
    message,
    components,
    signatureInputString,
    options.limits
  );
  const stableComponents = immutableComponents(components);
  const stableParameters = immutableParameters(parameters);
  const stableSignature = signature.slice();

  return verifier(
    signedData,
    stableSignature,
    stableParameters,
    stableComponents
  );
}
