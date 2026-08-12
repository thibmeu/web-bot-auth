import * as signatures from "http-message-sig";

import { b64Tou8, u8ToB64 } from "./base64";

export { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";
export { helpers } from "./crypto";

export type ComponentIdentifier = signatures.ComponentIdentifier;
export type HeadersInput = signatures.HeadersInput;
export type SignableMessage = signatures.SignableMessage;
export type SignableRequest = signatures.SignableRequest;
export type SignatureInputProfile = signatures.SignatureInputProfile;
export type StructuredFieldType = signatures.StructuredFieldType;

export const HTTP_MESSAGE_SIGNATURES_DIRECTORY =
  "/.well-known/http-message-signatures-directory";
export enum MediaType {
  HTTP_MESSAGE_SIGNATURES_DIRECTORY = "application/http-message-signatures-directory+json",
}
export enum Tag {
  HTTP_MESSAGE_SIGNAGURES_DIRECTORY = "http-message-signatures-directory",
}
export const HTTP_MESSAGE_SIGNATURE_TAG = "web-bot-auth";
export const SIGNATURE_AGENT_HEADER = "signature-agent";
const DEFAULT_SIGNATURE_LABEL = "sig1";
export const NONCE_LENGTH_IN_BYTES = 64;
const PROFILE_ALGORITHMS = [
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ed25519",
] as const;
export type Algorithm = (typeof PROFILE_ALGORITHMS)[number];

function isProfileAlgorithm(algorithm: string): boolean {
  return PROFILE_ALGORITHMS.some((candidate) => candidate === algorithm);
}

export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_LENGTH_IN_BYTES);
  crypto.getRandomValues(bytes);
  return u8ToB64(bytes);
}

export function validateNonce(nonce: string): boolean {
  try {
    return b64Tou8(nonce).length === NONCE_LENGTH_IN_BYTES;
  } catch {
    return false;
  }
}

export type ExtensionValue =
  | string
  | number
  | boolean
  | Uint8Array
  | { readonly type: "token"; readonly value: string }
  | { readonly type: "decimal"; readonly value: number }
  | { readonly type: "date"; readonly value: number }
  | { readonly type: "display-string"; readonly value: string };

export interface ExtensionParameter {
  readonly name: string;
  readonly value: ExtensionValue;
}

export interface SignatureParams {
  readonly created: Date;
  readonly expires: Date;
  readonly nonce?: string;
  readonly alg?: Algorithm;
  readonly key?: string;
  readonly components: ReadonlyArray<ComponentIdentifier>;
  readonly extensions?: ReadonlyArray<ExtensionParameter>;
  readonly signatureInputProfile?: SignatureInputProfile;
  readonly request?: SignableRequest;
  readonly structuredFields?: Readonly<Record<string, StructuredFieldType>>;
}

export interface Signer {
  readonly keyid: string;
  readonly alg: Algorithm;
  sign(data: string): Uint8Array | Promise<Uint8Array>;
}

export interface SignerSync {
  readonly keyid: string;
  readonly alg: Algorithm;
  signSync(data: string): Uint8Array;
}

export interface VerificationParams {
  readonly keyid: string;
  readonly signatureAgentKey?: string;
  readonly created: Date;
  readonly expires: Date;
  readonly tag: typeof HTTP_MESSAGE_SIGNATURE_TAG;
  readonly nonce?: string;
  readonly extensions: ReadonlyArray<ExtensionParameter>;
}

export type Verify = (
  data: string,
  signature: Uint8Array,
  params: VerificationParams
) => boolean | Promise<boolean>;

export interface Verifier {
  readonly keyid: string;
  readonly alg: Algorithm;
  verify: Verify;
}

export type VerifierFactory = (
  params: Readonly<VerificationParams>
) => Readonly<Verifier> | Promise<Readonly<Verifier>>;
export type VerifierInput = VerifierFactory | Readonly<Verifier>;

export interface VerifyOptions {
  readonly label?: string;
  readonly request?: SignableRequest;
  readonly structuredFields?: Readonly<Record<string, StructuredFieldType>>;
  readonly signatureInputProfile?: SignatureInputProfile;
}

export interface VerifyTransformOptions<T> extends VerifyOptions {
  transform(params: VerificationParams): T | Promise<T>;
}

const reserved = new Set([
  "created",
  "expires",
  "nonce",
  "alg",
  "keyid",
  "tag",
]);

function extensionParameters(
  extensions: ReadonlyArray<ExtensionParameter> | undefined
): signatures.SignatureParameters {
  if (extensions === undefined) return [];
  const names = new Set<string>();
  return extensions.map(({ name, value }) => {
    if (reserved.has(name))
      throw new Error(
        `custom parameter ${name} collides with a reserved parameter`
      );
    if (names.has(name)) throw new Error(`duplicate custom parameter ${name}`);
    names.add(name);
    return [name, value];
  });
}

function parameter(
  signature: Readonly<signatures.MessageSignature>,
  name: string
): signatures.SignatureParameterValue | undefined {
  return signature.parameters.find(([candidate]) => candidate === name)?.[1];
}

function requiredNumber(
  signature: Readonly<signatures.MessageSignature>,
  name: "created" | "expires"
): number {
  const value = parameter(signature, name);
  if (typeof value !== "number") throw new Error(`${name} MUST be defined`);
  return value;
}

function requiredString(
  signature: Readonly<signatures.MessageSignature>,
  name: "keyid" | "tag"
): string {
  const value = parameter(signature, name);
  if (typeof value !== "string") throw new Error(`${name} MUST be defined`);
  return value;
}

function signatureAgentKey(
  components: ReadonlyArray<ComponentIdentifier>
): string | undefined {
  const component = components.find(
    (candidate) =>
      (typeof candidate === "string"
        ? candidate
        : candidate.name
      ).toLowerCase() === SIGNATURE_AGENT_HEADER
  );
  if (component === undefined || typeof component === "string")
    return undefined;
  const key = component.parameters?.find(([name]) => name === "key")?.[1];
  return typeof key === "string" ? key : undefined;
}

function verifiedParameters(
  signature: Readonly<signatures.MessageSignature>
): VerificationParams {
  const tag = requiredString(signature, "tag");
  if (tag !== HTTP_MESSAGE_SIGNATURE_TAG)
    throw new Error(`tag must be '${HTTP_MESSAGE_SIGNATURE_TAG}'`);
  const nonce = parameter(signature, "nonce");
  if (nonce !== undefined && typeof nonce !== "string")
    throw new Error("nonce must be a string");
  return {
    keyid: requiredString(signature, "keyid"),
    signatureAgentKey: signatureAgentKey(signature.components),
    created: new Date(requiredNumber(signature, "created") * 1000),
    expires: new Date(requiredNumber(signature, "expires") * 1000),
    tag,
    nonce,
    extensions: signature.parameters
      .filter(([name]) => !reserved.has(name))
      .map(([name, value]) => ({ name, value })),
  };
}

function enforceCoverage(
  components: ReadonlyArray<ComponentIdentifier>,
  headers: signatures.HeadersInput
): void {
  const covered = components.map((component) =>
    (typeof component === "string" ? component : component.name).toLowerCase()
  );
  if (!covered.includes("@authority") && !covered.includes("@target-uri")) {
    throw new Error("signature must cover @authority or @target-uri");
  }
  const hasSignatureAgent =
    "has" in headers && typeof headers.has === "function"
      ? headers.has("signature-agent")
      : Object.entries(headers).some(
          ([name, value]) =>
            name.toLowerCase() === "signature-agent" && value !== undefined
        );
  if (!hasSignatureAgent) return;
  const component = components.find(
    (candidate) =>
      (typeof candidate === "string"
        ? candidate
        : candidate.name
      ).toLowerCase() === "signature-agent"
  );
  if (component === undefined) {
    throw new Error(
      "signature with signature-agent header must cover signature-agent"
    );
  }
  const parameters =
    typeof component === "string" ? [] : (component.parameters ?? []);
  if (parameters.some(([name]) => name === "req" || name === "tr")) {
    throw new Error(
      "signature-agent coverage must target the message header field section"
    );
  }
  if (signatureAgentKey(components) === undefined) {
    throw new Error("signature-agent coverage must select a dictionary key");
  }
}

function preflight(message: SignableMessage, options: VerifyOptions): void {
  const parsed = signatures.getSignatures(
    message,
    options.signatureInputProfile
  );
  const selected =
    options.label === undefined
      ? parsed.length === 1
        ? parsed[0]
        : undefined
      : parsed.find(({ label }) => label === options.label);
  if (selected === undefined) return;
  verifiedParameters(selected);
  enforceCoverage(selected.components, message.headers);
}

export interface SignatureSummary extends VerificationParams {
  readonly label: string;
  readonly components: ReadonlyArray<ComponentIdentifier>;
}

export interface SignatureHeaders {
  readonly Signature: string;
  readonly "Signature-Input": string;
}

export function recommendedComponents(
  signatureAgentKey?: string
): ReadonlyArray<ComponentIdentifier> {
  return signatureAgentKey === undefined
    ? ["@authority"]
    : [
        "@authority",
        {
          name: SIGNATURE_AGENT_HEADER,
          parameters: [["key", signatureAgentKey]],
        },
      ];
}

export function getSignatures(
  message: SignableMessage,
  signatureInputProfile?: SignatureInputProfile
): ReadonlyArray<SignatureSummary> {
  return signatures
    .getSignatures(message, signatureInputProfile)
    .map((signature) => ({
      ...verifiedParameters(signature),
      label: signature.label,
      components: signature.components,
    }));
}

export async function signatureHeaders(
  message: SignableMessage,
  signer: Signer,
  params: SignatureParams
): Promise<SignatureHeaders> {
  if (!isProfileAlgorithm(signer.alg))
    throw new Error(`algorithm ${signer.alg} is not allowed by Web Bot Auth`);
  if (params.alg !== undefined && params.alg !== signer.alg)
    throw new Error(
      `claimed algorithm ${params.alg} does not match ${signer.alg}`
    );
  if (params.created.getTime() > params.expires.getTime())
    throw new Error("created should happen before expires");
  const label = params.key ?? DEFAULT_SIGNATURE_LABEL;
  enforceCoverage(params.components, message.headers);
  const nonce = params.nonce ?? generateNonce();
  if (!validateNonce(nonce)) throw new Error("nonce is not a valid uint32");
  const signatureParameters: signatures.SignatureParameter[] = [
    ["created", params.created],
    ["expires", params.expires],
    ["nonce", nonce],
  ];
  if (params.alg !== undefined) {
    signatureParameters.push(["alg", params.alg]);
  }
  signatureParameters.push(
    ["keyid", signer.keyid],
    ["tag", HTTP_MESSAGE_SIGNATURE_TAG],
    ...extensionParameters(params.extensions)
  );
  const fields = await signatures.createSignature(message, {
    request: params.request,
    structuredFields: params.structuredFields,
    signatureInputProfile: params.signatureInputProfile,
    label,
    components: params.components,
    parameters: signatureParameters,
    signer: () => ({
      alg: signer.alg,
      sign(data) {
        return signer.sign(new TextDecoder().decode(data));
      },
    }),
  });
  return {
    Signature: fields.signatureField,
    "Signature-Input": fields.signatureInput,
  };
}

export function signatureHeadersSync(
  message: SignableMessage,
  signer: SignerSync,
  params: SignatureParams
): SignatureHeaders {
  if (!isProfileAlgorithm(signer.alg))
    throw new Error(`algorithm ${signer.alg} is not allowed by Web Bot Auth`);
  if (params.alg !== undefined && params.alg !== signer.alg)
    throw new Error(
      `claimed algorithm ${params.alg} does not match ${signer.alg}`
    );
  if (params.created.getTime() > params.expires.getTime())
    throw new Error("created should happen before expires");
  enforceCoverage(params.components, message.headers);
  const nonce = params.nonce ?? generateNonce();
  if (!validateNonce(nonce)) throw new Error("nonce is not a valid uint32");
  const parameters: signatures.SignatureParameter[] = [
    ["created", params.created],
    ["expires", params.expires],
    ["nonce", nonce],
  ];
  if (params.alg !== undefined) parameters.push(["alg", params.alg]);
  parameters.push(
    ["keyid", signer.keyid],
    ["tag", HTTP_MESSAGE_SIGNATURE_TAG],
    ...extensionParameters(params.extensions)
  );
  const fields = signatures.createSignatureSync(message, {
    request: params.request,
    structuredFields: params.structuredFields,
    signatureInputProfile: params.signatureInputProfile,
    label: params.key ?? DEFAULT_SIGNATURE_LABEL,
    components: params.components,
    parameters,
    signer: () => ({
      alg: signer.alg,
      sign(data) {
        return signer.signSync(new TextDecoder().decode(data));
      },
    }),
  });
  return {
    Signature: fields.signatureField,
    "Signature-Input": fields.signatureInput,
  };
}

export function verify(
  message: SignableMessage,
  verifier: VerifierInput,
  options?: VerifyOptions
): Promise<VerificationParams>;
export function verify<T>(
  message: SignableMessage,
  verifier: VerifierInput,
  options: VerifyTransformOptions<T>
): Promise<T>;
export async function verify<T>(
  message: SignableMessage,
  verifier: VerifierInput,
  options: VerifyOptions | VerifyTransformOptions<T> = {}
): Promise<VerificationParams | T> {
  preflight(message, options);
  const verified = await signatures.verify(message, {
    request: options.request,
    structuredFields: options.structuredFields,
    signatureInputProfile: options.signatureInputProfile,
    label: options.label,
    verifier: async (signature) => {
      const params = verifiedParameters(signature);
      const selected =
        typeof verifier === "function" ? await verifier(params) : verifier;
      if (!isProfileAlgorithm(selected.alg)) {
        throw new signatures.VerificationError(
          "algorithm_unsupported",
          `algorithm ${selected.alg} is not allowed by Web Bot Auth`
        );
      }
      if (selected.keyid !== params.keyid) {
        throw new signatures.VerificationError(
          "unknown_key",
          "claimed keyid does not match verifier keyid"
        );
      }
      return {
        alg: selected.alg,
        keyid: selected.keyid,
        verify(data, candidate) {
          return selected.verify(
            new TextDecoder().decode(data),
            candidate,
            params
          );
        },
      };
    },
    policy: {
      requiredComponents: [],
      requiredParameters: ["created", "expires", "keyid", "tag"],
      algorithms: PROFILE_ALGORITHMS,
      validate: (signature) =>
        enforceCoverage(signature.components, message.headers),
    },
  });
  const params = verifiedParameters(verified);
  return "transform" in options ? options.transform(params) : params;
}

export const token = signatures.token;
export const decimal = signatures.decimal;
export const date = signatures.date;
export const displayString = signatures.displayString;

export interface Directory {
  readonly keys: JsonWebKey[];
  readonly purpose: string;
  readonly schema?: string;
}

export async function directoryResponseHeaders(
  message: {
    readonly request: SignableRequest;
    readonly response: SignableMessage;
  },
  signers: ReadonlyArray<Signer>,
  params: Readonly<{ created: Date; expires: Date }>
): Promise<SignatureHeaders> {
  if (params.created.getTime() > params.expires.getTime())
    throw new Error("created should happen before expires");
  const seen = new Set<string>();
  const fields: SignatureHeaders[] = [];
  for (const [index, signer] of signers.entries()) {
    if (seen.has(signer.keyid))
      throw new Error(`Duplicated signer with keyid ${signer.keyid}`);
    seen.add(signer.keyid);
    const signature = await signatures.createSignature(message.response, {
      request: message.request,
      label: `binding${index}`,
      components: [{ name: "@authority", parameters: [["req", true]] }],
      parameters: [
        ["created", params.created],
        ["expires", params.expires],
        ["keyid", signer.keyid],
        ["alg", signer.alg],
        ["tag", Tag.HTTP_MESSAGE_SIGNAGURES_DIRECTORY],
      ],
      signer: () => ({
        alg: signer.alg,
        sign(data) {
          return signer.sign(new TextDecoder().decode(data));
        },
      }),
    });
    fields.push({
      Signature: signature.signatureField,
      "Signature-Input": signature.signatureInput,
    });
  }
  return {
    Signature: fields.map(({ Signature }) => Signature).join(", "),
    "Signature-Input": fields
      .map((field) => field["Signature-Input"])
      .join(", "),
  };
}

export {
  parseRegistry,
  parseSignatureAgentCard,
  parseSignatureAgentHeader,
  type JSONWebKeySet,
  type SignatureAgentCard,
  type SignatureAgentDiscoveryType,
  type SignatureAgentEntry,
  type SignatureAgentHeader,
  type WebBotAuthMetadata,
} from "./registry";
