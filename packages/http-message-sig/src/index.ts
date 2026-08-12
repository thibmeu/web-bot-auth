import * as engine from "fetch-message-signatures";

export type StructuredFieldType = "dictionary" | "list" | "item";
export type SignatureInputProfile = "rfc9421" | "rfc9651-extension";

export interface StructuredFieldToken {
  readonly type: "token";
  readonly value: string;
}

export interface StructuredFieldDecimal {
  readonly type: "decimal";
  readonly value: number;
}

export interface StructuredFieldDate {
  readonly type: "date";
  readonly value: number;
}

export interface StructuredFieldDisplayString {
  readonly type: "display-string";
  readonly value: string;
}

export type SignatureParameterValue =
  | string
  | number
  | boolean
  | Uint8Array
  | StructuredFieldToken
  | StructuredFieldDecimal
  | StructuredFieldDate
  | StructuredFieldDisplayString;
export type SignatureParameter = readonly [
  name: string,
  value: SignatureParameterValue | Date | undefined,
];
export type SignatureParameters = ReadonlyArray<SignatureParameter>;
export type ComponentParameter = readonly [
  name: string,
  value: string | boolean,
];

export interface ParameterizedComponent {
  readonly name: string;
  readonly parameters?: ReadonlyArray<ComponentParameter>;
}

export type ComponentIdentifier = string | ParameterizedComponent;

export interface MessageComponent {
  readonly name: string;
  readonly parameters: ReadonlyArray<ComponentParameter>;
}

export type HeadersInput =
  | Headers
  | Readonly<Record<string, string | ReadonlyArray<string> | undefined>>;

export interface RequestDescriptor {
  readonly method: string;
  readonly url: string;
  readonly headers: HeadersInput;
  readonly trailers?: HeadersInput;
}

export interface ResponseDescriptor {
  readonly status: number;
  readonly headers: HeadersInput;
  readonly trailers?: HeadersInput;
}

export type SignableRequest = Request | RequestDescriptor;
export type SignableResponse = Response | ResponseDescriptor;
export type SignableMessage = SignableRequest | SignableResponse;

export interface MessageSignature {
  readonly label: string;
  readonly components: ReadonlyArray<MessageComponent>;
  readonly parameters: ReadonlyArray<
    readonly [name: string, value: SignatureParameterValue]
  >;
  readonly signature: Uint8Array;
}

export interface SignatureFields extends MessageSignature {
  readonly signatureInput: string;
  readonly signatureField: string;
}

export interface Signer {
  readonly alg: string;
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface SignerSync {
  readonly alg: string;
  sign(data: Uint8Array): Uint8Array;
}

export interface Verifier {
  readonly alg: string;
  readonly keyid?: string;
  verify(data: Uint8Array, signature: Uint8Array): boolean | Promise<boolean>;
}

export type VerifierFactory = (
  signature: Readonly<MessageSignature>
) => Readonly<Verifier> | Promise<Readonly<Verifier>>;

interface SignatureContext {
  readonly request?: SignableRequest;
  readonly structuredFields?: Readonly<Record<string, StructuredFieldType>>;
  readonly signatureInputProfile?: SignatureInputProfile;
}

export interface CreateSignatureOptions extends SignatureContext {
  readonly signer: () => Readonly<Signer>;
  readonly components: ReadonlyArray<ComponentIdentifier>;
  readonly parameters?: SignatureParameters;
  readonly label?: string;
  readonly now?: number | Date;
}

export interface CreateSignatureSyncOptions extends SignatureContext {
  readonly signer: () => Readonly<SignerSync>;
  readonly components: ReadonlyArray<ComponentIdentifier>;
  readonly parameters?: SignatureParameters;
  readonly label?: string;
  readonly now?: number | Date;
}

export interface VerificationPolicy {
  readonly requiredComponents: ReadonlyArray<ComponentIdentifier>;
  readonly requiredParameters: ReadonlyArray<string>;
  readonly algorithms: ReadonlyArray<string>;
  readonly maxAge?: number;
  readonly clockSkew?: number;
  readonly now?: number | Date;
  validate?(signature: Readonly<VerifiedSignature>): void | Promise<void>;
}

export interface VerifyOptions extends SignatureContext {
  readonly verifier: VerifierFactory;
  readonly policy: VerificationPolicy;
  readonly label?: string;
}

export interface VerifiedSignature extends MessageSignature {
  readonly algorithm: string;
}

export type VerificationErrorCode =
  | "signature_missing"
  | "signature_malformed"
  | "policy_rejected"
  | "signature_time_invalid"
  | "unknown_key"
  | "algorithm_unsupported"
  | "signature_mismatch"
  | "verification_failed";

export class VerificationError extends Error {
  readonly code: VerificationErrorCode;
  readonly cause?: unknown;

  constructor(
    code: VerificationErrorCode,
    message: string,
    options?: Readonly<{ cause?: unknown }>
  ) {
    super(message);
    this.name = "VerificationError";
    this.code = code;
    this.cause = options?.cause;
  }
}

function strictParameters(
  parameters: SignatureParameters | undefined,
  profile: SignatureInputProfile | undefined
): void {
  if (profile === "rfc9651-extension" || parameters === undefined) return;
  for (const [, value] of parameters) {
    if (
      typeof value === "object" &&
      value !== null &&
      "type" in value &&
      (value.type === "date" || value.type === "display-string")
    ) {
      throw new TypeError(
        `${value.type} requires signatureInputProfile "rfc9651-extension"`
      );
    }
  }
}

function nonEmptySignature(signature: Uint8Array): void {
  if (signature.length === 0)
    throw new TypeError("Signature bytes must not be empty");
}

function emptySignatureError(error: unknown): TypeError | undefined {
  if (
    error instanceof TypeError &&
    error.message === "Signature bytes must not be empty"
  ) {
    return error;
  }
  if (error !== null && typeof error === "object" && "cause" in error)
    return emptySignatureError(error.cause);
  return undefined;
}

function ownedValue(
  value: engine.SignatureParameterValue
): SignatureParameterValue {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (typeof value !== "object") return value;
  if (value.type === "token") return { type: "token", value: value.value };
  if (value.type === "decimal") return { type: "decimal", value: value.value };
  if (value.type === "date") return { type: "date", value: value.value };
  return { type: "display-string", value: value.value };
}

function ownedComponent(component: engine.MessageComponent): MessageComponent {
  return {
    name: component.name,
    parameters: component.parameters.map(([name, value]) => [name, value]),
  };
}

function ownedSignature(signature: engine.MessageSignature): MessageSignature {
  return {
    label: signature.label,
    components: signature.components.map(ownedComponent),
    parameters: signature.parameters.map(([name, value]) => [
      name,
      ownedValue(value),
    ]),
    signature: new Uint8Array(signature.signature),
  };
}

function ownedFields(fields: engine.SignatureFields): SignatureFields {
  return {
    ...ownedSignature(fields),
    signatureInput: fields.signatureInput,
    signatureField: fields.signatureField,
  };
}

function parameter(
  signature: Readonly<MessageSignature>,
  name: string
): SignatureParameterValue | undefined {
  return signature.parameters.find(([candidate]) => candidate === name)?.[1];
}

function ownedError(error: unknown): VerificationError | undefined {
  if (error instanceof VerificationError) return error;
  if (error !== null && typeof error === "object" && "cause" in error)
    return ownedError(error.cause);
  return undefined;
}

function unixTimestamp(input: number | Date | undefined): number {
  let timestamp: number;
  if (input === undefined) {
    timestamp = Math.floor(Date.now() / 1000);
  } else if (typeof input === "number") {
    timestamp = input;
  } else {
    timestamp = Math.floor(Date.prototype.getTime.call(input) / 1000);
  }
  if (!Number.isSafeInteger(timestamp))
    throw new TypeError("Clock value must be an integer UNIX timestamp");
  return timestamp;
}

function syncParameters(
  options: CreateSignatureSyncOptions
): SignatureParameters {
  const parameters = options.parameters ?? [];
  const created = parameters.filter(([name]) => name === "created");
  if (created.length === 0)
    return [["created", unixTimestamp(options.now)], ...parameters];
  if (created.length === 1 && created[0]?.[1] === undefined) {
    return [
      ["created", unixTimestamp(options.now)],
      ...parameters.filter(([name]) => name !== "created"),
    ];
  }
  return parameters;
}

export function token(value: string): StructuredFieldToken {
  return engine.token(value);
}

export function decimal(value: number): StructuredFieldDecimal {
  return engine.decimal(value);
}

export function date(value: number | Date): StructuredFieldDate {
  return engine.date(value);
}

export function displayString(value: string): StructuredFieldDisplayString {
  return engine.displayString(value);
}

export async function createSignature(
  message: SignableMessage,
  options: CreateSignatureOptions
): Promise<SignatureFields> {
  strictParameters(options.parameters, options.signatureInputProfile);
  try {
    const fields = await engine.createSignature(message, {
      request: options.request,
      structuredFields: options.structuredFields,
      signer: () => {
        const signer = options.signer();
        return {
          alg: signer.alg,
          async sign(data) {
            const signature = await signer.sign(data);
            nonEmptySignature(signature);
            return signature;
          },
        };
      },
      components: options.components,
      parameters: options.parameters,
      label: options.label,
      now: options.now,
    });
    return ownedFields(fields);
  } catch (error) {
    const empty = emptySignatureError(error);
    if (empty !== undefined) throw empty;
    throw error;
  }
}

export function createSignatureSync(
  message: SignableMessage,
  options: CreateSignatureSyncOptions
): SignatureFields {
  strictParameters(options.parameters, options.signatureInputProfile);
  const signer = options.signer();
  const parameters = syncParameters(options);
  const claimedAlgorithm = parameters.find(([name]) => name === "alg")?.[1];
  if (claimedAlgorithm !== undefined && claimedAlgorithm !== signer.alg) {
    throw new TypeError(
      `claimed algorithm ${claimedAlgorithm.toString()} does not match ${signer.alg}`
    );
  }
  const base = engine.createSignatureBase(message, {
    request: options.request,
    structuredFields: options.structuredFields,
    components: options.components,
    parameters,
  });
  const signature = signer.sign(new TextEncoder().encode(base));
  nonEmptySignature(signature);
  return ownedFields(
    engine.createSignatureFields({
      signature,
      components: options.components,
      parameters,
      label: options.label,
    })
  );
}

export function getSignatures(
  message: SignableMessage,
  profile: SignatureInputProfile = "rfc9421"
): ReadonlyArray<MessageSignature> {
  const signatures = engine.getSignatures(message);
  if (signatures.length === 0)
    throw new TypeError("Message must contain at least one signature");
  for (const signature of signatures) {
    nonEmptySignature(signature.signature);
    strictParameters(signature.parameters, profile);
  }
  return signatures.map(ownedSignature);
}

export async function verify(
  message: SignableMessage,
  options: VerifyOptions
): Promise<VerifiedSignature> {
  getSignatures(message, options.signatureInputProfile);
  try {
    const verified = await engine.verify(message, {
      request: options.request,
      structuredFields: options.structuredFields,
      label: options.label,
      verifier: async (candidate) => {
        const signature = ownedSignature(candidate);
        let verifier: Readonly<Verifier>;
        try {
          verifier = await options.verifier(signature);
        } catch (error) {
          if (error instanceof VerificationError) {
            throw new engine.VerificationError(error.code, error.message, {
              cause: error,
            });
          }
          throw error;
        }
        const claimedKeyid = parameter(signature, "keyid");
        if (claimedKeyid !== verifier.keyid) {
          throw new engine.VerificationError(
            "unknown_key",
            "claimed keyid does not match verifier keyid"
          );
        }
        const claimedAlgorithm = parameter(signature, "alg");
        if (
          claimedAlgorithm !== undefined &&
          claimedAlgorithm !== verifier.alg
        ) {
          throw new engine.VerificationError(
            "algorithm_unsupported",
            "verifier algorithm does not match claimed algorithm"
          );
        }
        return {
          alg: verifier.alg,
          async verify(data, signature) {
            try {
              return await verifier.verify(data, signature);
            } catch (error) {
              if (error instanceof VerificationError) {
                throw new engine.VerificationError(error.code, error.message, {
                  cause: error,
                });
              }
              throw error;
            }
          },
        };
      },
      policy: {
        requiredComponents: options.policy.requiredComponents,
        requiredParameters: options.policy.requiredParameters,
        algorithms: options.policy.algorithms,
        maxAge: options.policy.maxAge,
        clockSkew: options.policy.clockSkew,
        now: options.policy.now,
        validate:
          options.policy.validate === undefined
            ? undefined
            : (signature, context) =>
                options.policy.validate?.({
                  ...ownedSignature(signature),
                  algorithm: context.algorithm,
                }),
      },
    });
    strictParameters(verified.parameters, options.signatureInputProfile);
    return { ...ownedSignature(verified), algorithm: verified.algorithm };
  } catch (error) {
    const existing = ownedError(error);
    if (existing !== undefined)
      throw new VerificationError(existing.code, existing.message, {
        cause: error,
      });
    if (error instanceof engine.VerificationError) {
      throw new VerificationError(error.code, error.message, { cause: error });
    }
    throw error;
  }
}
