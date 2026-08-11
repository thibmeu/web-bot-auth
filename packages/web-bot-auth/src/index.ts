import * as httpsig from "http-message-sig";
export {
  HTTP_MESSAGE_SIGNATURES_DIRECTORY,
  type Algorithm,
  MediaType,
  type SignatureHeaders,
  type Signer,
  type SignerSync,
  type SignOptions,
  type SignSyncOptions,
  Tag,
  directoryResponseHeaders,
} from "http-message-sig";
export { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";

import { b64Tou8, u8ToB64 } from "./base64";
export { helpers } from "./crypto";

export const HTTP_MESSAGE_SIGNATURE_TAG = "web-bot-auth";
export const SIGNATURE_AGENT_HEADER = "signature-agent";
export const REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT: httpsig.Component[] = [
  "@authority",
];
export const REQUEST_COMPONENTS: httpsig.Component[] = [
  "@authority",
  SIGNATURE_AGENT_HEADER,
];
export const NONCE_LENGTH_IN_BYTES = 64;

export interface SignatureParams {
  created: Date;
  expires: Date;
  nonce?: string;
  key?: string;
  components?: httpsig.Component[];
  customParameters?: readonly httpsig.SfParameter[];
  signatureInputProfile?: httpsig.SignatureInputProfile;
}

export interface VerificationParams {
  keyid: string;
  alg: httpsig.Algorithm;
  created: Date;
  expires: Date;
  tag: typeof HTTP_MESSAGE_SIGNATURE_TAG;
  nonce?: string;
  customParameters: readonly httpsig.SfParameter[];
}

export interface VerificationPolicy {
  readonly signatureInputProfile?: httpsig.SignatureInputProfile;
  readonly requiredCustomParameters?: readonly string[];
  readonly limits?: Partial<httpsig.SignatureLimits>;
}

const RESERVED_PARAMETERS = new Set([
  "created",
  "expires",
  "nonce",
  "alg",
  "keyid",
  "tag",
]);

export function generateNonce(): string {
  const nonceBytes = new Uint8Array(NONCE_LENGTH_IN_BYTES);
  crypto.getRandomValues(nonceBytes);
  return u8ToB64(nonceBytes);
}

export function validateNonce(nonce: string): boolean {
  try {
    return b64Tou8(nonce).length === NONCE_LENGTH_IN_BYTES;
  } catch {
    return false;
  }
}

export function recommendedComponents(
  signatureAgentKey?: string
): httpsig.Component[] {
  if (signatureAgentKey) {
    return [
      "@authority",
      { header: SIGNATURE_AGENT_HEADER, key: signatureAgentKey },
    ];
  }
  return ["@authority"];
}

function validateSigningSignatureAgentSection(
  components: readonly httpsig.Component[]
): void {
  for (const component of components) {
    const name =
      typeof component === "string"
        ? component
        : "header" in component
          ? component.header
          : component.name;
    if (name.toLowerCase() !== SIGNATURE_AGENT_HEADER) continue;
    const parameters =
      typeof component === "string" ? undefined : component.parameters;
    if (parameters?.has("req") || parameters?.has("tr"))
      throw new Error(
        `${SIGNATURE_AGENT_HEADER} must cover the target header section`
      );
  }
}

function validateVerificationSignatureAgentSection(
  components: readonly httpsig.CoveredComponent[]
): void {
  for (const component of components) {
    if (component.name.toLowerCase() !== SIGNATURE_AGENT_HEADER) continue;
    if (
      component.parameters.some(({ name }) => name === "req" || name === "tr")
    )
      throw new Error(
        `${SIGNATURE_AGENT_HEADER} must cover the target header section`
      );
  }
}

function getSigningOptions<
  T extends
    httpsig.RequestLike | httpsig.ResponseLike | httpsig.ResponseRequestPair,
>(
  message: T,
  params: SignatureParams
): Omit<httpsig.SignOptions | httpsig.SignSyncOptions, "signer" | "keyid"> {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }
  const customNames = new Set<string>();
  for (const { name } of params.customParameters ?? []) {
    if (RESERVED_PARAMETERS.has(name)) {
      throw new Error(`custom parameter ${name} is reserved`);
    }
    if (customNames.has(name)) {
      throw new Error(`duplicate custom parameter ${name}`);
    }
    customNames.add(name);
  }
  // Nonce should be a base64 encoded 64-byte array. We should check it
  let nonce = params.nonce;
  if (!nonce) {
    nonce = generateNonce();
  } else {
    if (!validateNonce(nonce)) {
      throw new Error("nonce is not a valid uint32");
    }
  }
  const signatureAgent = httpsig.extractHeader(
    httpsig.resolveMessageKind(message),
    SIGNATURE_AGENT_HEADER
  );
  let components: httpsig.Component[];
  if (!params.components) {
    // `extractHeader` returns "" instead of throwing or null when the header does not exist
    if (!signatureAgent) {
      components = REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT;
    } else {
      components = REQUEST_COMPONENTS;
    }
  } else {
    if (
      signatureAgent &&
      !params.components.some((c) => {
        if (typeof c === "string") {
          return c.toLowerCase() === SIGNATURE_AGENT_HEADER;
        }
        if ("header" in c) {
          return c.header.toLowerCase() === SIGNATURE_AGENT_HEADER;
        }
        return c.name.toLowerCase() === SIGNATURE_AGENT_HEADER;
      })
    ) {
      throw new Error(
        `${SIGNATURE_AGENT_HEADER} is required in params.components when included as a header param`
      );
    }
    components = params.components;
  }
  validateSigningSignatureAgentSection(components);

  return {
    components,
    created: params.created,
    expires: params.expires,
    nonce,
    key: params.key,
    tag: HTTP_MESSAGE_SIGNATURE_TAG,
    parameters: params.customParameters,
    signatureInputProfile: params.signatureInputProfile,
  };
}

export function signatureHeaders<
  T extends
    httpsig.RequestLike | httpsig.ResponseLike | httpsig.ResponseRequestPair,
>(
  message: T,
  signer: httpsig.Signer,
  params: SignatureParams
): Promise<httpsig.SignatureHeaders> {
  return httpsig.signatureHeaders(message, {
    signer,
    keyid: signer.keyid,
    ...getSigningOptions(message, params),
  });
}

export function signatureHeadersSync<
  T extends
    httpsig.RequestLike | httpsig.ResponseLike | httpsig.ResponseRequestPair,
>(
  message: T,
  signer: httpsig.SignerSync,
  params: SignatureParams
): httpsig.SignatureHeaders {
  return httpsig.signatureHeadersSync(message, {
    signer,
    keyid: signer.keyid,
    ...getSigningOptions(message, params),
  });
}

export type Verify<T> = {
  (
    data: string,
    signature: Uint8Array,
    params: VerificationParams
  ): T | Promise<T>;
  readonly alg: httpsig.Algorithm;
};

function verificationAlgorithm(value: string): httpsig.Algorithm {
  switch (value) {
    case "rsa-pss-sha512":
    case "rsa-v1_5-sha256":
    case "hmac-sha256":
    case "ecdsa-p256-sha256":
    case "ecdsa-p384-sha384":
    case "ed25519":
      return value;
    default:
      throw new Error(`unsupported signature algorithm: ${value}`);
  }
}

interface SnapshotPlan {
  readonly headers: Set<string>;
  readonly trailers: Set<string>;
}

interface SnapshotBudget {
  occurrences: number;
  bytes: number;
  readonly limits: httpsig.SignatureLimits;
}

function isHeadersMap(headers: httpsig.Headers): headers is httpsig.HeadersMap {
  return typeof headers.get === "function";
}

function accountSnapshotValue(
  name: string,
  value: string,
  budget: SnapshotBudget,
  fieldBytes: number
): number {
  budget.occurrences += 1;
  if (budget.occurrences > budget.limits.maxFieldOccurrences)
    throw new Error("field occurrence limit exceeded");
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0xff)
      throw new Error("field value cannot be represented as HTTP bytes");
  }
  const nextFieldBytes = fieldBytes + (fieldBytes === 0 ? 0 : 2) + value.length;
  budget.bytes += name.length + value.length;
  if (budget.bytes > budget.limits.maxFieldBytes)
    throw new Error("field byte limit exceeded");
  return nextFieldBytes;
}

function readHeaderSnapshot(
  headers: httpsig.Headers | undefined,
  name: string,
  budget: SnapshotBudget,
  maxBytes?: number
): httpsig.HeaderValue {
  if (headers === undefined) return "";
  let fieldBytes = 0;
  const values: string[] = [];
  const add = (value: string): void => {
    fieldBytes = accountSnapshotValue(name, value, budget, fieldBytes);
    if (maxBytes !== undefined && fieldBytes > maxBytes)
      throw new Error(`${name} byte limit exceeded`);
    values.push(value);
  };
  if (isHeadersMap(headers)) {
    const value = headers.get(name);
    if (value !== null) add(value);
  } else {
    const lower = name.toLowerCase();
    for (const key in headers) {
      if (
        !Object.prototype.hasOwnProperty.call(headers, key) ||
        key.toLowerCase() !== lower
      )
        continue;
      // eslint-disable-next-line security/detect-object-injection
      const value = headers[key];
      if (value === undefined) continue;
      if (Array.isArray(value)) {
        for (const occurrence of value) add(occurrence);
      } else add(value.toString());
    }
  }
  return Object.freeze(values);
}

function addComponentToPlan(
  plan: SnapshotPlan,
  component: httpsig.CoveredComponent
): void {
  const name = component.name.toLowerCase();
  if (name.startsWith("@")) return;
  const trailers = component.parameters.some(({ name }) => name === "tr");
  (trailers ? plan.trailers : plan.headers).add(name);
}

function snapshotHeaderRecord(
  headers: httpsig.Headers | undefined,
  names: ReadonlySet<string>,
  budget: SnapshotBudget,
  preloaded: ReadonlyMap<string, httpsig.HeaderValue> = new Map()
): Readonly<Record<string, httpsig.HeaderValue>> {
  const record: Record<string, httpsig.HeaderValue> = {};
  for (const name of names) {
    const known = preloaded.get(name);
    let value: httpsig.HeaderValue;
    if (known !== undefined) value = known;
    else value = readHeaderSnapshot(headers, name, budget);
    Object.defineProperty(record, name, {
      value,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(record);
}

function snapshotRequest(
  request: httpsig.RequestLike,
  plan: SnapshotPlan,
  budget: SnapshotBudget,
  preloaded?: ReadonlyMap<string, httpsig.HeaderValue>,
  capturedHeaders?: httpsig.Headers
): httpsig.RequestLike {
  const method = request.method;
  const url = request.url;
  const requestTarget = request.requestTarget;
  const protocol = request.protocol;
  const headers = capturedHeaders ?? request.headers;
  const trailers = request.trailers;
  return Object.freeze({
    method,
    url,
    ...(requestTarget === undefined ? {} : { requestTarget }),
    ...(protocol === undefined ? {} : { protocol }),
    headers: snapshotHeaderRecord(headers, plan.headers, budget, preloaded),
    trailers: snapshotHeaderRecord(trailers, plan.trailers, budget),
  });
}

function snapshotResponse(
  response: httpsig.ResponseLike,
  plan: SnapshotPlan,
  budget: SnapshotBudget,
  preloaded?: ReadonlyMap<string, httpsig.HeaderValue>,
  capturedHeaders?: httpsig.Headers
): httpsig.ResponseLike {
  const status = response.status;
  const headers = capturedHeaders ?? response.headers;
  const trailers = response.trailers;
  return Object.freeze({
    status,
    headers: snapshotHeaderRecord(headers, plan.headers, budget, preloaded),
    trailers: snapshotHeaderRecord(trailers, plan.trailers, budget),
  });
}

function verificationSnapshot(
  message:
    httpsig.RequestLike | httpsig.ResponseLike | httpsig.ResponseRequestPair,
  profile: httpsig.SignatureInputProfile | undefined,
  limitOverrides: Partial<httpsig.SignatureLimits> | undefined
): {
  readonly message:
    httpsig.RequestLike | httpsig.ResponseLike | httpsig.ResponseRequestPair;
  readonly input: ReturnType<typeof httpsig.parseSignatureInputField>[number];
  readonly signatureAgent: string;
} {
  const current = httpsig.resolveMessageKind(message);
  const currentHeaders = current.headers;
  const limits = httpsig.resolveSignatureLimits(limitOverrides);
  const budget: SnapshotBudget = { occurrences: 0, bytes: 0, limits };
  const signatureInputValue = readHeaderSnapshot(
    currentHeaders,
    "signature-input",
    budget,
    limits.maxSignatureInputBytes
  );
  const signatureInput = httpsig.extractHeader(
    { status: 0, headers: { "signature-input": signatureInputValue } },
    "signature-input"
  );
  const signatureValue = readHeaderSnapshot(
    currentHeaders,
    "signature",
    budget,
    limits.maxSignatureBytes
  );
  const signatureAgentValue = readHeaderSnapshot(
    currentHeaders,
    SIGNATURE_AGENT_HEADER,
    budget
  );
  const signatureAgent = httpsig.extractHeader(
    { status: 0, headers: { [SIGNATURE_AGENT_HEADER]: signatureAgentValue } },
    SIGNATURE_AGENT_HEADER
  );
  const parsedInputs = httpsig.parseSignatureInputField(
    signatureInput,
    profile,
    limitOverrides
  );
  const input = parsedInputs[0];
  if (parsedInputs.length !== 1 || input === undefined)
    throw new Error("exactly one signature is required");
  validateVerificationSignatureAgentSection(input.components);

  const responsePlan: SnapshotPlan = {
    headers: new Set(["signature-input", "signature", SIGNATURE_AGENT_HEADER]),
    trailers: new Set(),
  };
  const requestPlan: SnapshotPlan = {
    headers: new Set(["host"]),
    trailers: new Set(),
  };
  for (const component of input.components) {
    const usesRequest = component.parameters.some(({ name }) => name === "req");
    addComponentToPlan(usesRequest ? requestPlan : responsePlan, component);
  }
  const preloaded = new Map<string, httpsig.HeaderValue>([
    ["signature-input", signatureInputValue],
    ["signature", signatureValue],
    [SIGNATURE_AGENT_HEADER, signatureAgentValue],
  ]);

  if (httpsig.isRawMessage(message)) {
    for (const component of input.components) {
      if (component.parameters.some(({ name }) => name === "req"))
        throw new Error(
          "`req` component parameter can only be used with ResponseRequestPair message types"
        );
    }
    const plan: SnapshotPlan = {
      headers: new Set(
        "method" in message
          ? [...responsePlan.headers, ...requestPlan.headers]
          : responsePlan.headers
      ),
      trailers: new Set(responsePlan.trailers),
    };
    return {
      message:
        "method" in message
          ? snapshotRequest(message, plan, budget, preloaded, currentHeaders)
          : snapshotResponse(message, plan, budget, preloaded, currentHeaders),
      input,
      signatureAgent,
    };
  }
  if (!("status" in current)) throw new Error("invalid response/request pair");
  return {
    message: {
      response: snapshotResponse(
        current,
        responsePlan,
        budget,
        preloaded,
        currentHeaders
      ),
      request: snapshotRequest(message.request, requestPlan, budget),
    },
    input,
    signatureAgent,
  };
}

function immutableCustomParameters(
  parameters: readonly httpsig.SfParameter[]
): readonly httpsig.SfParameter[] {
  return Object.freeze(
    parameters.map(({ name, value }) =>
      Object.freeze({
        name,
        value:
          value.type === "bytes"
            ? Object.freeze({ type: "bytes", value: value.value.slice() })
            : Object.freeze({ ...value }),
      })
    )
  );
}

export async function verify<T>(
  message:
    httpsig.RequestLike | httpsig.ResponseLike | httpsig.ResponseRequestPair,
  verifier: Verify<T>,
  policy: VerificationPolicy = {}
): Promise<T> {
  const snapshot = verificationSnapshot(
    message,
    policy.signatureInputProfile,
    policy.limits
  );
  const signatureAgent = snapshot.signatureAgent;
  const parsedInput = snapshot.input;
  const customParameters = immutableCustomParameters(
    parsedInput.parameters.filter(({ name }) => !RESERVED_PARAMETERS.has(name))
  );
  for (const required of policy.requiredCustomParameters ?? []) {
    if (!customParameters.some(({ name }) => name === required)) {
      throw new Error(`custom parameter ${required} is required`);
    }
  }
  const v = (
    data: string,
    signature: Uint8Array,
    params: httpsig.Parameters,
    components: httpsig.Component[]
  ): T | Promise<T> => {
    if (params.tag !== HTTP_MESSAGE_SIGNATURE_TAG) {
      throw new Error(`tag must be '${HTTP_MESSAGE_SIGNATURE_TAG}'`);
    }
    if (params.alg === undefined) {
      throw new Error("alg MUST be defined");
    }
    const alg = verificationAlgorithm(params.alg);
    if (alg !== verifier.alg) {
      throw new Error(
        `Signature algorithm ${alg} does not match verifier algorithm ${verifier.alg}`
      );
    }
    if (params.created === undefined) {
      throw new Error("created MUST be defined");
    }
    const createdTime = params.created.getTime();
    if (!Number.isFinite(createdTime)) {
      throw new Error("created timestamp is outside JavaScript Date range");
    }
    if (params.expires === undefined) {
      throw new Error("expires MUST be defined");
    }
    const expiresTime = params.expires.getTime();
    if (!Number.isFinite(expiresTime)) {
      throw new Error("expires timestamp is outside JavaScript Date range");
    }
    if (createdTime > Date.now()) {
      throw new Error("created in the future");
    }
    if (expiresTime < Date.now()) {
      throw new Error("signature has expired");
    }
    if (params.keyid === undefined) {
      throw new Error("keyid MUST be defined");
    }
    // A signature that covers no request target can be replayed against any
    // endpoint. Require @authority or @target-uri, and signature-agent whenever
    // the header is present. Mirrors crates/web-bot-auth/src/lib.rs.
    const covered = components.map((c) =>
      (typeof c === "string"
        ? c
        : "header" in c
          ? c.header
          : c.name
      ).toLowerCase()
    );
    if (!covered.includes("@authority") && !covered.includes("@target-uri")) {
      throw new Error("signature must cover @authority or @target-uri");
    }
    if (signatureAgent && !covered.includes(SIGNATURE_AGENT_HEADER)) {
      throw new Error(
        `signature with ${SIGNATURE_AGENT_HEADER} header must cover ${SIGNATURE_AGENT_HEADER}`
      );
    }
    const vparams: VerificationParams = Object.freeze({
      keyid: params.keyid,
      alg,
      created: new Date(createdTime),
      expires: new Date(expiresTime),
      tag: params.tag,
      nonce: params.nonce,
      customParameters,
    });
    return verifier(data, signature, vparams);
  };
  return httpsig.verify(snapshot.message, v, {
    signatureInputProfile: policy.signatureInputProfile,
    limits: policy.limits,
  });
}

export interface Directory extends httpsig.Directory {
  purpose: string;
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
