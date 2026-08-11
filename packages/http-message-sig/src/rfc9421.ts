import { encode as encodeBase64 } from "./base64";
import {
  parseDictionary,
  serializeBareItem,
  serializeDictionary,
  serializeMember,
  serializeParameters,
  type BareItem,
  type SfDictionaryEntry,
  type SfInnerList,
  type SfParameter,
  StructuredFieldLimitError,
  type StructuredFieldRevision,
} from "./structured-fields";
import { dateFromIntegerSeconds } from "./timestamps";
import type { Algorithm } from "./types";

export type SignatureInputProfile = "rfc9421" | "rfc9651-extension";
export type StructuredFieldType = "item" | "list" | "dictionary";

export interface FieldOccurrence {
  readonly name: string;
  readonly value: string;
  readonly bytes?: Uint8Array;
  readonly structuredType?: StructuredFieldType;
}

export interface HttpRequest {
  readonly kind: "request";
  readonly method: string;
  readonly targetUri: string;
  readonly requestTarget?: string;
  readonly fields: readonly FieldOccurrence[];
  readonly trailers?: readonly FieldOccurrence[];
}

export interface HttpResponse {
  readonly kind: "response";
  readonly status: number;
  readonly fields: readonly FieldOccurrence[];
  readonly trailers?: readonly FieldOccurrence[];
  readonly request?: HttpRequest;
}

export type HttpMessage = HttpRequest | HttpResponse;

export interface CoveredComponent {
  readonly name: string;
  readonly parameters: readonly SfParameter[];
}

export interface SignatureInput {
  readonly label: string;
  readonly components: readonly CoveredComponent[];
  readonly parameters: readonly SfParameter[];
}

export interface ParsedSignature {
  readonly label: string;
  readonly bytes: Uint8Array;
}

export interface SignatureFields {
  readonly signature: string;
  readonly signatureInput: string;
}

export interface SignatureBaseOptions {
  readonly coveredFieldRevision?: StructuredFieldRevision;
  readonly signatureInputProfile?: SignatureInputProfile;
  readonly limits?: Partial<SignatureLimits>;
}

export interface SignatureLimits {
  readonly maxSignatureInputBytes: number;
  readonly maxSignatureBytes: number;
  readonly maxSignatures: number;
  readonly maxComponentsPerSignature: number;
  readonly maxParametersPerSignature: number;
  readonly maxComponentParameters: number;
  readonly maxFieldOccurrences: number;
  readonly maxFieldBytes: number;
  readonly maxTargetUriBytes: number;
  readonly maxSignatureBaseBytes: number;
}

export const DEFAULT_SIGNATURE_LIMITS: SignatureLimits = Object.freeze({
  maxSignatureInputBytes: 65_536,
  maxSignatureBytes: 65_536,
  maxSignatures: 32,
  maxComponentsPerSignature: 64,
  maxParametersPerSignature: 32,
  maxComponentParameters: 8,
  maxFieldOccurrences: 256,
  maxFieldBytes: 1_048_576,
  maxTargetUriBytes: 16_384,
  maxSignatureBaseBytes: 1_048_576,
});

export interface ParsedSignatureSet {
  readonly inputs: ReadonlyMap<string, SignatureInput>;
  readonly signatures: ReadonlyMap<string, Uint8Array>;
  readonly labels: readonly string[];
}

export class MessageSignatureError extends Error {
  constructor(
    message: string,
    readonly code:
      | "invalid-component"
      | "invalid-field"
      | "invalid-signature-input"
      | "invalid-signature"
      | "policy"
      | "crypto" = "invalid-signature-input"
  ) {
    super(message);
    this.name = "MessageSignatureError";
  }
}

const FIELD_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const DERIVED_NAME = /^@[a-z][a-z0-9-]*$/;
const LABEL = /^[a-z*][a-z0-9_.*-]*$/;
const REGISTERED_PARAMETERS: Readonly<Record<string, BareItem["type"]>> = {
  created: "integer",
  expires: "integer",
  nonce: "string",
  alg: "string",
  keyid: "string",
  tag: "string",
};

export function resolveSignatureLimits(
  overrides: Partial<SignatureLimits> = {}
): SignatureLimits {
  const result = { ...DEFAULT_SIGNATURE_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(result)) {
    if (!Number.isSafeInteger(value) || value < 1)
      throw new MessageSignatureError(`invalid limit ${name}`, "policy");
  }
  return result;
}

export function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (
      code >= 0xd800 &&
      code <= 0xdbff &&
      index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 &&
      value.charCodeAt(index + 1) <= 0xdfff
    ) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
  }
  return bytes;
}

const byteLength = utf8ByteLength;

export function boundedUtf8ByteLength(
  value: string,
  maximum: number,
  message: string
): number {
  if (value.length > maximum)
    throw new MessageSignatureError(message, "policy");
  const bytes = byteLength(value);
  if (bytes > maximum) throw new MessageSignatureError(message, "policy");
  return bytes;
}

interface MessageBudget {
  occurrences: number;
  stringBytes: number;
  codeUnits: number;
  explicitBytes: number;
}

function denseLength<T>(
  values: readonly T[],
  maximum: number,
  message: string
): number {
  const length = values.length;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum)
    throw new MessageSignatureError(message, "policy");
  for (let index = 0; index < length; index += 1) {
    if (values[index] === undefined)
      throw new MessageSignatureError(`${message}: sparse array`, "policy");
  }
  return length;
}

function fieldLists(
  message: HttpMessage
): readonly (readonly FieldOccurrence[])[] {
  const lists: (readonly FieldOccurrence[])[] = [message.fields];
  if (message.trailers !== undefined) lists.push(message.trailers);
  if (message.kind === "response" && message.request !== undefined) {
    lists.push(message.request.fields);
    if (message.request.trailers !== undefined)
      lists.push(message.request.trailers);
  }
  return lists;
}

function validateFieldLists(
  message: HttpMessage,
  configured: SignatureLimits
): void {
  let remaining = configured.maxFieldOccurrences;
  for (const fields of fieldLists(message)) {
    const length = denseLength(
      fields,
      remaining,
      "field occurrence limit exceeded"
    );
    remaining -= length;
  }
}

function accountField(
  field: FieldOccurrence,
  budget: MessageBudget,
  configured: SignatureLimits
): void {
  budget.occurrences += 1;
  if (budget.occurrences > configured.maxFieldOccurrences)
    throw new MessageSignatureError(
      "field occurrence limit exceeded",
      "policy"
    );
  const name = field.name;
  const bytes = field.bytes;
  const value = field.value;
  const codeUnits = name.length + value.length;
  if (
    budget.codeUnits + codeUnits > configured.maxFieldBytes ||
    budget.stringBytes + codeUnits > configured.maxFieldBytes
  )
    throw new MessageSignatureError("field byte limit exceeded", "policy");
  const nameBytes = boundedUtf8ByteLength(
    name,
    configured.maxFieldBytes - budget.stringBytes,
    "field byte limit exceeded"
  );
  const valueBytes = boundedUtf8ByteLength(
    value,
    configured.maxFieldBytes - budget.stringBytes - nameBytes,
    "field byte limit exceeded"
  );
  if (bytes === undefined) {
    for (let index = 0; index < value.length; index += 1) {
      if (value.charCodeAt(index) > 0xff)
        throw new MessageSignatureError(
          "field value cannot be represented as HTTP bytes",
          "invalid-field"
        );
    }
  } else budget.explicitBytes += bytes.length;
  budget.stringBytes += nameBytes + valueBytes;
  budget.codeUnits += codeUnits;
  if (
    budget.stringBytes > configured.maxFieldBytes ||
    budget.codeUnits > configured.maxFieldBytes ||
    budget.explicitBytes > configured.maxFieldBytes
  )
    throw new MessageSignatureError("field byte limit exceeded", "policy");
}

function enforceMessageLimits(
  message: HttpMessage,
  configured: SignatureLimits
): void {
  const request = message.kind === "request" ? message : message.request;
  if (request !== undefined) enforceRequestTargetLimits(request, configured);
  validateFieldLists(message, configured);
  const budget: MessageBudget = {
    occurrences: 0,
    stringBytes: 0,
    codeUnits: 0,
    explicitBytes: 0,
  };
  for (const field of message.fields) accountField(field, budget, configured);
  for (const field of message.trailers ?? [])
    accountField(field, budget, configured);
  if (message.kind === "response" && message.request !== undefined) {
    for (const field of message.request.fields)
      accountField(field, budget, configured);
    for (const field of message.request.trailers ?? [])
      accountField(field, budget, configured);
  }
}

function enforceInputLimits(
  input: SignatureInput,
  configured: SignatureLimits
): void {
  const declaredComponentCount = input.components.length;
  if (
    !Number.isSafeInteger(declaredComponentCount) ||
    declaredComponentCount < 0 ||
    (declaredComponentCount === 0 ? 0 : declaredComponentCount - 1) >
      configured.maxSignatureInputBytes
  )
    throw new MessageSignatureError(
      "Signature-Input byte limit exceeded",
      "policy"
    );
  const componentCount = denseLength(
    input.components,
    configured.maxComponentsPerSignature,
    "component limit exceeded"
  );
  denseLength(
    input.parameters,
    configured.maxParametersPerSignature,
    "signature parameter limit exceeded"
  );
  for (let index = 0; index < componentCount; index += 1) {
    const component = input.components[index];
    if (component === undefined)
      throw new MessageSignatureError("component limit exceeded", "policy");
    denseLength(
      component.parameters,
      configured.maxComponentParameters,
      "component parameter limit exceeded"
    );
  }
}

function bareItemBytes(
  value: BareItem,
  maximum: number,
  message: string
): number {
  switch (value.type) {
    case "bytes":
      if (value.value.length > maximum)
        throw new MessageSignatureError(message, "policy");
      return value.value.length;
    case "string":
    case "token":
    case "display-string":
    case "decimal":
      return boundedUtf8ByteLength(value.value, maximum, message);
    case "integer":
    case "date":
      if (maximum < 24) throw new MessageSignatureError(message, "policy");
      return 24;
    case "boolean":
      if (maximum < 1) throw new MessageSignatureError(message, "policy");
      return 1;
  }
}

function enforceInputByteBudget(
  input: SignatureInput,
  configured: SignatureLimits
): void {
  inputLogicalBytes(
    input,
    configured,
    configured.maxSignatureInputBytes,
    "Signature-Input byte limit exceeded"
  );
}

function inputLogicalBytes(
  input: SignatureInput,
  configured: SignatureLimits,
  maximum: number,
  message: string
): number {
  let bytes = boundedUtf8ByteLength(input.label, maximum, message);
  const componentCount = denseLength(
    input.components,
    configured.maxComponentsPerSignature,
    "component limit exceeded"
  );
  for (let index = 0; index < componentCount; index += 1) {
    const component = input.components[index];
    if (component === undefined)
      throw new MessageSignatureError("component limit exceeded", "policy");
    bytes += boundedUtf8ByteLength(component.name, maximum - bytes, message);
    const componentParameterCount = denseLength(
      component.parameters,
      configured.maxComponentParameters,
      "component parameter limit exceeded"
    );
    for (
      let parameterIndex = 0;
      parameterIndex < componentParameterCount;
      parameterIndex += 1
    ) {
      const parameter = component.parameters[parameterIndex];
      if (parameter === undefined)
        throw new MessageSignatureError(
          "component parameter limit exceeded",
          "policy"
        );
      bytes += boundedUtf8ByteLength(parameter.name, maximum - bytes, message);
      bytes += bareItemBytes(parameter.value, maximum - bytes, message);
    }
  }
  const parameterCount = denseLength(
    input.parameters,
    configured.maxParametersPerSignature,
    "signature parameter limit exceeded"
  );
  for (let index = 0; index < parameterCount; index += 1) {
    const parameter = input.parameters[index];
    if (parameter === undefined)
      throw new MessageSignatureError(
        "signature parameter limit exceeded",
        "policy"
      );
    bytes += boundedUtf8ByteLength(parameter.name, maximum - bytes, message);
    bytes += bareItemBytes(parameter.value, maximum - bytes, message);
  }
  return bytes;
}

function enforceStructuredParseLimit(error: unknown): void {
  if (!(error instanceof StructuredFieldLimitError)) return;
  switch (error.limit) {
    case "dictionary":
      throw new MessageSignatureError(
        "signature count limit exceeded",
        "policy"
      );
    case "inner-list":
      throw new MessageSignatureError("component limit exceeded", "policy");
    case "item-parameters":
      throw new MessageSignatureError(
        "component parameter limit exceeded",
        "policy"
      );
    case "member-parameters":
      throw new MessageSignatureError(
        "signature parameter limit exceeded",
        "policy"
      );
  }
}

function parameter(
  component: CoveredComponent,
  name: string
): BareItem | undefined {
  return component.parameters.find((candidate) => candidate.name === name)
    ?.value;
}

function enabled(component: CoveredComponent, name: string): boolean {
  const value = parameter(component, name);
  return value?.type === "boolean" && value.value;
}

function validateComponent(
  component: CoveredComponent,
  configured: SignatureLimits
): void {
  const derived = component.name.startsWith("@");
  if (
    derived
      ? !DERIVED_NAME.test(component.name)
      : !FIELD_NAME.test(component.name)
  )
    throw new MessageSignatureError(
      "invalid component name",
      "invalid-component"
    );
  const seen = new Set<string>();
  denseLength(
    component.parameters,
    configured.maxComponentParameters,
    "component parameter limit exceeded"
  );
  for (const { name, value } of component.parameters) {
    if (seen.has(name))
      throw new MessageSignatureError(
        "duplicate component parameter",
        "invalid-component"
      );
    seen.add(name);
    const legal = derived
      ? component.name === "@query-param"
        ? name === "name" || name === "req"
        : name === "req"
      : ["sf", "key", "bs", "tr", "req"].includes(name);
    if (!legal)
      throw new MessageSignatureError(
        `illegal component parameter ${name}`,
        "invalid-component"
      );
    if (name === "name" || name === "key") {
      if (value.type !== "string")
        throw new MessageSignatureError(
          `${name} must be a string`,
          "invalid-component"
        );
    } else if (value.type !== "boolean" || !value.value) {
      throw new MessageSignatureError(
        `${name} must be boolean true`,
        "invalid-component"
      );
    }
  }
  if (
    component.name === "@query-param" &&
    parameter(component, "name")?.type !== "string"
  )
    throw new MessageSignatureError(
      "@query-param requires name",
      "invalid-component"
    );
  if (
    !derived &&
    enabled(component, "bs") &&
    (enabled(component, "sf") || parameter(component, "key") !== undefined)
  )
    throw new MessageSignatureError(
      "bs is incompatible with sf and key",
      "invalid-component"
    );
}

export function serializeComponentIdentifier(
  component: CoveredComponent,
  limitOverrides: Partial<SignatureLimits> = {}
): string {
  const configured = resolveSignatureLimits(limitOverrides);
  return serializeComponentIdentifierWithLimits(component, configured);
}

function serializeComponentIdentifierWithLimits(
  component: CoveredComponent,
  configured: SignatureLimits
): string {
  validateComponent(component, configured);
  return `${serializeBareItem({ type: "string", value: component.name.toLowerCase() }, "rfc8941")}${serializeParameters(component.parameters, "rfc8941")}`;
}

function validateSignatureParameters(
  parameters: readonly SfParameter[],
  accept: boolean
): void {
  const seen = new Set<string>();
  for (const { name, value } of parameters) {
    if (seen.has(name))
      throw new MessageSignatureError(
        "duplicate signature parameter",
        "invalid-signature-input"
      );
    seen.add(name);
    const expected = REGISTERED_PARAMETERS[name];
    if (accept && (name === "created" || name === "expires")) {
      if (value.type !== "boolean" || !value.value)
        throw new MessageSignatureError(
          `${name} must be bare true in Accept-Signature`,
          "invalid-signature-input"
        );
      continue;
    }
    if (expected !== undefined && value.type !== expected)
      throw new MessageSignatureError(
        `${name} must be ${expected}`,
        "invalid-signature-input"
      );
  }
}

export function serializeSignatureParams(
  components: readonly CoveredComponent[],
  parameters: readonly SfParameter[],
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): string {
  return serializeSignatureParameters(
    components,
    parameters,
    profile,
    false,
    resolveSignatureLimits(limitOverrides)
  );
}

function serializeSignatureParameters(
  components: readonly CoveredComponent[],
  parameters: readonly SfParameter[],
  profile: SignatureInputProfile,
  accept: boolean,
  configured: SignatureLimits
): string {
  denseLength(
    components,
    configured.maxComponentsPerSignature,
    "component limit exceeded"
  );
  denseLength(
    parameters,
    configured.maxParametersPerSignature,
    "signature parameter limit exceeded"
  );
  validateSignatureParameters(parameters, accept);
  const identifiers = components.map((component) =>
    serializeComponentIdentifierWithLimits(component, configured)
  );
  const equivalents = identifiers.map((identifier) => {
    const parts = identifier.split(";");
    const name = parts.shift() ?? "";
    return [name, ...parts.sort()].join(";");
  });
  if (new Set(equivalents).size !== equivalents.length)
    throw new MessageSignatureError(
      "duplicate component identifier",
      "invalid-component"
    );
  const revision = profile === "rfc9421" ? "rfc8941" : "rfc9651";
  const output = `(${identifiers.join(" ")})${serializeParameters(parameters, revision)}`;
  boundedUtf8ByteLength(
    output,
    configured.maxSignatureInputBytes,
    "Signature-Input byte limit exceeded"
  );
  return output;
}

function sourceMessage(
  message: HttpMessage,
  component: CoveredComponent
): HttpMessage {
  if (!enabled(component, "req")) return message;
  if (message.kind !== "response" || message.request === undefined)
    throw new MessageSignatureError(
      "req requires a request-bound response",
      "invalid-component"
    );
  return message.request;
}

function occurrences(
  message: HttpMessage,
  component: CoveredComponent
): readonly FieldOccurrence[] {
  return enabled(component, "tr") ? (message.trailers ?? []) : message.fields;
}

export function normalizeFieldValue(value: string): string {
  const unfolded = value.replace(/\r\n[\t ]+/g, " ");
  if (/[\r\n]/.test(unfolded))
    throw new MessageSignatureError(
      "field value contains CR or LF",
      "invalid-field"
    );
  return unfolded.replace(/^[\t ]+|[\t ]+$/g, "");
}

export function httpFieldBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code > 0xff)
      throw new MessageSignatureError(
        "field value cannot be represented as HTTP bytes",
        "invalid-field"
      );
    bytes[index] = code;
  }
  return bytes;
}

export function normalizeFieldBytes(value: string | Uint8Array): Uint8Array {
  if (typeof value === "string")
    return httpFieldBytes(normalizeFieldValue(value));
  const unfolded = new Uint8Array(value.length);
  let length = 0;
  for (let index = 0; index < value.length; index += 1) {
    const byte = value[index];
    if (byte === undefined) break;
    if (byte === 0x0d) {
      if (
        value[index + 1] !== 0x0a ||
        (value[index + 2] !== 0x20 && value[index + 2] !== 0x09)
      )
        throw new MessageSignatureError(
          "field bytes contain invalid CR or LF",
          "invalid-field"
        );
      unfolded[length] = 0x20;
      length += 1;
      index += 2;
      while (value[index + 1] === 0x20 || value[index + 1] === 0x09) index += 1;
      continue;
    }
    if (byte === 0x0a)
      throw new MessageSignatureError(
        "field bytes contain invalid CR or LF",
        "invalid-field"
      );
    unfolded[length] = byte;
    length += 1;
  }
  let start = 0;
  while (
    start < length &&
    (unfolded[start] === 0x20 || unfolded[start] === 0x09)
  )
    start += 1;
  let end = length;
  while (
    end > start &&
    (unfolded[end - 1] === 0x20 || unfolded[end - 1] === 0x09)
  )
    end -= 1;
  return unfolded.slice(start, end);
}

function canonicalStructuredField(
  value: string,
  type: StructuredFieldType,
  revision: StructuredFieldRevision
): string {
  if (type === "dictionary")
    return serializeDictionary(parseDictionary(value, revision), revision);
  if (type === "list")
    return serializeStructuredList(
      parseStructuredList(value, revision),
      revision
    );
  return serializeStructuredItem(
    parseStructuredItem(value, revision),
    revision
  );
}

import {
  parseItem as parseStructuredItem,
  parseList as parseStructuredList,
  serializeItem as serializeStructuredItem,
  serializeList as serializeStructuredList,
} from "./structured-fields";

function dictionaryMember(
  value: string,
  key: string,
  revision: StructuredFieldRevision
): string {
  const entry = parseDictionary(value, revision).find(
    (candidate) => candidate.key === key
  );
  if (entry === undefined)
    throw new MessageSignatureError(
      `missing dictionary key ${key}`,
      "invalid-field"
    );
  return serializeMember(entry.value, revision);
}

function fieldValue(
  message: HttpMessage,
  component: CoveredComponent,
  revision: StructuredFieldRevision
): string {
  const matching = occurrences(message, component).filter(
    ({ name }) => name.toLowerCase() === component.name.toLowerCase()
  );
  if (matching.length === 0)
    throw new MessageSignatureError(
      `missing field ${component.name}`,
      "invalid-field"
    );
  if (enabled(component, "bs")) {
    return matching
      .map(
        ({ value, bytes }) =>
          `:${encodeBase64(normalizeFieldBytes(bytes === undefined ? value : bytes))}:`
      )
      .join(", ");
  }
  const values = matching.map(({ value }) => normalizeFieldValue(value));
  const combined = values.join(", ");
  const key = parameter(component, "key");
  if (key?.type === "string")
    return dictionaryMember(combined, key.value, revision);
  if (enabled(component, "sf")) {
    const type = matching.find(
      ({ structuredType }) => structuredType !== undefined
    )?.structuredType;
    if (type === undefined)
      throw new MessageSignatureError(
        "sf requires a field schema",
        "invalid-field"
      );
    return canonicalStructuredField(combined, type, revision);
  }
  return values.join(", ");
}

function componentLogicalBytes(
  message: HttpMessage,
  component: CoveredComponent
): number {
  const source = sourceMessage(message, component);
  if (!component.name.startsWith("@")) {
    let bytes = 0;
    for (const field of occurrences(source, component)) {
      if (field.name.toLowerCase() !== component.name.toLowerCase()) continue;
      const representation =
        field.bytes === undefined
          ? byteLength(field.value)
          : Math.max(byteLength(field.value), field.bytes.length);
      bytes += enabled(component, "bs")
        ? representation * 2 + 2
        : representation;
    }
    return bytes;
  }
  if (source.kind === "response") return 3;
  switch (component.name) {
    case "@method":
      return byteLength(source.method);
    case "@query-param":
      return byteLength(source.targetUri) * 3;
    default:
      return Math.max(
        byteLength(source.targetUri),
        byteLength(source.requestTarget ?? "")
      );
  }
}

function formEncode(value: string): string {
  let encoded = "";
  for (const byte of new TextEncoder().encode(value)) {
    const unescaped =
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      [0x2a, 0x2d, 0x2e, 0x5f].includes(byte);
    encoded += unescaped
      ? String.fromCharCode(byte)
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}

interface RawTargetUri {
  readonly scheme: string;
  readonly authority: string;
  readonly path: string;
  readonly query?: string;
}

function normalizeHost(value: string): string {
  let result = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === undefined) break;
    if (
      character === "%" &&
      /^[0-9A-Fa-f]{2}$/.test(value.slice(index + 1, index + 3))
    ) {
      result += value.slice(index, index + 3);
      index += 2;
    } else result += character.toLowerCase();
  }
  return result;
}

interface ParsedAuthority {
  readonly normalized: string;
  readonly hasPort: boolean;
}

function invalidAuthority(message: string): never {
  throw new MessageSignatureError(message, "invalid-component");
}

function validateIpLiteral(value: string): void {
  if (/^v[0-9A-F]+\.[A-Z0-9._~!$&'()*+,;=:-]+$/i.test(value)) return;
  if (!/^[0-9A-Fa-f:.]+$/.test(value))
    invalidAuthority("invalid IPv6 authority");
  try {
    new URL(`http://[${value}]/`);
  } catch {
    invalidAuthority("invalid IPv6 authority");
  }
}

function validateRegNameOrIpv4(value: string): void {
  if (!/^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+$/.test(value))
    invalidAuthority("invalid authority host");
  const ipv4Parts = value.split(".");
  if (ipv4Parts.length !== 4 || !ipv4Parts.every((part) => /^\d+$/.test(part)))
    return;
  for (const part of ipv4Parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)
      invalidAuthority("invalid authority host");
  }
}

function parseAuthority(
  rawAuthority: string,
  scheme?: string
): ParsedAuthority {
  if (rawAuthority === "" || rawAuthority.includes("@"))
    invalidAuthority("target URI has invalid authority");
  let host: string;
  let port: string | undefined;
  if (rawAuthority.startsWith("[")) {
    const bracket = rawAuthority.indexOf("]");
    if (bracket < 0) invalidAuthority("invalid IPv6 authority");
    const literal = rawAuthority.slice(1, bracket);
    validateIpLiteral(literal);
    host = normalizeHost(rawAuthority.slice(0, bracket + 1));
    const suffix = rawAuthority.slice(bracket + 1);
    if (suffix !== "") {
      if (!/^:[0-9]+$/.test(suffix)) invalidAuthority("invalid authority port");
      port = suffix.slice(1);
    }
  } else {
    const colon = rawAuthority.lastIndexOf(":");
    const rawHost = colon < 0 ? rawAuthority : rawAuthority.slice(0, colon);
    if (colon >= 0) {
      const candidate = rawAuthority.slice(colon + 1);
      if (!/^[0-9]+$/.test(candidate))
        invalidAuthority("invalid authority port");
      port = candidate;
    }
    validateRegNameOrIpv4(rawHost);
    host = normalizeHost(rawHost);
  }
  const hasPort = port !== undefined;
  if (port !== undefined) {
    const numericPort = Number(port);
    if (!Number.isSafeInteger(numericPort) || numericPort > 65_535)
      invalidAuthority("invalid authority port");
    port =
      (scheme === "http" && numericPort === 80) ||
      (scheme === "https" && numericPort === 443)
        ? undefined
        : numericPort.toString();
  }
  return {
    normalized: `${host}${port === undefined ? "" : `:${port}`}`,
    hasPort,
  };
}

function rawTargetUri(source: string): RawTargetUri {
  if (!/^[\x21-\x7e]+$/.test(source))
    throw new MessageSignatureError(
      "target URI contains invalid characters",
      "invalid-component"
    );
  for (
    let index = source.indexOf("%");
    index >= 0;
    index = source.indexOf("%", index + 1)
  ) {
    if (!/^[0-9A-Fa-f]{2}$/.test(source.slice(index + 1, index + 3)))
      throw new MessageSignatureError(
        "target URI contains invalid percent encoding",
        "invalid-component"
      );
  }
  if (source.includes("#"))
    throw new MessageSignatureError(
      "target URI must not contain a fragment",
      "invalid-component"
    );
  const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(source);
  const schemeSource = schemeMatch?.[1];
  if (schemeMatch === null || schemeSource === undefined)
    throw new MessageSignatureError(
      "target URI must be absolute",
      "invalid-component"
    );
  const authorityStart = schemeMatch[0].length;
  const authorityEndCandidate = source.slice(authorityStart).search(/[/?]/);
  const authorityEnd =
    authorityEndCandidate < 0
      ? source.length
      : authorityStart + authorityEndCandidate;
  const rawAuthority = source.slice(authorityStart, authorityEnd);
  const remainder = source.slice(authorityEnd);
  const queryIndex = remainder.indexOf("?");
  const pathSource =
    queryIndex < 0 ? remainder : remainder.slice(0, queryIndex);
  const query = queryIndex < 0 ? undefined : remainder.slice(queryIndex);
  const path = pathSource === "" ? "/" : pathSource;
  if (!path.startsWith("/"))
    throw new MessageSignatureError(
      "target URI path must be absolute",
      "invalid-component"
    );

  const scheme = schemeSource.toLowerCase();
  const authority = parseAuthority(rawAuthority, scheme);
  return {
    scheme,
    authority: authority.normalized,
    path,
    query,
  };
}

type RequestTargetForm = "origin" | "absolute" | "authority" | "asterisk";

function requestTargetForm(value: string): RequestTargetForm {
  if (value === "*") return "asterisk";
  if (!/^[\x21-\x7e]+$/.test(value) || value.includes("#"))
    throw new MessageSignatureError(
      "invalid request target",
      "invalid-component"
    );
  for (
    let index = value.indexOf("%");
    index >= 0;
    index = value.indexOf("%", index + 1)
  ) {
    if (!/^[0-9A-Fa-f]{2}$/.test(value.slice(index + 1, index + 3)))
      throw new MessageSignatureError(
        "request target contains invalid percent encoding",
        "invalid-component"
      );
  }
  if (value.startsWith("/")) return "origin";
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)) {
    rawTargetUri(value);
    return "absolute";
  }
  if (value.includes(":")) {
    const authority = parseAuthority(value);
    if (!authority.hasPort)
      throw new MessageSignatureError(
        "authority-form request target requires a port",
        "invalid-component"
      );
    return "authority";
  }
  throw new MessageSignatureError(
    "invalid request target form",
    "invalid-component"
  );
}

export function validateRequestTarget(method: string, value: string): void {
  const form = requestTargetForm(value);
  const normalizedMethod = method.toUpperCase();
  if (normalizedMethod === "CONNECT" && form !== "authority")
    throw new MessageSignatureError(
      "CONNECT requires authority-form request target",
      "invalid-component"
    );
  if (normalizedMethod !== "CONNECT" && form === "authority")
    throw new MessageSignatureError(
      "authority-form request target requires CONNECT",
      "invalid-component"
    );
  if (form === "asterisk" && normalizedMethod !== "OPTIONS")
    throw new MessageSignatureError(
      "asterisk-form request target requires OPTIONS",
      "invalid-component"
    );
}

function requestTargetValue(request: HttpRequest): string {
  if (request.requestTarget !== undefined) {
    validateRequestTarget(request.method, request.requestTarget);
    return request.requestTarget;
  }
  const target = rawTargetUri(request.targetUri);
  const value = `${target.path}${target.query ?? ""}`;
  validateRequestTarget(request.method, value);
  return value;
}

function enforceRequestTargetLimits(
  request: HttpRequest,
  configured: SignatureLimits
): void {
  boundedUtf8ByteLength(
    request.targetUri,
    configured.maxTargetUriBytes,
    "target URI byte limit exceeded"
  );
  rawTargetUri(request.targetUri);
  if (request.requestTarget !== undefined) {
    boundedUtf8ByteLength(
      request.requestTarget,
      configured.maxTargetUriBytes,
      "request target byte limit exceeded"
    );
    validateRequestTarget(request.method, request.requestTarget);
  }
}

function decodeFormComponent(value: string): string {
  const bytes: number[] = [];
  for (let index = 0; index < value.length;) {
    const character = value[index];
    if (character === undefined) break;
    if (character === "%") {
      const hex = value.slice(index + 1, index + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex))
        throw new MessageSignatureError(
          "invalid query percent encoding",
          "invalid-component"
        );
      bytes.push(Number.parseInt(hex, 16));
      index += 3;
      continue;
    }
    if (character === "+") bytes.push(0x20);
    else {
      const codePoint = value.codePointAt(index);
      if (codePoint === undefined) break;
      const decoded = String.fromCodePoint(codePoint);
      bytes.push(...new TextEncoder().encode(decoded));
      index += decoded.length;
      continue;
    }
    index += 1;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(bytes)
    );
  } catch {
    throw new MessageSignatureError("invalid query UTF-8", "invalid-component");
  }
}

function rawQueryParameters(
  query: string | undefined
): readonly [string, string][] {
  if (query === undefined || query.length === 1) return [];
  return query
    .slice(1)
    .split("&")
    .map((part) => {
      const equals = part.indexOf("=");
      return equals < 0
        ? [decodeFormComponent(part), ""]
        : [
            decodeFormComponent(part.slice(0, equals)),
            decodeFormComponent(part.slice(equals + 1)),
          ];
    });
}

function requestComponentValue(
  request: HttpRequest,
  component: CoveredComponent
): string {
  if (component.name === "@method") return request.method;
  const target = rawTargetUri(request.targetUri);
  switch (component.name) {
    case "@target-uri":
      return request.targetUri;
    case "@authority":
      return target.authority;
    case "@scheme":
      return target.scheme;
    case "@request-target":
      return requestTargetValue(request);
    case "@path":
      return target.path;
    case "@query":
      return target.query ?? "?";
    case "@query-param": {
      const name = parameter(component, "name");
      if (name?.type !== "string")
        throw new MessageSignatureError(
          "@query-param requires name",
          "invalid-component"
        );
      const matches = rawQueryParameters(target.query).filter(
        ([key]) => formEncode(key) === name.value
      );
      if (matches.length !== 1)
        throw new MessageSignatureError(
          "query parameter must occur exactly once",
          "invalid-component"
        );
      const match = matches[0];
      if (match === undefined)
        throw new MessageSignatureError(
          "query parameter absent",
          "invalid-component"
        );
      return formEncode(match[1]);
    }
    case "@status":
      throw new MessageSignatureError(
        "@status is response only",
        "invalid-component"
      );
    default:
      throw new MessageSignatureError(
        `unknown derived component ${component.name}`,
        "invalid-component"
      );
  }
}

export function componentValue(
  message: HttpMessage,
  component: CoveredComponent,
  revision: StructuredFieldRevision = "rfc8941",
  limitOverrides: Partial<SignatureLimits> = {}
): string {
  validateComponent(component, resolveSignatureLimits(limitOverrides));
  const source = sourceMessage(message, component);
  if (!component.name.startsWith("@"))
    return fieldValue(source, component, revision);
  if (source.kind === "request")
    return requestComponentValue(source, component);
  if (component.name === "@status") return source.status.toString();
  throw new MessageSignatureError(
    `${component.name} is request only`,
    "invalid-component"
  );
}

export function buildSignatureBase(
  message: HttpMessage,
  components: readonly CoveredComponent[],
  parameters: readonly SfParameter[],
  options: SignatureBaseOptions = {}
): string {
  const configured = resolveSignatureLimits(options.limits);
  enforceMessageLimits(message, configured);
  const baseInput = { label: "base", components, parameters };
  enforceInputLimits(baseInput, configured);
  enforceInputByteBudget(baseInput, configured);
  inputLogicalBytes(
    baseInput,
    configured,
    configured.maxSignatureBaseBytes,
    "signature base byte limit exceeded"
  );
  const signatureParams = serializeSignatureParams(
    components,
    parameters,
    options.signatureInputProfile,
    options.limits
  );
  const lines: string[] = [];
  let baseBytes = 0;
  const addLine = (identifier: string, value: string): void => {
    baseBytes +=
      byteLength(identifier) +
      2 +
      byteLength(value) +
      (lines.length === 0 ? 0 : 1);
    if (baseBytes > configured.maxSignatureBaseBytes)
      throw new MessageSignatureError(
        "signature base byte limit exceeded",
        "policy"
      );
    lines.push(`${identifier}: ${value}`);
  };
  for (const component of components) {
    const identifier = serializeComponentIdentifier(component, options.limits);
    if (
      baseBytes +
        byteLength(identifier) +
        2 +
        componentLogicalBytes(message, component) +
        (lines.length === 0 ? 0 : 1) >
      configured.maxSignatureBaseBytes
    )
      throw new MessageSignatureError(
        "signature base byte limit exceeded",
        "policy"
      );
    const value = componentValue(
      message,
      component,
      options.coveredFieldRevision,
      options.limits
    );
    addLine(identifier, value);
  }
  addLine('"@signature-params"', signatureParams);
  return lines.join("\n");
}

function signatureInputFromMember(
  label: string,
  member: SfDictionaryEntry["value"],
  profile: SignatureInputProfile,
  accept: boolean,
  configured: SignatureLimits
): SignatureInput {
  if (member.kind !== "inner-list")
    throw new MessageSignatureError(
      "Signature-Input member must be an inner list",
      "invalid-signature-input"
    );
  const components = member.items.map(({ value, parameters }) => {
    if (value.type !== "string")
      throw new MessageSignatureError(
        "covered component must be a string",
        "invalid-signature-input"
      );
    if (
      !value.value.startsWith("@") &&
      value.value !== value.value.toLowerCase()
    )
      throw new MessageSignatureError(
        "field component name must be lowercase",
        "invalid-component"
      );
    return { name: value.value, parameters };
  });
  for (const component of components) validateComponent(component, configured);
  serializeSignatureParameters(
    components,
    member.parameters,
    profile,
    accept,
    configured
  );
  return { label, components, parameters: member.parameters };
}

export function parseSignatureInputField(
  source: string,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): readonly SignatureInput[] {
  const configured = resolveSignatureLimits(limitOverrides);
  boundedUtf8ByteLength(
    source,
    configured.maxSignatureInputBytes,
    "Signature-Input byte limit exceeded"
  );
  const revision = profile === "rfc9421" ? "rfc8941" : "rfc9651";
  try {
    const entries = parseDictionary(source, revision, {
      maxDictionaryMembers: configured.maxSignatures,
      maxInnerListItems: configured.maxComponentsPerSignature,
      maxItemParameters: configured.maxComponentParameters,
      maxMemberParameters: configured.maxParametersPerSignature,
    });
    if (entries.length > configured.maxSignatures)
      throw new MessageSignatureError(
        "signature count limit exceeded",
        "policy"
      );
    return entries.map(({ key, value }) => {
      if (value.kind === "inner-list") {
        if (value.items.length > configured.maxComponentsPerSignature)
          throw new MessageSignatureError("component limit exceeded", "policy");
        if (value.parameters.length > configured.maxParametersPerSignature)
          throw new MessageSignatureError(
            "signature parameter limit exceeded",
            "policy"
          );
        if (
          value.items.some(
            ({ parameters }) =>
              parameters.length > configured.maxComponentParameters
          )
        )
          throw new MessageSignatureError(
            "component parameter limit exceeded",
            "policy"
          );
      }
      return signatureInputFromMember(key, value, profile, false, configured);
    });
  } catch (error) {
    if (error instanceof MessageSignatureError) throw error;
    enforceStructuredParseLimit(error);
    throw new MessageSignatureError(
      `invalid Signature-Input: ${error instanceof Error ? error.message : String(error)}`,
      "invalid-signature-input"
    );
  }
}

export function parseAcceptSignatureField(
  source: string,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): readonly SignatureInput[] {
  const configured = resolveSignatureLimits(limitOverrides);
  boundedUtf8ByteLength(
    source,
    configured.maxSignatureInputBytes,
    "Accept-Signature byte limit exceeded"
  );
  const revision = profile === "rfc9421" ? "rfc8941" : "rfc9651";
  try {
    const entries = parseDictionary(source, revision, {
      maxDictionaryMembers: configured.maxSignatures,
      maxInnerListItems: configured.maxComponentsPerSignature,
      maxItemParameters: configured.maxComponentParameters,
      maxMemberParameters: configured.maxParametersPerSignature,
    });
    if (entries.length > configured.maxSignatures)
      throw new MessageSignatureError(
        "signature count limit exceeded",
        "policy"
      );
    return entries.map(({ key, value }) => {
      if (value.kind === "inner-list") {
        if (value.items.length > configured.maxComponentsPerSignature)
          throw new MessageSignatureError("component limit exceeded", "policy");
        if (value.parameters.length > configured.maxParametersPerSignature)
          throw new MessageSignatureError(
            "signature parameter limit exceeded",
            "policy"
          );
        if (
          value.items.some(
            ({ parameters }) =>
              parameters.length > configured.maxComponentParameters
          )
        )
          throw new MessageSignatureError(
            "component parameter limit exceeded",
            "policy"
          );
      }
      return signatureInputFromMember(key, value, profile, true, configured);
    });
  } catch (error) {
    if (error instanceof MessageSignatureError) throw error;
    enforceStructuredParseLimit(error);
    throw new MessageSignatureError(
      `invalid Accept-Signature: ${error instanceof Error ? error.message : String(error)}`,
      "invalid-signature-input"
    );
  }
}

export function listAcceptSignatures(
  source: string,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): readonly string[] {
  return parseAcceptSignatureField(source, profile, limitOverrides).map(
    ({ label }) => label
  );
}

export function selectAcceptSignature(
  source: string,
  label: string,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): SignatureInput {
  const input = parseAcceptSignatureField(source, profile, limitOverrides).find(
    (candidate) => candidate.label === label
  );
  if (input === undefined)
    throw new MessageSignatureError(
      `unknown Accept-Signature label ${label}`,
      "invalid-signature-input"
    );
  return input;
}

export function parseSignatureField(
  source: string,
  limitOverrides: Partial<SignatureLimits> = {}
): readonly ParsedSignature[] {
  const configured = resolveSignatureLimits(limitOverrides);
  boundedUtf8ByteLength(
    source,
    configured.maxSignatureBytes,
    "Signature byte limit exceeded"
  );
  try {
    const entries = parseDictionary(source, "rfc8941", {
      maxDictionaryMembers: configured.maxSignatures,
      maxMemberParameters: 0,
    });
    if (entries.length > configured.maxSignatures)
      throw new MessageSignatureError(
        "signature count limit exceeded",
        "policy"
      );
    return entries.map(({ key, value }) => {
      if (
        value.kind !== "item" ||
        value.value.type !== "bytes" ||
        value.parameters.length !== 0
      )
        throw new MessageSignatureError(
          "Signature member must be an unparameterized byte sequence",
          "invalid-signature"
        );
      return { label: key, bytes: value.value.value };
    });
  } catch (error) {
    if (error instanceof MessageSignatureError) throw error;
    enforceStructuredParseLimit(error);
    throw new MessageSignatureError(
      `invalid Signature: ${error instanceof Error ? error.message : String(error)}`,
      "invalid-signature"
    );
  }
}

export function parseSignatureFields(
  fields: SignatureFields,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): ParsedSignatureSet {
  const inputs = new Map(
    parseSignatureInputField(
      fields.signatureInput,
      profile,
      limitOverrides
    ).map((input) => [input.label, input])
  );
  const signatures = new Map(
    parseSignatureField(fields.signature, limitOverrides).map((signature) => [
      signature.label,
      signature.bytes,
    ])
  );
  if (inputs.size === 0 || signatures.size === 0)
    throw new MessageSignatureError(
      "signature set is empty",
      "invalid-signature"
    );
  if (
    inputs.size !== signatures.size ||
    [...inputs.keys()].some((label) => !signatures.has(label))
  )
    throw new MessageSignatureError(
      "Signature and Signature-Input labels differ",
      "invalid-signature"
    );
  return { inputs, signatures, labels: [...inputs.keys()] };
}

export function listSignatures(
  fields: SignatureFields,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): readonly string[] {
  return parseSignatureFields(fields, profile, limitOverrides).labels;
}

export function selectSignature(
  fields: SignatureFields,
  label: string,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): { readonly input: SignatureInput; readonly signature: Uint8Array } {
  const parsed = parseSignatureFields(fields, profile, limitOverrides);
  const input = parsed.inputs.get(label);
  const signature = parsed.signatures.get(label);
  if (input === undefined || signature === undefined)
    throw new MessageSignatureError(
      `unknown signature label ${label}`,
      "invalid-signature"
    );
  return { input, signature };
}

function signatureInputMember(input: SignatureInput): SfInnerList {
  return {
    kind: "inner-list",
    items: input.components.map((component) => ({
      kind: "item",
      value: { type: "string", value: component.name.toLowerCase() },
      parameters: component.parameters,
    })),
    parameters: input.parameters,
  };
}

export function appendAcceptSignature(
  source: string | undefined,
  input: SignatureInput,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): string {
  const configured = resolveSignatureLimits(limitOverrides);
  enforceInputLimits(input, configured);
  enforceInputByteBudget(input, configured);
  if (!LABEL.test(input.label))
    throw new MessageSignatureError(
      "invalid signature label",
      "invalid-signature-input"
    );
  serializeSignatureParameters(
    input.components,
    input.parameters,
    profile,
    true,
    configured
  );
  const existing =
    source === undefined
      ? []
      : parseAcceptSignatureField(source, profile, limitOverrides);
  if (existing.some(({ label }) => label === input.label))
    throw new MessageSignatureError(
      `duplicate Accept-Signature label ${input.label}`,
      "invalid-signature-input"
    );
  const revision = profile === "rfc9421" ? "rfc8941" : "rfc9651";
  if (existing.length >= configured.maxSignatures)
    throw new MessageSignatureError("signature count limit exceeded", "policy");
  const output = serializeDictionary(
    [
      ...existing.map((entry) => ({
        key: entry.label,
        value: signatureInputMember(entry),
      })),
      { key: input.label, value: signatureInputMember(input) },
    ],
    revision
  );
  if (byteLength(output) > configured.maxSignatureInputBytes)
    throw new MessageSignatureError(
      "Signature-Input byte limit exceeded",
      "policy"
    );
  return output;
}

export function appendSignature(
  fields: SignatureFields | undefined,
  input: SignatureInput,
  signature: Uint8Array,
  profile: SignatureInputProfile = "rfc9421",
  limitOverrides: Partial<SignatureLimits> = {}
): SignatureFields {
  const configured = resolveSignatureLimits(limitOverrides);
  enforceInputLimits(input, configured);
  enforceInputByteBudget(input, configured);
  validateRepresentableTimestamps(input);
  if (signature.length > configured.maxSignatureBytes)
    throw new MessageSignatureError("Signature byte limit exceeded", "policy");
  if (!LABEL.test(input.label))
    throw new MessageSignatureError(
      "invalid signature label",
      "invalid-signature"
    );
  serializeSignatureParams(
    input.components,
    input.parameters,
    profile,
    limitOverrides
  );
  const parsedExisting =
    fields === undefined
      ? undefined
      : parseSignatureFields(fields, profile, limitOverrides);
  const existingInputs =
    parsedExisting === undefined ? [] : [...parsedExisting.inputs.values()];
  for (const existing of existingInputs)
    validateRepresentableTimestamps(existing);
  const existingSignatures =
    parsedExisting === undefined
      ? []
      : [...parsedExisting.signatures].map(([label, bytes]) => ({
          label,
          bytes,
        }));
  if (
    existingInputs.some(({ label }) => label === input.label) ||
    existingSignatures.some(({ label }) => label === input.label)
  )
    throw new MessageSignatureError(
      `duplicate signature label ${input.label}`,
      "invalid-signature"
    );
  if (existingInputs.length >= configured.maxSignatures)
    throw new MessageSignatureError("signature count limit exceeded", "policy");
  const revision = profile === "rfc9421" ? "rfc8941" : "rfc9651";
  const inputEntries: SfDictionaryEntry[] = [
    ...existingInputs.map((entry): SfDictionaryEntry => ({
      key: entry.label,
      value: signatureInputMember(entry),
    })),
    { key: input.label, value: signatureInputMember(input) },
  ];
  const signatureEntries: SfDictionaryEntry[] = [
    ...existingSignatures.map((entry): SfDictionaryEntry => ({
      key: entry.label,
      value: {
        kind: "item",
        value: { type: "bytes", value: entry.bytes },
        parameters: [],
      },
    })),
    {
      key: input.label,
      value: {
        kind: "item",
        value: { type: "bytes", value: signature },
        parameters: [],
      },
    },
  ];
  const output = {
    signatureInput: serializeDictionary(inputEntries, revision),
    signature: serializeDictionary(signatureEntries, "rfc8941"),
  };
  if (byteLength(output.signatureInput) > configured.maxSignatureInputBytes)
    throw new MessageSignatureError(
      "Signature-Input byte limit exceeded",
      "policy"
    );
  if (byteLength(output.signature) > configured.maxSignatureBytes)
    throw new MessageSignatureError("Signature byte limit exceeded", "policy");
  return output;
}

export interface SigningAlgorithmProvider {
  readonly algorithm: Algorithm;
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface VerificationAlgorithmProvider {
  readonly algorithm: Algorithm;
  verify(data: Uint8Array, signature: Uint8Array): boolean | Promise<boolean>;
}

export interface AlgorithmProvider
  extends SigningAlgorithmProvider, VerificationAlgorithmProvider {}

export interface VerificationPolicy {
  beforeCrypto?(input: SignatureInput, now: Date): void | Promise<void>;
  afterCrypto?(input: SignatureInput): void | Promise<void>;
}

function validateRepresentableTimestamps(input: SignatureInput): void {
  for (const { name, value } of input.parameters) {
    if (name !== "created" && name !== "expires") continue;
    if (value.type !== "integer") continue;
    if (dateFromIntegerSeconds(value.value) === undefined)
      throw new MessageSignatureError(
        `${name} timestamp is outside JavaScript Date range`,
        "policy"
      );
  }
}

function copyBareItem(value: BareItem): BareItem {
  if (value.type === "bytes")
    return Object.freeze({ type: "bytes", value: value.value.slice() });
  return Object.freeze({ ...value });
}

function immutableInput(input: SignatureInput): SignatureInput {
  const components = input.components.map((component) =>
    Object.freeze({
      name: component.name,
      parameters: Object.freeze(
        component.parameters.map(({ name, value }) =>
          Object.freeze({ name, value: copyBareItem(value) })
        )
      ),
    })
  );
  const parameters = input.parameters.map(({ name, value }) =>
    Object.freeze({ name, value: copyBareItem(value) })
  );
  return Object.freeze({
    label: input.label,
    components: Object.freeze(components),
    parameters: Object.freeze(parameters),
  });
}

export function snapshotMessage(
  message: HttpMessage,
  limitOverrides: Partial<SignatureLimits> = {}
): HttpMessage {
  const configured = resolveSignatureLimits(limitOverrides);
  const request = message.kind === "response" ? message.request : message;
  validateFieldLists(message, configured);
  const budget: MessageBudget = {
    occurrences: 0,
    stringBytes: 0,
    codeUnits: 0,
    explicitBytes: 0,
  };
  const copyField = (field: FieldOccurrence): FieldOccurrence => {
    accountField(field, budget, configured);
    const name = field.name;
    const value = field.value;
    const bytes = field.bytes;
    const structuredType = field.structuredType;
    return Object.freeze({
      name,
      value,
      bytes: bytes?.slice(),
      structuredType,
    });
  };
  const copyFields = (
    source: readonly FieldOccurrence[]
  ): readonly FieldOccurrence[] => {
    const length = denseLength(
      source,
      configured.maxFieldOccurrences,
      "field occurrence limit exceeded"
    );
    const copy: FieldOccurrence[] = [];
    for (let index = 0; index < length; index += 1) {
      const field = source[index];
      if (field === undefined)
        throw new MessageSignatureError(
          "field occurrence array is sparse",
          "policy"
        );
      copy.push(copyField(field));
    }
    return Object.freeze(copy);
  };
  const fields = copyFields(message.fields);
  const trailers =
    message.trailers === undefined ? undefined : copyFields(message.trailers);
  const stableTrailers = trailers === undefined ? undefined : trailers;
  if (message.kind === "request") {
    const stable: HttpRequest = {
      kind: "request",
      method: message.method,
      targetUri: message.targetUri,
      requestTarget: message.requestTarget,
      fields,
      trailers: stableTrailers,
    };
    enforceRequestTargetLimits(stable, configured);
    return Object.freeze(stable);
  }
  let stableRequest: HttpRequest | undefined;
  if (request !== undefined) {
    stableRequest = Object.freeze({
      kind: "request",
      method: request.method,
      targetUri: request.targetUri,
      requestTarget: request.requestTarget,
      fields: copyFields(request.fields),
      trailers:
        request.trailers === undefined
          ? undefined
          : copyFields(request.trailers),
    });
  }
  if (stableRequest !== undefined)
    enforceRequestTargetLimits(stableRequest, configured);
  return Object.freeze({
    kind: "response",
    status: message.status,
    fields,
    trailers: stableTrailers,
    request: stableRequest,
  });
}

function algorithmParameter(input: SignatureInput): Algorithm | undefined {
  const value = input.parameters.find(({ name }) => name === "alg")?.value;
  if (value === undefined) return undefined;
  if (value.type !== "string")
    throw new MessageSignatureError("alg parameter must be string", "policy");
  if (
    ![
      "rsa-pss-sha512",
      "rsa-v1_5-sha256",
      "hmac-sha256",
      "ecdsa-p256-sha256",
      "ecdsa-p384-sha384",
      "ed25519",
    ].includes(value.value)
  )
    throw new MessageSignatureError(
      `unsupported algorithm ${value.value}`,
      "policy"
    );
  switch (value.value) {
    case "rsa-pss-sha512":
    case "rsa-v1_5-sha256":
    case "hmac-sha256":
    case "ecdsa-p256-sha256":
    case "ecdsa-p384-sha384":
    case "ed25519":
      return value.value;
    default:
      throw new MessageSignatureError("unsupported algorithm", "policy");
  }
}

export async function signMessage(
  message: HttpMessage,
  input: SignatureInput,
  provider: SigningAlgorithmProvider,
  fields?: SignatureFields,
  options: SignatureBaseOptions = {}
): Promise<SignatureFields> {
  const configured = resolveSignatureLimits(options.limits);
  enforceInputLimits(input, configured);
  enforceInputByteBudget(input, configured);
  const stableInput = immutableInput(input);
  validateRepresentableTimestamps(stableInput);
  if (fields !== undefined) {
    const existing = parseSignatureFields(
      fields,
      options.signatureInputProfile,
      options.limits
    );
    for (const existingInput of existing.inputs.values())
      validateRepresentableTimestamps(existingInput);
  }
  const declaredAlgorithm = algorithmParameter(stableInput);
  if (
    declaredAlgorithm !== undefined &&
    declaredAlgorithm !== provider.algorithm
  )
    throw new MessageSignatureError("algorithm/provider mismatch", "crypto");
  const base = buildSignatureBase(
    snapshotMessage(message, options.limits),
    stableInput.components,
    stableInput.parameters,
    options
  );
  const signature = await provider.sign(new TextEncoder().encode(base));
  return appendSignature(
    fields,
    stableInput,
    signature,
    options.signatureInputProfile,
    options.limits
  );
}

export async function verifyMessageSignatures(
  message: HttpMessage,
  fields: SignatureFields,
  providerFor: (
    input: SignatureInput
  ) => VerificationAlgorithmProvider | Promise<VerificationAlgorithmProvider>,
  policy: VerificationPolicy = {},
  options: SignatureBaseOptions = {}
): Promise<readonly string[]> {
  // One defensive copy closes provider/policy await-point TOCTOU windows.
  const stableMessage = snapshotMessage(message, options.limits);
  const parsed = parseSignatureFields(
    fields,
    options.signatureInputProfile,
    options.limits
  );
  const encoder = new TextEncoder();
  const verified: string[] = [];
  for (const label of parsed.labels) {
    const parsedInput = parsed.inputs.get(label);
    const parsedSignature = parsed.signatures.get(label);
    if (parsedInput === undefined || parsedSignature === undefined)
      throw new MessageSignatureError(
        "incomplete parsed signature",
        "invalid-signature"
      );
    const input = immutableInput(parsedInput);
    validateRepresentableTimestamps(input);
    const base = buildSignatureBase(
      stableMessage,
      input.components,
      input.parameters,
      options
    );
    const signature = parsedSignature.slice();
    const declaredAlgorithm = algorithmParameter(input);
    const encodedBase = encoder.encode(base);
    await policy.beforeCrypto?.(immutableInput(input), new Date());
    const provider = await providerFor(immutableInput(input));
    if (
      declaredAlgorithm !== undefined &&
      declaredAlgorithm !== provider.algorithm
    )
      throw new MessageSignatureError("algorithm/provider mismatch", "crypto");
    const valid = await provider.verify(encodedBase, signature);
    if (!valid)
      throw new MessageSignatureError(`invalid signature ${label}`, "crypto");
    await policy.afterCrypto?.(immutableInput(input));
    verified.push(label);
  }
  return verified;
}
