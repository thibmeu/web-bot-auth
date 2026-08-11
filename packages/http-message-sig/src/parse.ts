import { type HeaderValue, type Parameters, type Component } from "./types";
import {
  parseAcceptSignatureField,
  parseSignatureField,
  parseSignatureInputField,
  type SignatureInputProfile,
  type SignatureLimits,
} from "./rfc9421";
import type { BareItem, SfParameter } from "./structured-fields";
import { dateFromIntegerSeconds } from "./timestamps";

function legacyValue(name: string, value: BareItem): Parameters[string] {
  if ((name === "created" || name === "expires") && value.type === "integer") {
    const date = dateFromIntegerSeconds(value.value);
    if (date === undefined)
      throw new Error(`${name} timestamp is outside JavaScript Date range`);
    return date;
  }
  switch (value.type) {
    case "integer":
      return value.value;
    case "decimal":
      return Number(value.value);
    case "string":
    case "token":
    case "display-string":
      return value.value;
    case "bytes":
      return value.value;
    case "boolean":
      return value.value;
    case "date":
      return new Date(value.value * 1000);
  }
}

function legacyParameters(values: readonly SfParameter[]): Parameters {
  const result: Parameters = {};
  for (const { name, value } of values) result[name] = legacyValue(name, value);
  return result;
}

function legacyComponents(
  input: ReturnType<typeof parseSignatureInputField>[number]
): Component[] {
  return input.components.map(({ name, parameters }) => {
    if (parameters.length === 0) return name;
    const mapped = new Map<string, string | boolean>();
    let dictionaryKey: string | undefined;
    for (const parameter of parameters) {
      if (
        parameter.value.type !== "string" &&
        parameter.value.type !== "boolean"
      ) {
        throw new Error(`Invalid component parameter ${parameter.name}`);
      }
      mapped.set(parameter.name, parameter.value.value);
      if (parameter.name === "key" && parameter.value.type === "string") {
        dictionaryKey = parameter.value.value;
      }
    }
    return dictionaryKey === undefined
      ? { name, parameters: mapped }
      : { header: name, key: dictionaryKey, parameters: mapped };
  });
}

function parseSingleInput(
  name: string,
  header: HeaderValue,
  profile: SignatureInputProfile,
  limits: Partial<SignatureLimits>
): { key: string; components: Component[]; parameters: Parameters } {
  const entries = parseSignatureInputField(header.toString(), profile, limits);
  if (entries.length !== 1)
    throw new Error(`Multiple signatures is not supported`);
  const entry = entries[0];
  if (entry === undefined)
    throw new Error(`Invalid ${name} header. Invalid value`);
  return {
    key: entry.label,
    components: legacyComponents(entry),
    parameters: legacyParameters(entry.parameters),
  };
}

export function parseSignatureInputHeader(
  header: HeaderValue,
  profile: SignatureInputProfile = "rfc9421",
  limits: Partial<SignatureLimits> = {}
): { key: string; components: Component[]; parameters: Parameters } {
  try {
    return parseSingleInput("Signature-Input", header, profile, limits);
  } catch (error) {
    throw new Error(
      `Invalid Signature-Input header; failed to parse as RFC 8941 dictionary: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

export function parseAcceptSignatureHeader(
  header: HeaderValue,
  profile: SignatureInputProfile = "rfc9421",
  limits: Partial<SignatureLimits> = {}
): { key: string; components: Component[]; parameters: Parameters } {
  const entries = parseAcceptSignatureField(header.toString(), profile, limits);
  if (entries.length !== 1)
    throw new Error(`Multiple signatures is not supported`);
  const entry = entries[0];
  if (entry === undefined)
    throw new Error(`Invalid Accept-Signature header. Invalid value`);
  return {
    key: entry.label,
    components: legacyComponents(entry),
    parameters: legacyParameters(entry.parameters),
  };
}

export function parseSignatureHeader(
  key: string,
  header: HeaderValue,
  limits: Partial<SignatureLimits> = {}
): Uint8Array {
  const entries = parseSignatureField(header.toString(), limits);
  if (entries.length !== 1)
    throw new Error("Multiple signatures is not supported");
  const entry = entries[0];
  if (entry === undefined) throw new Error("Invalid Signature header");
  if (entry.label !== key) {
    throw new Error(
      `Invalid Signature header. Key mismatch ${entry.label} !== ${key}`
    );
  }
  return entry.bytes;
}
