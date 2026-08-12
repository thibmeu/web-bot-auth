import {
  Component,
  ComponentParameters,
  ComponentWithParameters,
  Parameters,
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
  StructuredFieldDictionaryComponent,
} from "./types";
import { encode as encodeBase64 } from "./base64";
import {
  normalizeFieldBytes,
  normalizeFieldValue,
  resolveSignatureLimits,
  serializeComponentIdentifier,
  serializeSignatureParams,
  utf8ByteLength,
  validateRequestTarget,
  type SignatureLimits,
} from "./rfc9421";
import {
  type BareItem,
  parseDictionary,
  serializeMember,
  type SfParameter,
  type StructuredFieldRevision,
} from "./structured-fields";

function copyDense<T>(
  values: readonly T[],
  maximum: number,
  message: string
): T[] {
  const length = values.length;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum)
    throw new Error(message);
  const copy: T[] = [];
  for (let index = 0; index < length; index += 1) {
    const value = values[index];
    if (value === undefined) throw new Error(`${message}: sparse array`);
    copy.push(value);
  }
  return copy;
}

interface LegacyFieldBudget {
  bytes: number;
  occurrences: number;
  readonly maxBytes: number;
  readonly maxOccurrences: number;
}

function createFieldBudget(
  maxBytes: number,
  maxOccurrences: number
): LegacyFieldBudget {
  return { bytes: 0, occurrences: 0, maxBytes, maxOccurrences };
}

function collectHeaderValues(
  headers: RequestLike["headers"],
  header: string,
  budget: LegacyFieldBudget
): string[] {
  const normalized: string[] = [];
  const add = (name: string, value: string): void => {
    if (budget.occurrences >= budget.maxOccurrences)
      throw new Error(`${header} occurrence limit exceeded`);
    const codeUnits = name.length + value.length;
    if (codeUnits > budget.maxBytes - budget.bytes)
      throw new Error(`${header} byte limit exceeded`);
    budget.bytes += utf8ByteLength(name) + utf8ByteLength(value);
    if (budget.bytes > budget.maxBytes)
      throw new Error(`${header} byte limit exceeded`);
    normalized.push(normalizeFieldValue(value));
    budget.occurrences += 1;
  };
  const addArray = (name: string, values: readonly string[]): void => {
    const length = values.length;
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > budget.maxOccurrences - budget.occurrences
    )
      throw new Error(`${header} occurrence limit exceeded`);
    const separators =
      length === 0 ? 0 : (length - (normalized.length === 0 ? 1 : 0)) * 2;
    if (!Number.isSafeInteger(separators) || separators > budget.maxBytes)
      throw new Error(`${header} byte limit exceeded`);
    for (let index = 0; index < length; index += 1) {
      const value = values[index];
      if (value === undefined)
        throw new Error(`${header} occurrence array is sparse`);
      add(name, value);
    }
  };
  if (typeof headers.get === "function") {
    const value = headers.get(header);
    if (value !== null) add(header, value);
    return normalized;
  }
  const lower = header.toLowerCase();
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== lower || value === undefined) continue;
    if (Array.isArray(value)) addArray(name, value);
    else add(name, value.toString());
  }
  return normalized;
}

/**
 * Extract a value from a dictionary-style header by key.
 *
 * The selected member value is serialized per RFC 8941, as required by
 * RFC 9421 section 2.1.2.
 */
export function extractStructuredFieldDictionaryHeader(
  r: RequestLike | ResponseLike,
  component: StructuredFieldDictionaryComponent,
  maxBytes?: number,
  maxOccurrences?: number
): string {
  const configured = resolveSignatureLimits();
  return extractStructuredFieldDictionaryHeaderWithBudget(
    r,
    component,
    createFieldBudget(
      maxBytes ?? configured.maxFieldBytes,
      maxOccurrences ?? configured.maxFieldOccurrences
    )
  );
}

function extractStructuredFieldDictionaryHeaderWithBudget(
  r: RequestLike | ResponseLike,
  component: StructuredFieldDictionaryComponent,
  budget: LegacyFieldBudget
): string {
  const headerValue = component.parameters?.has("tr")
    ? extractTrailerWithBudget(r.trailers, component.header, budget)
    : extractHeaderWithBudget(r, component.header, budget);
  if (!headerValue) return headerValue;

  const entry = parseDictionary(headerValue, "rfc8941").find(
    ({ key }) => key === component.key
  );
  if (entry === undefined) {
    throw new Error(
      `Header ${component.header} does not contain dictionary key ${component.key}`
    );
  }

  return serializeMember(entry.value, "rfc8941");
}

export function extractHeader(
  { headers }: RequestLike | ResponseLike,
  header: string,
  maxBytes?: number,
  maxOccurrences?: number
): string {
  const configured = resolveSignatureLimits();
  const byteLimit = maxBytes ?? configured.maxFieldBytes;
  const occurrenceLimit = maxOccurrences ?? configured.maxFieldOccurrences;
  return collectHeaderValues(
    headers,
    header,
    createFieldBudget(byteLimit, occurrenceLimit)
  ).join(", ");
}

function extractHeaderWithBudget(
  { headers }: RequestLike | ResponseLike,
  header: string,
  budget: LegacyFieldBudget
): string {
  return collectHeaderValues(headers, header, budget).join(", ");
}

function extractTrailerWithBudget(
  trailers: RequestLike["headers"] | undefined,
  header: string,
  budget: LegacyFieldBudget
): string {
  if (trailers === undefined) return "";
  return extractHeaderWithBudget(
    { headers: trailers, status: 0 },
    header,
    budget
  );
}

export function extractTrailer(
  { trailers }: RequestLike | ResponseLike,
  header: string,
  maxBytes?: number,
  maxOccurrences?: number
): string {
  const configured = resolveSignatureLimits();
  return extractTrailerWithBudget(
    trailers,
    header,
    createFieldBudget(
      maxBytes ?? configured.maxFieldBytes,
      maxOccurrences ?? configured.maxFieldOccurrences
    )
  );
}

function extractBinaryHeader(
  message: RequestLike | ResponseLike,
  header: string,
  trailer: boolean,
  budget: LegacyFieldBudget
): string {
  const headers = trailer ? message.trailers : message.headers;
  if (headers === undefined) return "";
  return collectHeaderValues(headers, header, budget)
    .map((value) => {
      if (value.length > budget.maxBytes)
        throw new Error(`${header} byte limit exceeded`);
      return `:${encodeBase64(normalizeFieldBytes(value))}:`;
    })
    .join(", ");
}

export function getUrl(
  message: RequestLike | ResponseLike,
  component: string
): URL {
  if ("url" in message && "protocol" in message) {
    const host = extractHeader(message, "host");
    const protocol = message.protocol || "http";
    const baseUrl = `${protocol}://${host}`;
    return new URL(message.url, baseUrl);
  }
  if (!("url" in message) || !message.url)
    throw new Error(`${component} is only valid for requests`);
  return new URL(message.url);
}

// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-06#section-2.3
export function extractComponent(
  message: RequestLike | ResponseLike,
  component: string
): string {
  switch (component) {
    case "@method":
      if (!("method" in message) || !message.method)
        throw new Error(`${component} is only valid for requests`);
      return message.method;
    case "@target-uri":
      if (!("url" in message) || !message.url)
        throw new Error(`${component} is only valid for requests`);
      return message.url;
    case "@authority":
      // URL.host omits only the scheme's default port, per RFC 9421 section 2.2.3.
      return getUrl(message, component).host;
    case "@scheme":
      return getUrl(message, component).protocol.slice(0, -1);
    case "@request-target": {
      if ("requestTarget" in message && message.requestTarget !== undefined) {
        if (!("method" in message))
          throw new Error(`${component} is only valid for requests`);
        validateRequestTarget(message.method, message.requestTarget);
        return message.requestTarget;
      }
      const { pathname, search } = getUrl(message, component);
      const value = `${pathname}${search}`;
      if (!("method" in message))
        throw new Error(`${component} is only valid for requests`);
      validateRequestTarget(message.method, value);
      return value;
    }
    case "@path":
      return getUrl(message, component).pathname;
    case "@query":
      return getUrl(message, component).search;
    case "@status":
      if (!("status" in message))
        throw new Error(`${component} is only valid for responses`);
      return message.status.toString();
    case "@query-params":
      throw new Error(`${component} is not implemented yet`);
    default:
      throw new Error(`Unknown specialty component ${component}`);
  }
}

export function isStructuredFieldDictionaryComponent(
  component: Component
): component is StructuredFieldDictionaryComponent {
  return typeof component === "object" && "header" in component;
}

function structuredFieldComponentParameters(
  cwp: StructuredFieldDictionaryComponent
): ComponentParameters {
  if (!cwp.parameters) {
    return new Map([["key", cwp.key]]);
  }

  const key = cwp.parameters.get("key");
  if (key === cwp.key) {
    return cwp.parameters;
  }

  if (key !== undefined) {
    throw new Error(
      `Structured field component key mismatch ${key.toString()} !== ${cwp.key}`
    );
  }

  return new Map([["key", cwp.key], ...cwp.parameters]);
}

export function serializeComponent(cwp: Component): string {
  return serializeComponentIdentifier(legacyCoveredComponent(cwp));
}

function legacyCoveredComponent(cwp: Component): {
  readonly name: string;
  readonly parameters: readonly SfParameter[];
} {
  if (typeof cwp === "string") {
    return { name: cwp, parameters: [] };
  }

  if (isStructuredFieldDictionaryComponent(cwp)) {
    return {
      name: cwp.header,
      parameters: legacyComponentParameters(
        structuredFieldComponentParameters(cwp)
      ),
    };
  }

  return {
    name: cwp.name,
    parameters: legacyComponentParameters(cwp.parameters),
  };
}

function legacyComponentParameters(
  parameters: ComponentParameters
): readonly SfParameter[] {
  const converted: SfParameter[] = [];
  for (const [parameterName, value] of parameters) {
    converted.push({
      name: parameterName,
      value:
        typeof value === "boolean"
          ? { type: "boolean", value }
          : { type: "string", value },
    });
  }
  return converted;
}

export function isRawMessage(
  message: RequestLike | ResponseLike | ResponseRequestPair
): message is RequestLike | ResponseLike {
  return !("response" in message) && !("request" in message);
}

export function componentHasParameters(component: Component): component is
  | ComponentWithParameters
  | (StructuredFieldDictionaryComponent & {
      parameters: ComponentParameters;
    }) {
  return (
    typeof component === "object" &&
    "parameters" in component &&
    component.parameters !== undefined
  );
}

export function resolveMessageKind(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  cwp?: Component
): RequestLike | ResponseLike {
  let requiresReq = false;
  if (cwp !== undefined && componentHasParameters(cwp)) {
    requiresReq = cwp.parameters.has("req");
  }

  if (isRawMessage(message)) {
    if (requiresReq) {
      throw new Error(
        "`req` component parameter can only be used with ResponseRequestPair message types"
      );
    }

    return message;
  }

  if (requiresReq) {
    return message.request;
  }

  return message.response;
}

export function validateMessageRequestTarget(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  limitOverrides: Partial<SignatureLimits> = {}
): void {
  const configured = resolveSignatureLimits(limitOverrides);
  const validate = (request: RequestLike): void => {
    if (
      request.url.length > configured.maxTargetUriBytes ||
      utf8ByteLength(request.url) > configured.maxTargetUriBytes ||
      (request.requestTarget?.length ?? 0) > configured.maxTargetUriBytes ||
      utf8ByteLength(request.requestTarget ?? "") > configured.maxTargetUriBytes
    )
      throw new Error("target URI byte limit exceeded");
    if (request.requestTarget !== undefined)
      validateRequestTarget(request.method, request.requestTarget);
  };
  if (isRawMessage(message)) {
    if ("method" in message) validate(message);
    return;
  }
  validate(message.request);
}

export function buildSignatureInputString(
  componentNames: Component[],
  parameters: Parameters,
  orderedParameters: readonly SfParameter[] = [],
  revision: StructuredFieldRevision = "rfc8941",
  limitOverrides: Partial<SignatureLimits> = {}
): string {
  const configured = resolveSignatureLimits(limitOverrides);
  const stableComponents = copyDense(
    componentNames,
    configured.maxComponentsPerSignature,
    "component limit exceeded"
  );
  const stableOrderedParameters = copyDense(
    orderedParameters,
    configured.maxParametersPerSignature,
    "signature parameter limit exceeded"
  );
  const legacyParameterEntries = Object.entries(parameters);
  const existing = new Set(Object.keys(parameters));
  const custom = new Set<string>();
  for (const { name } of stableOrderedParameters) {
    if (existing.has(name) || custom.has(name)) {
      throw new Error(`Duplicate signature parameter ${name}`);
    }
    custom.add(name);
  }
  const legacyParameters = legacyParameterEntries.map(([name, value]) => {
    let item: BareItem;
    if (value instanceof Date) {
      item = {
        type: "integer",
        value: Math.floor(value.getTime() / 1000),
      };
    } else if (value instanceof Uint8Array) {
      item = { type: "bytes", value };
    } else if (typeof value === "number") {
      item = Number.isInteger(value)
        ? { type: "integer", value }
        : { type: "decimal", value: value.toString() };
    } else if (typeof value === "boolean") {
      item = { type: "boolean", value };
    } else {
      item = { type: "string", value: value.toString() };
    }
    return { name, value: item };
  });

  return serializeSignatureParams(
    stableComponents.map(legacyCoveredComponent),
    [...legacyParameters, ...stableOrderedParameters],
    revision === "rfc8941" ? "rfc9421" : "rfc9651-extension",
    limitOverrides
  );
}

export function buildSignedData(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  components: Component[],
  signatureInputString: string,
  limitOverrides: Partial<SignatureLimits> = {}
): string {
  const configured = resolveSignatureLimits(limitOverrides);
  const declaredComponentCount = components.length;
  if (
    !Number.isSafeInteger(declaredComponentCount) ||
    declaredComponentCount < 0 ||
    (declaredComponentCount === 0 ? 0 : declaredComponentCount - 1) >
      configured.maxSignatureBaseBytes
  )
    throw new Error("signature base byte limit exceeded");
  const stableComponents = copyDense(
    components,
    configured.maxComponentsPerSignature,
    "component limit exceeded"
  );
  validateMessageRequestTarget(message, limitOverrides);
  const parts: string[] = [];
  let baseBytes = 0;
  const add = (identifier: string, value: string): void => {
    const separatorBytes = parts.length === 0 ? 0 : 1;
    const codeUnits = identifier.length + 2 + value.length + separatorBytes;
    if (codeUnits > configured.maxSignatureBaseBytes - baseBytes)
      throw new Error("signature base byte limit exceeded");
    baseBytes +=
      utf8ByteLength(identifier) + 2 + utf8ByteLength(value) + separatorBytes;
    if (baseBytes > configured.maxSignatureBaseBytes)
      throw new Error("signature base byte limit exceeded");
    parts.push(`${identifier}: ${value}`);
  };
  const budget = createFieldBudget(
    configured.maxFieldBytes,
    configured.maxFieldOccurrences
  );
  for (const component of stableComponents) {
    const messageToUse = resolveMessageKind(message, component);
    const parameters = componentHasParameters(component)
      ? component.parameters
      : undefined;
    const trailer = parameters?.has("tr") ?? false;
    const binary = parameters?.has("bs") ?? false;
    let value: string;

    if (typeof component === "string") {
      value = component.startsWith("@")
        ? extractComponent(messageToUse, component)
        : extractHeaderWithBudget(messageToUse, component, budget);
    } else if (isStructuredFieldDictionaryComponent(component)) {
      value = extractStructuredFieldDictionaryHeaderWithBudget(
        messageToUse,
        component,
        budget
      );
    } else {
      const componentName = component.name;
      value = componentName.startsWith("@")
        ? extractComponent(messageToUse, componentName)
        : binary
          ? extractBinaryHeader(messageToUse, componentName, trailer, budget)
          : trailer
            ? extractTrailerWithBudget(
                messageToUse.trailers,
                componentName,
                budget
              )
            : extractHeaderWithBudget(messageToUse, componentName, budget);
    }
    add(serializeComponent(component), value);
  }
  add('"@signature-params"', signatureInputString);
  return parts.join("\n");
}
