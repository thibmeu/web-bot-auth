export type StructuredFieldRevision = "rfc8941" | "rfc9651";

export interface StructuredFieldParseLimits {
  readonly maxDictionaryMembers?: number;
  readonly maxInnerListItems?: number;
  readonly maxItemParameters?: number;
  readonly maxMemberParameters?: number;
}

export type BareItem =
  | { readonly type: "integer"; readonly value: number }
  | { readonly type: "decimal"; readonly value: string }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "token"; readonly value: string }
  | { readonly type: "bytes"; readonly value: Uint8Array }
  | { readonly type: "boolean"; readonly value: boolean }
  | { readonly type: "date"; readonly value: number }
  | { readonly type: "display-string"; readonly value: string };

export interface SfParameter {
  readonly name: string;
  readonly value: BareItem;
}

export interface SfItem {
  readonly kind: "item";
  readonly value: BareItem;
  readonly parameters: readonly SfParameter[];
}

export interface SfInnerList {
  readonly kind: "inner-list";
  readonly items: readonly SfItem[];
  readonly parameters: readonly SfParameter[];
}

export type SfMember = SfItem | SfInnerList;

export interface SfDictionaryEntry {
  readonly key: string;
  readonly value: SfMember;
}

export class StructuredFieldError extends Error {
  constructor(
    message: string,
    readonly offset?: number
  ) {
    super(offset === undefined ? message : `${message} at byte ${offset}`);
    this.name = "StructuredFieldError";
  }
}

export class StructuredFieldLimitError extends StructuredFieldError {
  constructor(
    readonly limit:
      "dictionary" | "inner-list" | "item-parameters" | "member-parameters"
  ) {
    super(`${limit} limit exceeded`);
    this.name = "StructuredFieldLimitError";
  }
}

const KEY = /^[a-z*][a-z0-9_.*-]*$/;
const TOKEN = /^[A-Za-z*][!#$%&'*+.^_`|~:/A-Za-z0-9-]*$/;

function requireInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || Math.abs(value) > 999_999_999_999_999) {
    throw new StructuredFieldError(`invalid ${name}`);
  }
}

function serializeString(value: string): string {
  if (!/^[\x20-\x7e]*$/.test(value))
    throw new StructuredFieldError("invalid string");
  return `"${value.replace(/["\\]/g, "\\$&")}"`;
}

function serializeDecimal(source: string): string {
  const match = /^(-?)(\d+)\.(\d+)$/.exec(source);
  if (match === null) throw new StructuredFieldError("invalid decimal");
  const sign = match[1];
  const integerSource = match[2];
  const fractionSource = match[3];
  if (
    sign === undefined ||
    integerSource === undefined ||
    fractionSource === undefined
  )
    throw new StructuredFieldError("invalid decimal");
  let integer = BigInt(integerSource);
  let fraction = fractionSource.slice(0, 3).padEnd(3, "0");
  const discarded = fractionSource.slice(3);
  const firstDiscarded = discarded[0];
  if (firstDiscarded !== undefined) {
    const first = Number(firstDiscarded);
    const tieHasRemainder = /[1-9]/.test(discarded.slice(1));
    const lastKept = Number(fraction[2]);
    if (first > 5 || (first === 5 && (tieHasRemainder || lastKept % 2 === 1))) {
      const incremented = Number(fraction) + 1;
      if (incremented === 1000) {
        integer += 1n;
        fraction = "000";
      } else {
        fraction = incremented.toString().padStart(3, "0");
      }
    }
  }
  if (integer > 999_999_999_999n)
    throw new StructuredFieldError("invalid decimal");
  const canonicalFraction = fraction.replace(/0+$/, "") || "0";
  const negative =
    sign === "-" && (integer !== 0n || canonicalFraction !== "0");
  return `${negative ? "-" : ""}${integer}.${canonicalFraction}`;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

export function serializeBareItem(
  item: BareItem,
  revision: StructuredFieldRevision = "rfc9651"
): string {
  switch (item.type) {
    case "integer":
      requireInteger(item.value, "integer");
      return item.value.toString();
    case "decimal":
      return serializeDecimal(item.value);
    case "string":
      return serializeString(item.value);
    case "token":
      if (!TOKEN.test(item.value))
        throw new StructuredFieldError("invalid token");
      return item.value;
    case "bytes": {
      let binary = "";
      for (const byte of item.value) binary += String.fromCharCode(byte);
      return `:${btoa(binary)}:`;
    }
    case "boolean":
      return item.value ? "?1" : "?0";
    case "date":
      if (revision === "rfc8941")
        throw new StructuredFieldError("date requires RFC 9651");
      requireInteger(item.value, "date");
      return `@${item.value}`;
    case "display-string": {
      if (revision === "rfc8941")
        throw new StructuredFieldError("display string requires RFC 9651");
      if (hasUnpairedSurrogate(item.value))
        throw new StructuredFieldError("invalid display string surrogate");
      let value = "";
      for (const byte of new TextEncoder().encode(item.value)) {
        value +=
          byte === 0x25 || byte === 0x22 || byte < 0x20 || byte >= 0x7f
            ? `%${byte.toString(16).padStart(2, "0")}`
            : String.fromCharCode(byte);
      }
      return `%"${value}"`;
    }
  }
}

export function serializeParameters(
  parameters: readonly SfParameter[],
  revision: StructuredFieldRevision = "rfc9651"
): string {
  const seen = new Set<string>();
  return parameters
    .map(({ name, value }) => {
      if (!KEY.test(name) || seen.has(name))
        throw new StructuredFieldError(
          `invalid or duplicate parameter ${name}`
        );
      seen.add(name);
      return value.type === "boolean" && value.value
        ? `;${name}`
        : `;${name}=${serializeBareItem(value, revision)}`;
    })
    .join("");
}

export function serializeItem(
  item: SfItem,
  revision: StructuredFieldRevision = "rfc9651"
): string {
  return `${serializeBareItem(item.value, revision)}${serializeParameters(item.parameters, revision)}`;
}

export function serializeMember(
  member: SfMember,
  revision: StructuredFieldRevision = "rfc9651"
): string {
  if (member.kind === "item") return serializeItem(member, revision);
  return `(${member.items.map((item) => serializeItem(item, revision)).join(" ")})${serializeParameters(member.parameters, revision)}`;
}

export function serializeList(
  members: readonly SfMember[],
  revision: StructuredFieldRevision = "rfc9651"
): string {
  return members.map((member) => serializeMember(member, revision)).join(", ");
}

export function serializeDictionary(
  entries: readonly SfDictionaryEntry[],
  revision: StructuredFieldRevision = "rfc9651"
): string {
  const seen = new Set<string>();
  return entries
    .map(({ key, value }) => {
      if (!KEY.test(key) || seen.has(key))
        throw new StructuredFieldError(
          `invalid or duplicate dictionary key ${key}`
        );
      seen.add(key);
      if (
        value.kind === "item" &&
        value.value.type === "boolean" &&
        value.value.value
      ) {
        return `${key}${serializeParameters(value.parameters, revision)}`;
      }
      return `${key}=${serializeMember(value, revision)}`;
    })
    .join(", ");
}

export class StructuredFieldParser {
  private offset = 0;

  constructor(
    private readonly source: string,
    private readonly revision: StructuredFieldRevision = "rfc9651",
    private readonly limits: StructuredFieldParseLimits = {}
  ) {}

  parseItem(): SfItem {
    this.sp();
    const result = this.item();
    this.sp();
    this.end();
    return result;
  }

  parseList(): readonly SfMember[] {
    this.sp();
    if (this.offset === this.source.length) return [];
    const result = [this.member()];
    while (true) {
      this.ows();
      if (!this.consume(",")) break;
      this.ows();
      if (this.peek() === undefined) this.fail();
      result.push(this.member());
    }
    this.sp();
    this.end();
    return result;
  }

  parseDictionary(): readonly SfDictionaryEntry[] {
    this.sp();
    if (this.offset === this.source.length) return [];
    const result = new Map<string, SfMember>();
    let members = 0;
    while (true) {
      members += 1;
      if (
        this.limits.maxDictionaryMembers !== undefined &&
        members > this.limits.maxDictionaryMembers
      )
        throw new StructuredFieldLimitError("dictionary");
      const key = this.key();
      let value: SfMember;
      if (this.consume("=")) value = this.member();
      else {
        value = {
          kind: "item",
          value: { type: "boolean", value: true },
          parameters: this.parameters(this.limits.maxMemberParameters),
        };
      }
      result.set(key, value);
      this.ows();
      if (!this.consume(",")) break;
      this.ows();
      if (this.peek() === undefined) this.fail();
    }
    this.sp();
    this.end();
    return [...result].map(([key, value]) => ({ key, value }));
  }

  private member(): SfMember {
    if (!this.consume("("))
      return this.item(this.limits.maxMemberParameters, "member-parameters");
    this.sp();
    const items: SfItem[] = [];
    while (!this.consume(")")) {
      if (this.peek() === undefined || this.peek() === "\t") this.fail();
      if (
        this.limits.maxInnerListItems !== undefined &&
        items.length >= this.limits.maxInnerListItems
      )
        throw new StructuredFieldLimitError("inner-list");
      items.push(this.item(this.limits.maxItemParameters));
      if (this.consume(")")) break;
      if (this.peek() !== " ") this.fail();
      this.sp();
    }
    return {
      kind: "inner-list",
      items,
      parameters: this.parameters(
        this.limits.maxMemberParameters,
        "member-parameters"
      ),
    };
  }

  private item(
    maxParameters?: number,
    limit: "item-parameters" | "member-parameters" = "item-parameters"
  ): SfItem {
    return {
      kind: "item",
      value: this.bareItem(),
      parameters: this.parameters(maxParameters, limit),
    };
  }

  private parameters(
    maxParameters?: number,
    limit: "item-parameters" | "member-parameters" = "member-parameters"
  ): readonly SfParameter[] {
    const result = new Map<string, BareItem>();
    while (this.consume(";")) {
      if (maxParameters !== undefined && result.size >= maxParameters)
        throw new StructuredFieldLimitError(limit);
      this.sp();
      const name = this.key();
      result.set(
        name,
        this.consume("=") ? this.bareItem() : { type: "boolean", value: true }
      );
    }
    return [...result].map(([name, value]) => ({ name, value }));
  }

  private bareItem(): BareItem {
    const first = this.peek();
    if (first === '"') return { type: "string", value: this.string() };
    if (first === ":") return { type: "bytes", value: this.bytes() };
    if (first === "?") return { type: "boolean", value: this.boolean() };
    if (first === "@") return { type: "date", value: this.date() };
    if (first === "%")
      return { type: "display-string", value: this.displayString() };
    if (first === "-" || (first !== undefined && /[0-9]/.test(first)))
      return this.number();
    return { type: "token", value: this.token() };
  }

  private number(): BareItem {
    const start = this.offset;
    this.consume("-");
    const integerStart = this.offset;
    while (this.peek() !== undefined && /[0-9]/.test(this.peek() ?? ""))
      this.offset += 1;
    const integerDigits = this.offset - integerStart;
    if (integerDigits === 0) this.fail();
    if (!this.consume(".")) {
      if (integerDigits > 15) this.fail();
      const value = Number(this.source.slice(start, this.offset));
      requireInteger(value, "integer");
      return { type: "integer", value };
    }
    const fractionStart = this.offset;
    while (this.peek() !== undefined && /[0-9]/.test(this.peek() ?? ""))
      this.offset += 1;
    const fractionDigits = this.offset - fractionStart;
    if (integerDigits > 12 || fractionDigits < 1 || fractionDigits > 3)
      this.fail();
    const value = this.source.slice(start, this.offset);
    serializeDecimal(value);
    return { type: "decimal", value };
  }

  private string(): string {
    this.expect('"');
    let value = "";
    while (true) {
      const character = this.peek();
      if (character === undefined) this.fail();
      this.offset += 1;
      if (character === '"') return value;
      if (character === "\\") {
        const escaped = this.peek();
        if (escaped !== '"' && escaped !== "\\") this.fail();
        value += escaped;
        this.offset += 1;
      } else {
        const code = character.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) this.fail();
        value += character;
      }
    }
  }

  private token(): string {
    const start = this.offset;
    const first = this.peek();
    if (first === undefined || !/[A-Za-z*]/.test(first)) this.fail();
    this.offset += 1;
    while (
      this.peek() !== undefined &&
      /[!#$%&'*+.^_`|~:/A-Za-z0-9-]/.test(this.peek() ?? "")
    )
      this.offset += 1;
    return this.source.slice(start, this.offset);
  }

  private bytes(): Uint8Array {
    this.expect(":");
    const start = this.offset;
    const end = this.source.indexOf(":", start);
    if (end < 0) this.fail("invalid byte sequence");
    this.offset = end;
    const encoded = this.source.slice(start, this.offset);
    this.expect(":");
    if (
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        encoded
      )
    )
      this.fail("invalid byte sequence");
    let binary: string;
    try {
      binary = atob(encoded);
    } catch {
      this.fail("invalid byte sequence");
    }
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (
      (encoded.endsWith("==") &&
        (alphabet.indexOf(encoded.charAt(encoded.length - 3)) & 0x0f) !== 0) ||
      (encoded.endsWith("=") &&
        !encoded.endsWith("==") &&
        (alphabet.indexOf(encoded.charAt(encoded.length - 2)) & 0x03) !== 0)
    )
      this.fail("non-canonical byte sequence");
    const result = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1)
      result[index] = binary.charCodeAt(index);
    return result;
  }

  private boolean(): boolean {
    this.expect("?");
    if (this.consume("1")) return true;
    if (this.consume("0")) return false;
    this.fail("invalid boolean");
  }

  private date(): number {
    if (this.revision === "rfc8941")
      throw new StructuredFieldError("date requires RFC 9651", this.offset);
    this.expect("@");
    const start = this.offset;
    this.consume("-");
    const digitStart = this.offset;
    while (this.peek() !== undefined && /[0-9]/.test(this.peek() ?? ""))
      this.offset += 1;
    if (this.offset === digitStart || this.offset - digitStart > 15)
      this.fail();
    const value = Number(this.source.slice(start, this.offset));
    requireInteger(value, "date");
    return value;
  }

  private displayString(): string {
    if (this.revision === "rfc8941")
      throw new StructuredFieldError(
        "display string requires RFC 9651",
        this.offset
      );
    this.expect("%");
    this.expect('"');
    const bytes: number[] = [];
    while (true) {
      const character = this.peek();
      if (character === undefined) this.fail();
      this.offset += 1;
      if (character === '"') break;
      if (character === "%") {
        const hex = this.source.slice(this.offset, this.offset + 2);
        if (!/^[0-9a-f]{2}$/.test(hex))
          this.fail("invalid display string escape");
        bytes.push(Number.parseInt(hex, 16));
        this.offset += 2;
      } else {
        const code = character.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) this.fail();
        bytes.push(code);
      }
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(
        Uint8Array.from(bytes)
      );
    } catch {
      this.fail("invalid display string UTF-8");
    }
  }

  private key(): string {
    const start = this.offset;
    const first = this.peek();
    if (first === undefined || !/[a-z*]/.test(first)) this.fail("invalid key");
    this.offset += 1;
    while (this.peek() !== undefined && /[a-z0-9_.*-]/.test(this.peek() ?? ""))
      this.offset += 1;
    return this.source.slice(start, this.offset);
  }

  private peek(): string | undefined {
    return this.source[this.offset];
  }

  private consume(character: string): boolean {
    if (this.peek() !== character) return false;
    this.offset += 1;
    return true;
  }

  private expect(character: string): void {
    if (!this.consume(character)) this.fail(`expected ${character}`);
  }

  private sp(): void {
    while (this.consume(" ")) {}
  }

  private ows(): void {
    while (this.peek() === " " || this.peek() === "\t") this.offset += 1;
  }

  private end(): void {
    if (this.offset !== this.source.length) this.fail("trailing data");
  }

  private fail(message = "malformed structured field"): never {
    throw new StructuredFieldError(message, this.offset);
  }
}

export function parseItem(
  source: string,
  revision: StructuredFieldRevision = "rfc9651"
): SfItem {
  return new StructuredFieldParser(source, revision).parseItem();
}

export function parseList(
  source: string,
  revision: StructuredFieldRevision = "rfc9651"
): readonly SfMember[] {
  return new StructuredFieldParser(source, revision).parseList();
}

export function parseDictionary(
  source: string,
  revision: StructuredFieldRevision = "rfc9651",
  limits: StructuredFieldParseLimits = {}
): readonly SfDictionaryEntry[] {
  return new StructuredFieldParser(source, revision, limits).parseDictionary();
}
