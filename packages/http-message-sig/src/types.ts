// HTTP Message Signatures Algorithms Registry at IANA
// https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-algorithms
export type Algorithm =
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256"
  | "hmac-sha256"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ed25519";

export interface Signer {
  sign: (data: string) => Uint8Array | Promise<Uint8Array>;
  keyid: string;
  alg: Algorithm;
}

export interface SignerSync {
  signSync: (data: string) => Uint8Array;
  keyid: string;
  alg: Algorithm;
}

export type Verify<T> = {
  (
    data: string,
    signature: Uint8Array,
    params: Parameters,
    components: Component[]
  ): T | Promise<T>;
  readonly alg?: Algorithm;
};

export interface HeadersMap {
  get(name: string): string | null;
  set(name: string, value: string): void;
}

export type Headers = Record<string, HeaderValue> | HeadersMap;

export type HeaderValue = { toString(): string } | string | readonly string[];

export interface RequestLike {
  method: string;
  url: string;
  requestTarget?: string;
  protocol?: string;
  headers: Headers;
  trailers?: Headers;
}

export interface ResponseLike {
  status: number;
  headers: Headers;
  trailers?: Headers;
}

// Allows usage of the req parameter.
export interface ResponseRequestPair {
  response: ResponseLike;
  request: RequestLike;
}

// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-06#section-2.3.1
export type Parameter =
  "created" | "expires" | "nonce" | "alg" | "keyid" | string;

export interface StructuredFieldDictionaryComponent {
  header: string;
  key: string;
  parameters?: ComponentParameters;
}

export type Component =
  | "@method"
  | "@target-uri"
  | "@authority"
  | "@scheme"
  | "@request-target"
  | "@path"
  | "@query"
  | "@query-param"
  | "@status"
  | string
  | ComponentWithParameters
  | StructuredFieldDictionaryComponent;

export interface ComponentWithParameters {
  name: string;
  parameters: ComponentParameters;
}

export type ComponentParameters = Map<string, string | boolean>;

interface StandardParameters {
  expires?: Date;
  created?: Date;
  nonce?: string;
  alg?: string;
  keyid?: string;
  tag?: string;
}

export type Parameters = StandardParameters &
  Record<
    Parameter,
    | string
    | number
    | boolean
    | Date
    | Uint8Array
    | { [Symbol.toStringTag]: () => string }
  >;

export type SignOptions = StandardParameters & {
  components?: Component[];
  key?: string;
  parameters?: readonly SfParameter[];
  signatureInputProfile?: "rfc9421" | "rfc9651-extension";
  limits?: Partial<SignatureLimits>;
  signer: Signer;
  [name: Parameter]:
    | Component[]
    | ComponentWithParameters[]
    | StructuredFieldDictionaryComponent[]
    | readonly SfParameter[]
    | Partial<SignatureLimits>
    | Signer
    | string
    | number
    | true
    | Date
    | { [Symbol.toStringTag]: () => string }
    | undefined;
};

export type SignSyncOptions = StandardParameters & {
  components?: Component[];
  key?: string;
  parameters?: readonly SfParameter[];
  signatureInputProfile?: "rfc9421" | "rfc9651-extension";
  limits?: Partial<SignatureLimits>;
  signer: SignerSync;
  [name: Parameter]:
    | Component[]
    | ComponentWithParameters[]
    | StructuredFieldDictionaryComponent[]
    | readonly SfParameter[]
    | Partial<SignatureLimits>
    | SignerSync
    | string
    | number
    | true
    | Date
    | { [Symbol.toStringTag]: () => string }
    | undefined;
};

export interface SignatureHeaders {
  Signature: string;
  "Signature-Input": string;
}

export interface Directory {
  keys: JsonWebKey[];
}
import type { SfParameter } from "./structured-fields";
import type { SignatureLimits } from "./rfc9421";
