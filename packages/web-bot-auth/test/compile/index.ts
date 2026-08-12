import {
  signatureHeaders,
  type ComponentIdentifier,
  type SignableMessage,
  type SignatureInputProfile,
} from "../../src";

const components: ReadonlyArray<ComponentIdentifier> = [
  "@authority",
  { name: "signature-agent", parameters: [["key", "sig1"]] },
];

const profile: SignatureInputProfile = "rfc9651-extension";

export async function compileSurface(
  message: SignableMessage
): Promise<string> {
  const fields = await signatureHeaders(
    message,
    {
      keyid: "test-key",
      alg: "ed25519",
      sign: () => new Uint8Array([1]),
    },
    {
      created: new Date(0),
      expires: new Date(1_000),
      alg: "ed25519",
      components,
      signatureInputProfile: profile,
    }
  );
  return fields["Signature-Input"];
}
