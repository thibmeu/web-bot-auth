import { describe, expect, it } from "vitest";

import { decode, encode } from "../src/base64";

describe("base64", () => {
  it.each([0, 1, 2, 3, 65_535, 65_536, 200_000])(
    "round trips %i bytes without argument spreading",
    (length) => {
      const input = Uint8Array.from(
        { length },
        (_, index) => (index * 31 + 17) % 256
      );

      const encoded = encode(input);

      expect(encoded).toHaveLength(Math.ceil(length / 3) * 4);
      expect(decode(encoded)).toEqual(input);
    }
  );
});
