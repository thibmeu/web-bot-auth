export function encode(u: Uint8Array): string {
  const chunks: string[] = [];
  const chunkSize = 8_192;
  for (let offset = 0; offset < u.length; offset += chunkSize) {
    const length = Math.min(chunkSize, u.length - offset);
    const characters: string[] = [];
    for (let index = 0; index < length; index += 1) {
      characters.push(String.fromCharCode(u[offset + index]));
    }
    chunks.push(characters.join(""));
  }
  return btoa(chunks.join(""));
}

export function decode(b: string): Uint8Array {
  const binary = atob(b);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
