/**
 * Utility functions for the OHTTP client implementation
 */

/**
 * Converts a hexadecimal string to a Uint8Array
 * @param hex The hexadecimal string to convert
 * @returns A Uint8Array containing the decoded bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  // Remove '0x' prefix if present
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  
  // Ensure even length
  const paddedHex = cleanHex.length % 2 === 0 ? cleanHex : '0' + cleanHex;
  
  const bytes = new Uint8Array(paddedHex.length / 2);
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes[i / 2] = parseInt(paddedHex.substring(i, i + 2), 16);
  }
  
  return bytes;
}

/**
 * Converts a Uint8Array to a hexadecimal string
 * @param bytes The Uint8Array to convert
 * @returns A hexadecimal string representation of the bytes
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Creates a random string using alphanumeric characters
 * @param length The length of the random string to generate
 * @returns A random alphanumeric string
 */
export function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

/**
 * Converts a plain object of headers to the standard Headers format
 * @param headers The headers object to convert
 * @returns A Headers object
 */
export function objectToHeaders(headers: Record<string, string>): Headers {
  const result = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    result.append(key, value);
  }
  return result;
}

/**
 * Converts a Headers object to a plain object
 * @param headers The Headers object to convert
 * @returns A plain object of header key-value pairs
 */
export function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

/**
 * Creates a multipart/form-data body from the given fields
 * @param fields The fields to include in the multipart body
 * @param boundary The boundary string to use
 * @returns A FormData object
 */
export function createMultipartFormData(fields: Record<string, string | Blob>): FormData {
  const formData = new FormData();
  
  for (const [name, value] of Object.entries(fields)) {
    formData.append(name, value);
  }
  
  return formData;
}

/**
 * Reads a file from the given path and returns it as a Uint8Array
 * @param filePath The path to the file to read
 * @returns A Promise that resolves to the file contents as a Uint8Array
 */
export async function readFileAsBytes(filePath: string): Promise<Uint8Array> {
  // In browser environments, this would need to be handled differently
  // Using Node.js fs module for file operations
  if (typeof window === 'undefined' && typeof require !== 'undefined') {
    const fs = require('fs');
    const buffer = fs.readFileSync(filePath);
    return new Uint8Array(buffer);
  } else {
    throw new Error('File reading is only supported in Node.js environments');
  }
}

/**
 * Concatenates multiple Uint8Arrays into a single Uint8Array
 * @param arrays The arrays to concatenate
 * @returns A new Uint8Array containing all the input arrays
 */
export function concatUint8Arrays(...arrays: Uint8Array[]): Uint8Array {
  // Calculate the total length
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  
  // Create a new array with the total length
  const result = new Uint8Array(totalLength);
  
  // Copy each array into the result
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  
  return result;
}

declare const Deno: undefined;
declare const caches: undefined;

/**
 * Checks whether the execution env is browser or not.
 */
export const isBrowser = () => typeof window !== "undefined";

/**
 * Checks whether the execution env is Cloudflare Workers or not.
 */
export const isCloudflareWorkers = () => typeof caches !== "undefined";

/**
 * Checks whether the execution env is Deno or not.
 */
export const isDeno = () => typeof Deno !== "undefined";

/**
 * Checks whetehr the type of input is CryptoKeyPair or not.
 */
export const isCryptoKeyPair = (x: unknown): x is CryptoKeyPair =>
  typeof x === "object" &&
  x !== null &&
  typeof (x as CryptoKeyPair).privateKey === "object" &&
  typeof (x as CryptoKeyPair).publicKey === "object";

/**
 * Converts integer to octet string. I2OSP implementation.
 */
export function i2Osp(n: number, w: number): Uint8Array {
  if (w <= 0) {
    throw new Error("i2Osp: too small size");
  }
  if (n >= 256 ** w) {
    throw new Error("i2Osp: too large integer");
  }
  const ret = new Uint8Array(w);
  for (let i = 0; i < w && n; i++) {
    ret[w - (i + 1)] = n % 256;
    n = n >> 8;
  }
  return ret;
}

/**
 * Return a new array that is the concatennation of the two input arrays.
 * @param a array
 * @param b array
 * @returns concatenation of a and b
 */
export function concatArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

/**
 * Return the maximum of two numbers.
 * @param a number
 * @param b number
 * @returns the larger of a and b
 */
export function max(a: number, b: number): number {
  if (a > b) {
    return a;
  }
  return b;
}

/**
 * Encode a number as a varint.
 * @param value The number to encode
 * @returns A Uint8Array containing the varint-encoded value
 */
export function varintEncode(value: number): Uint8Array {
  if (value < 0) {
    throw new Error("varintEncode: negative values not supported");
  }
  
  if (value < 128) {
    return new Uint8Array([value]);
  }
  
  const bytes = [];
  while (value > 0) {
    let byte = value & 0x7f;
    value >>= 7;
    if (value > 0) {
      byte |= 0x80;
    }
    bytes.push(byte);
  }
  
  return new Uint8Array(bytes);
}

/**
 * Decode a varint from a Uint8Array
 * @param bytes The Uint8Array containing the varint
 * @param offset The offset to start decoding from
 * @returns An object containing the decoded value and the number of bytes consumed
 */
export function varintDecode(bytes: Uint8Array, offset: number = 0): { value: number, bytesConsumed: number } {
  if (offset >= bytes.length) {
    throw new Error("varintDecode: offset out of bounds");
  }
  
  let value = 0;
  let shift = 0;
  let bytesConsumed = 0;
  
  while (true) {
    if (offset + bytesConsumed >= bytes.length) {
      throw new Error("varintDecode: incomplete varint");
    }
    
    const byte = bytes[offset + bytesConsumed];
    bytesConsumed++;
    
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      break;
    }
    
    shift += 7;
    if (shift > 28) {
      throw new Error("varintDecode: varint too large");
    }
  }
  
  return { value, bytesConsumed };
}

/**
 * XOR two Uint8Arrays of the same length
 * @param a First array
 * @param b Second array
 * @returns A new Uint8Array with the result of a XOR b
 */
export function xorArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error("xorArrays: arrays must have the same length");
  }
  
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  
  return result;
}
