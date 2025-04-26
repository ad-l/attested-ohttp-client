import { loadCrypto } from "./webCrypto.js";
import { concatArrays, i2Osp, max, varintDecode, xorArrays } from "./utils";
import {
  InvalidConfigIdError,
  InvalidContentTypeError,
  InvalidEncodingError,
  InvalidHpkeCiphersuiteError,
} from "./errors";

import { Aead, AeadId, CipherSuite, Kdf, KdfId, Kem, KemId } from "hpke-js";
import { BHttpDecoder, BHttpEncoder } from "bhttp-js";

const invalidEncodingErrorString = "Invalid message encoding";
const invalidKeyIdErrorString = "Invalid configuration ID";
const invalidHpkeCiphersuiteErrorString = "Invalid HPKE ciphersuite";
const invalidContentTypeErrorString = "Invalid content type";

const requestInfoLabel = "message/bhttp request";
const responseInfoLabel = "message/bhttp response";
const chunkedResponseInfoLabel = "message/bhttp chunked response";
const aeadKeyLabel = "key";
const aeadNonceLabel = "nonce";
const requestHdrLength = 7; // len(keyID) + len(kemID) + len(kdfID) + len(aeadID)

async function randomBytes(l: number): Promise<Uint8Array> {
  const buffer = new Uint8Array(l);
  const cryptoApi = await loadCrypto();
  cryptoApi.getRandomValues(buffer);
  return buffer;
}

function encodeSymmetricAlgorithms(kdf: Kdf, aead: Aead): Uint8Array {
  return new Uint8Array([
    0x00,
    0x04, // Length
    (kdf >> 8) & 0xFF,
    kdf & 0xFF,
    (aead >> 8) & 0xFF,
    aead & 0xFF,
  ]);
}

export function parseKeyConfig(configBytes: Uint8Array): {
  keyId: number;
  kemId: number;
  kdfId: number;
  aeadId: number;
  publicKey: Uint8Array;
} {
  let offset = 0;
  
  // Skip Key Identifier (8 bits = 1 byte)
  const keyId = configBytes[offset];
  offset += 1;
  
  // HPKE KEM ID (16 bits = 2 bytes)
  const kemId = (configBytes[offset] << 8) | configBytes[offset + 1];
  offset += 2;
  
  // Determine public key length based on KEM ID
  let publicKeyLength: number;
  switch (kemId) {
    case 0x0010: // DHKEM(P-256, HKDF-SHA256)
      publicKeyLength = 65; // 65 bytes for P-256
      break;
    case 0x0011: // DHKEM(P-384, HKDF-SHA384)
      publicKeyLength = 97; // 97 bytes for P-384
      break;
    case 0x0012: // DHKEM(P-521, HKDF-SHA512)
      publicKeyLength = 133; // 133 bytes for P-521
      break;
    case 0x0020: // DHKEM(X25519, HKDF-SHA256)
      publicKeyLength = 32; // 32 bytes for X25519
      break;
    default:
      throw new Error(`Unsupported KEM ID: ${kemId.toString(16)}`);
  }
  
  // Extract HPKE Public Key
  const publicKey = configBytes.slice(offset, offset + publicKeyLength);
  offset += publicKeyLength;
  
  // HPKE Symmetric Algorithms Length (16 bits = 2 bytes)
  const symAlgLength = (configBytes[offset] << 8) | configBytes[offset + 1];
  offset += 2;
  
  if (symAlgLength < 4 || symAlgLength > 65532) {
    throw new Error(`Invalid HPKE Symmetric Algorithms Length: ${symAlgLength}`);
  }
  
  // Parse HPKE Symmetric Algorithms
  // Each algorithm entry is 4 bytes (32 bits) containing KDF ID (16 bits) and AEAD ID (16 bits)
  const kdfId = (configBytes[offset] << 8) | configBytes[offset + 1];
  offset += 2;
  
  const aeadId = (configBytes[offset] << 8) | configBytes[offset + 1];
  offset += 2;

  return {
    keyId,
    kemId,
    kdfId,
    aeadId,
    publicKey
  };
}

export class KeyConfig {
  public keyId: number;
  public kem: Kem;
  public kdf: Kdf;
  public aead: Aead;
  public keyPair: Promise<CryptoKeyPair>;

  constructor(keyId: number) {
    if (keyId < 0 || keyId > 255) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    this.keyId = keyId;
    this.kem = Kem.DhkemP384HkdfSha384;
    this.kdf = Kdf.HkdfSha256;
    this.aead = Aead.Aes128Gcm;
    const suite = new CipherSuite({
      kem: this.kem,
      kdf: this.kdf,
      aead: this.aead,
    });
    this.keyPair = suite.generateKeyPair();
  }

  async publicConfig(): Promise<PublicKeyConfig> {
    const publicKey = (await this.keyPair).publicKey;
    return new PublicKeyConfig(
      this.keyId,
      this.kem,
      this.kdf,
      this.aead,
      publicKey,
    );
  }
}

export class PublicKeyConfig {
  public keyId: number;
  public kem: Kem;
  public kdf: Kdf;
  public aead: Aead;
  public suite: CipherSuite;
  public publicKey: CryptoKey;

  constructor(
    keyId: number,
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
    publicKey: CryptoKey,
  ) {
    if (keyId < 0 || keyId > 255) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    this.keyId = keyId;
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;

    this.suite = new CipherSuite({
      kem: this.kem,
      kdf: this.kdf,
      aead: this.aead,
    });

    this.publicKey = publicKey;
  }

  async encode(): Promise<Uint8Array> {
    const preamble = new Uint8Array([
      this.keyId & 0xFF,
      (this.kem >> 8) & 0xFF,
      this.kem & 0xFF,
    ]);
    const encodedKey = new Uint8Array(
      await this.suite.kem.serializePublicKey(
        this.publicKey,
      ),
    );
    const algorithms = encodeSymmetricAlgorithms(
      this.kdf,
      this.aead,
    );
    return concatArrays(concatArrays(preamble, encodedKey), algorithms);
  }

  async encodeAsList(): Promise<Uint8Array> {
    const encodedConfig = await this.encode();
    return concatArrays(i2Osp(encodedConfig.length, 2), encodedConfig);
  }
}

export class ServerResponse {
  public readonly responseNonce: Uint8Array;
  public readonly encResponse: Uint8Array;

  constructor(responseNonce: Uint8Array, encResponse: Uint8Array) {
    this.responseNonce = responseNonce;
    this.encResponse = encResponse;
  }

  encode(): Uint8Array {
    return concatArrays(this.responseNonce, this.encResponse);
  }
}

export class ServerResponseContext {
  public readonly encodedRequest: Uint8Array;
  private enc: Uint8Array;
  private secret: Uint8Array;
  private suite: CipherSuite;

  constructor(
    suite: CipherSuite,
    request: Uint8Array,
    secret: Uint8Array,
    enc: Uint8Array,
  ) {
    this.encodedRequest = request;
    this.enc = enc;
    this.secret = secret;
    this.suite = suite;
  }

  async encapsulate(encodedResponse: Uint8Array): Promise<ServerResponse> {
    const responseNonce = await randomBytes(
      max(this.suite.aead.keySize, this.suite.aead.nonceSize),
    );
    const salt = concatArrays(new Uint8Array(this.enc), responseNonce);
    const prk = await this.suite.kdf.extract(salt, this.secret);
    const aeadKey = await this.suite.kdf.expand(
      prk,
      new TextEncoder().encode(aeadKeyLabel),
      this.suite.aead.keySize,
    );
    const aeadNonce = await this.suite.kdf.expand(
      prk,
      new TextEncoder().encode(aeadNonceLabel),
      this.suite.aead.nonceSize,
    );

    const aeadKeyS = await this.suite.aead.createEncryptionContext(aeadKey);
    const encResponse = new Uint8Array(
      await aeadKeyS.seal(
        aeadNonce,
        encodedResponse,
        new TextEncoder().encode(""),
      ),
    );

    return new ServerResponse(responseNonce, encResponse);
  }

  async encapsulateResponse(response: Response): Promise<Response> {
    const encoder = new BHttpEncoder();
    const encodedResponse = await encoder.encodeResponse(response);

    const serverResponse = await this.encapsulate(encodedResponse);
    return new Response(serverResponse.encode(), {
      status: 200,
      headers: {
        "Content-Type": "message/ohttp-res",
      },
    });
  }

  request(): Request {
    const decoder = new BHttpDecoder();
    return decoder.decodeRequest(this.encodedRequest);
  }
}

export class Server {
  private config: KeyConfig;

  constructor(config: KeyConfig) {
    this.config = config;
  }

  async decapsulate(
    clientRequest: ClientRequest,
  ): Promise<ServerResponseContext> {
    let info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
    info = concatArrays(info, new Uint8Array([0x00]));
    info = concatArrays(info, clientRequest.hdr);

    const recipientKeyPair = await this.config.keyPair;
    const recipient = await clientRequest.suite.createRecipientContext({
      recipientKey: recipientKeyPair,
      enc: clientRequest.enc,
      info: info,
    });

    const request = new Uint8Array(
      await recipient.open(clientRequest.encapsulatedReq),
    );

    const exportContext = new TextEncoder().encode(responseInfoLabel);
    const secret = new Uint8Array(
      await recipient.export(exportContext, clientRequest.suite.aead.keySize),
    );

    return new ServerResponseContext(
      clientRequest.suite,
      request,
      secret,
      clientRequest.enc,
    );
  }

  async decodeAndDecapsulate(msg: Uint8Array): Promise<ServerResponseContext> {
    if (msg.length < requestHdrLength) {
      throw new InvalidEncodingError(invalidEncodingErrorString);
    }
    const hdr = msg.slice(0, requestHdrLength);
    
    // Extract the configuration parameters from the header using the utility function
    const config = {
      keyId: hdr[0],
      kemId: (hdr[1] << 8) | hdr[2],
      kdfId: (hdr[3] << 8) | hdr[4],
      aeadId: (hdr[5] << 8) | hdr[6],
      publicKey: new Uint8Array() // Not needed here
    };

    if (config.keyId != this.config.keyId) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    
    const suite = new CipherSuite({
      kem: config.kemId as KemId,
      kdf: config.kdfId as KdfId,
      aead: config.aeadId as AeadId,
    });
    
    const encSize = suite.kem.encSize;
    if (msg.length < requestHdrLength+encSize) {
      throw new InvalidEncodingError(invalidEncodingErrorString);
    }
    const enc = msg.slice(requestHdrLength, requestHdrLength+encSize);
    
    const encRequest = msg.slice(requestHdrLength+encSize, msg.length);
    return await this.decapsulate(ClientRequest.fromConfig(config, enc, encRequest));
  }

  async decapsulateRequest(request: Request): Promise<ServerResponseContext> {
    const { headers } = request;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-req") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    const encapRequestBody = new Uint8Array(await request.arrayBuffer());
    return this.decodeAndDecapsulate(encapRequestBody);
  }

  async encodeKeyConfig(): Promise<Uint8Array> {
    const publicConfig = await this.config.publicConfig();
    return publicConfig.encode();
  }

  async encodeKeyConfigAsList(): Promise<Uint8Array> {
    const publicConfig = await this.config.publicConfig();
    return publicConfig.encodeAsList();
  }
  
}

export class Client {
  private config: PublicKeyConfig;
  private suite: CipherSuite;

  constructor(config: PublicKeyConfig) {
    this.config = config;
    this.suite = new CipherSuite({
      kem: this.config.kem,
      kdf: this.config.kdf,
      aead: this.config.aead,
    });
  }

  async encapsulate(encodedRequest: Uint8Array): Promise<ClientRequestContext> {
    // Create a config object with all the necessary parameters
    const config = {
      keyId: this.config.keyId,
      kemId: this.suite.kem.id,
      kdfId: this.suite.kdf.id,
      aeadId: this.suite.aead.id
    };
    
    // Create a temporary request to get the correct header format
    const tempRequest = ClientRequest.fromConfig(config, new Uint8Array(0), new Uint8Array(0));
    const hdr = tempRequest.hdr;
    
    // Create the info data
    let info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
    info = concatArrays(info, new Uint8Array([0x00]));
    info = concatArrays(info, hdr);

    const publicKey = this.config.publicKey;
    const sender = await this.suite.createSenderContext({
      recipientPublicKey: publicKey,
      info: info,
    });

    const encRequest = new Uint8Array(await sender.seal(encodedRequest));
    const enc = new Uint8Array(sender.enc);
    const exportContext = new TextEncoder().encode(responseInfoLabel);
    const secret = new Uint8Array(
      await sender.export(exportContext, this.suite.aead.keySize),
    );
    
    // Use the ClientRequest factory method
    const request = ClientRequest.fromConfig(config, enc, encRequest);
    
    return new ClientRequestContext(
      this.suite,
      request.hdr,  // Use the header from the request
      request.enc,  // Use the enc from the request
      request.encapsulatedReq,  // Use the encapsulated request from the request
      secret
    );
  }

  async encapsulateRequest(
    originalRequest: Request,
  ): Promise<ClientRequestContext> {
    const encoder = new BHttpEncoder();
    const encodedRequest = await encoder.encodeRequest(originalRequest);
    const encapRequestContext = await this.encapsulate(encodedRequest);
    return encapRequestContext;
  }
}

class ClientRequest {
  public readonly suite: CipherSuite;
  public readonly hdr: Uint8Array;
  public readonly enc: Uint8Array;
  public readonly encapsulatedReq: Uint8Array;

  constructor(suite: CipherSuite, hdr: Uint8Array, enc: Uint8Array, encapsulatedReq: Uint8Array) {
    this.suite = suite;
    this.hdr = hdr;
    this.enc = enc;
    this.encapsulatedReq = encapsulatedReq;
  }

  static fromConfig(config: {
    keyId: number;
    kemId: number;
    kdfId: number;
    aeadId: number;
  }, enc: Uint8Array, encapsulatedReq: Uint8Array): ClientRequest {
    // Create header from config data
    let hdr = new Uint8Array([config.keyId]);
    hdr = concatArrays(hdr, i2Osp(config.kemId, 2));
    hdr = concatArrays(hdr, i2Osp(config.kdfId, 2));
    hdr = concatArrays(hdr, i2Osp(config.aeadId, 2));
    
    const suite = new CipherSuite({
      kem: config.kemId as KemId,
      kdf: config.kdfId as KdfId,
      aead: config.aeadId as AeadId,
    });
    
    return new ClientRequest(suite, hdr, enc, encapsulatedReq);
  }

  encode(): Uint8Array {
    var prefix = concatArrays(this.hdr, this.enc);
    return concatArrays(prefix, this.encapsulatedReq);
  }

  request(relayUrl: string): Request {
    const encapsulatedRequest = this.encode();
    return new Request(relayUrl, {
      method: "POST",
      body: encapsulatedRequest,
      headers: {
        "Content-Type": "message/ohttp-req",
      },
    });
  }
}

class ClientRequestContext {
  public readonly request: ClientRequest;
  private secret: Uint8Array;
  private suite: CipherSuite;

  constructor(
    suite: CipherSuite,
    hdr: Uint8Array,
    enc: Uint8Array,
    encapsulatedReq: Uint8Array,
    secret: Uint8Array,
  ) {
    this.request = new ClientRequest(suite, hdr, enc, encapsulatedReq);
    this.secret = secret;
    this.suite = suite;
  }

  async decapsulate(serverResponse: ServerResponse): Promise<Uint8Array> {
    const senderEnc = new Uint8Array(
      this.request.enc,
      0,
      this.request.enc.length,
    );
    const salt = concatArrays(senderEnc, serverResponse.responseNonce);

    const prk = await this.suite.kdf.extract(salt, this.secret);
    const aeadKey = await this.suite.kdf.expand(
      prk,
      new TextEncoder().encode(aeadKeyLabel),
      this.suite.aead.keySize,
    );
    const aeadNonce = await this.suite.kdf.expand(
      prk,
      new TextEncoder().encode(aeadNonceLabel),
      this.suite.aead.nonceSize,
    );

    const aeadKeyS = await this.suite.aead.createEncryptionContext(aeadKey);
    const request = new Uint8Array(
      await aeadKeyS.open(
        aeadNonce,
        serverResponse.encResponse,
        new TextEncoder().encode(""),
      ),
    );

    return request;
  }

  async decodeAndDecapsulate(msg: Uint8Array): Promise<Uint8Array> {
    const responseNonceLen = max(
      this.suite.aead.keySize,
      this.suite.aead.nonceSize,
    );
    const responseNonce = msg.slice(0, responseNonceLen);
    const encResponse = msg.slice(responseNonceLen, msg.length);
    return await this.decapsulate(
      new ServerResponse(responseNonce, encResponse),
    );
  }

  async decapsulateResponse(response: Response): Promise<Response> {
    const { headers } = response;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-res") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    const encapResponseBody = new Uint8Array(await response.arrayBuffer());
    const encodedResponse = await this.decodeAndDecapsulate(encapResponseBody);

    const decoder = new BHttpDecoder();
    return decoder.decodeResponse(encodedResponse);
  }

  async decapsulateResponseChunked(response: Response): Promise<ReadableStream<Uint8Array>> {
    const { headers } = response;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-chunked-res") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    if (!response.body) {
      throw new Error("Response body is null");
    }

    // Set up the AEAD key and nonce derivation
    const responseNonceLen = max(
      this.suite.aead.keySize,
      this.suite.aead.nonceSize,
    );

    // For chunked responses, reading is more complex.
    // First, we need to read the response nonce from the beginning of the stream.
    const reader = response.body.getReader();
    
    // Read the nonce
    const { value: nonceBytes, done: nonceDone } = await reader.read();
    if (!nonceBytes || nonceBytes.length < responseNonceLen) {
      throw new Error("Failed to read response nonce");
    }
    
    // Extract the response nonce
    const responseNonce = nonceBytes.slice(0, responseNonceLen);
    
    // If we have more data in the first chunk, we'll handle it later
    let remainingData = nonceBytes.length > responseNonceLen ? 
      nonceBytes.slice(responseNonceLen) : new Uint8Array(0);
    
    // Set up the decryption key and nonce
    const senderEnc = new Uint8Array(
      this.request.enc,
      0,
      this.request.enc.length,
    );
    const salt = concatArrays(senderEnc, responseNonce);
    
    const prk = await this.suite.kdf.extract(salt, this.secret);
    const aeadKey = await this.suite.kdf.expand(
      prk,
      new TextEncoder().encode(aeadKeyLabel),
      this.suite.aead.keySize,
    );
    const aeadNonce = await this.suite.kdf.expand(
      prk,
      new TextEncoder().encode(aeadNonceLabel),
      this.suite.aead.nonceSize,
    );
    
    // Create the AEAD encryption context
    const aeadKeyS = await this.suite.aead.createEncryptionContext(aeadKey);
    const nonceLen = this.suite.aead.nonceSize;
    
    // Define a TransformStream to handle the chunked response
    return new ReadableStream({
      async start(controller) {
        let buffer = remainingData;
        let counter = 0;
        
        try {
          while (true) {
            // If we don't have enough data to even read a varint length, fetch more
            if (buffer.length === 0) {
              const { value, done } = await reader.read();
              if (done) break;
              buffer = value;
              if (buffer.length === 0) continue;
            }
            
            try {
              // Try to decode the varint length
              let { value: chunkLength, bytesConsumed } = varintDecode(buffer);
              buffer = buffer.slice(bytesConsumed);

              // Check if this is the final chunk
              const isFinalChunk = chunkLength === 0;

              if(isFinalChunk) {
                // Read last fragment length
                const { value: cl, bytesConsumed:c } = varintDecode(buffer);
                bytesConsumed += c;
                chunkLength = cl;
                buffer = buffer.slice(c);
              }
              
              // If we don't have enough data for the full chunk, fetch more
              while (buffer.length < chunkLength) {
                const { value, done } = await reader.read();
                if (done) {
                  throw new Error("Stream ended prematurely");
                }
                buffer = concatArrays(buffer, value);
              }

              // Extract the chunk data
              const chunkData = buffer.slice(0, chunkLength);
              buffer = buffer.slice(chunkLength);
              
              // Compute the chunk nonce by XORing the base nonce with the counter
              const counterArray = i2Osp(counter, nonceLen);
              const chunkNonce = xorArrays(new Uint8Array(aeadNonce), counterArray);
              
              // Decrypt the chunk with the appropriate AAD
              const aad = isFinalChunk ? 
                new TextEncoder().encode("final") : 
                new TextEncoder().encode("");

              // Open the encrypted chunk
              const openResult = await aeadKeyS.open(
                chunkNonce,
                chunkData,
                aad
              );

              controller.enqueue(new Uint8Array(openResult));

              // If this was the final chunk, we're done
              if (isFinalChunk) {
                break;
              }
              
              // Increment the counter for the next chunk
              counter++;
            } catch (error) {
              // If varint decoding failed, we need more data
              const { value, done } = await reader.read();
              if (done) break;
              buffer = concatArrays(buffer, value);
            }
          }
          
          // Close the controller when we're done
          controller.close();
        } catch (error) {
          console.error("Error during stream processing:", error);
          controller.error(error);
        }
      }
    });
  }
}
