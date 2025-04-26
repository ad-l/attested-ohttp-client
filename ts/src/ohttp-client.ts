import { concatUint8Arrays, hexToBytes, bytesToHex } from './utils';
import * as ohttp from "./ohttp";

// Import types from hpke-js directly
import { Aead, AeadId, CipherSuite, Kdf, KdfId, Kem, KemId } from "hpke-js";

// Import Client from ohttp
import { Client } from './ohttp';

// Export interfaces for client configuration
export interface OhttpClientConfig {
  gatewayUrl: string;
  requestPath: string;
  requestMethod: string;
  requestBody?: Uint8Array;
  requestHeaders?: Record<string, string>;
  outerRequestHeaders?: Record<string, string>;
}

// OhttpClient interface definition for export
export interface OhttpClient {
  encapsulate(request: Uint8Array): Promise<any>;
  encapsulateRequest(request: Request): Promise<any>;
}

// Builder pattern for constructing OhttpClient instances
export class OhttpClientBuilder {
  private configBytes?: Uint8Array;
  private kmsUrl?: string;
  private kmsCertPath?: string;

  constructor() {
    // Initialize with empty values
  }

  // Set the config bytes directly
  withConfig(config: Uint8Array): OhttpClientBuilder {
    this.configBytes = config;
    return this;
  }

  // Set the config from a hex string
  withConfigHex(configHex: string): OhttpClientBuilder {
    this.configBytes = hexToBytes(configHex);
    return this;
  }

  // Set the KMS URL for fetching keys
  withKmsUrl(url: string): OhttpClientBuilder {
    this.kmsUrl = url;
    return this;
  }

  // Set the KMS certificate path
  withKmsCertPath(path: string): OhttpClientBuilder {
    this.kmsCertPath = path;
    return this;
  }

  // Build the OHTTP client
  async build(): Promise<Client> {
    // If we have configBytes, use them directly
    if (this.configBytes) {
      // Parse the config bytes to extract key parameters
      const config = ohttp.parseKeyConfig(this.configBytes);
      
      // Convert numeric IDs to their enum types
      const kemId = config.kemId as KemId;
      const kdfId = config.kdfId as KdfId;
      const aeadId = config.aeadId as AeadId;
      
      // Create a CipherSuite
      const suite = new CipherSuite({
        kem: kemId,
        kdf: kdfId,
        aead: aeadId
      });
      
      // Import the raw public key bytes into a crypto key
      const publicKey = await suite.kem.deserializePublicKey(config.publicKey);
      
      // Map numeric KEM, KDF, and AEAD IDs to their enum values
      const kem = Kem[Object.keys(Kem).find(k => Kem[k as keyof typeof Kem] === kemId) as keyof typeof Kem];
      const kdf = Kdf[Object.keys(Kdf).find(k => Kdf[k as keyof typeof Kdf] === kdfId) as keyof typeof Kdf];
      const aead = Aead[Object.keys(Aead).find(k => Aead[k as keyof typeof Aead] === aeadId) as keyof typeof Aead];
      
      // Create a PublicKeyConfig with the parsed parameters
      const publicKeyConfig = new ohttp.PublicKeyConfig(
        config.keyId,
        kem,
        kdf,
        aead,
        publicKey
      );
      // Return a new Client instance
      return new ohttp.Client(publicKeyConfig);
    }
    
    // If we have KMS URL, fetch config from KMS
    if (this.kmsUrl && this.kmsCertPath) {
      const config = await this.fetchConfigFromKms();
      console.log('Fetched config from KMS:', bytesToHex(config));
      // Parse the config bytes to extract key parameters
      const parsedConfig = ohttp.parseKeyConfig(config);
      
      // Convert numeric IDs to their enum types
      const kemId = parsedConfig.kemId as KemId;
      const kdfId = parsedConfig.kdfId as KdfId;
      const aeadId = parsedConfig.aeadId as AeadId;
      
      // Create a CipherSuite
      const suite = new CipherSuite({
        kem: kemId,
        kdf: kdfId,
        aead: aeadId
      });
      
      // Import the raw public key bytes into a crypto key
      const publicKey = await suite.kem.deserializePublicKey(parsedConfig.publicKey);
      
      // Map numeric KEM, KDF, and AEAD IDs to their enum values
      const kem = Kem[Object.keys(Kem).find(k => Kem[k as keyof typeof Kem] === kemId) as keyof typeof Kem];
      const kdf = Kdf[Object.keys(Kdf).find(k => Kdf[k as keyof typeof Kdf] === kdfId) as keyof typeof Kdf];
      const aead = Aead[Object.keys(Aead).find(k => Aead[k as keyof typeof Aead] === aeadId) as keyof typeof Aead];
      
      // Create a PublicKeyConfig with the parsed parameters
      const publicKeyConfig = new ohttp.PublicKeyConfig(
        parsedConfig.keyId,
        kem,
        kdf,
        aead,
        publicKey
      );
      // Return a new Client instance
      return new ohttp.Client(publicKeyConfig);
    }
    
    throw new Error("Either key config or KMS URL + certificate must be provided");
  }

  // Fetch config from KMS
  private async fetchConfigFromKms(): Promise<Uint8Array> {
    if (!this.kmsUrl || !this.kmsCertPath) {
      throw new Error("KMS URL and certificate path must be set");
    }
    
    // Read the certificate file
    let trustedCert: string;
    try {
      if (typeof window === 'undefined' && typeof require !== 'undefined') {
        // Node.js environment
        const fs = require('fs');
        trustedCert = fs.readFileSync(this.kmsCertPath, 'utf8');
      } else {
        // Browser environment - would need to fetch the certificate
        const response = await fetch(this.kmsCertPath);
        trustedCert = await response.text();
      }
    } catch (error) {
      throw new Error(`Failed to read KMS certificate: ${error instanceof Error ? error.message : String(error)}`);
    }
    
    // Create endpoint URL for fetching the key configuration
    const kmsEndpoint = new URL('/app/listpubkeys', this.kmsUrl).toString();
    
    // Set up retry parameters
    const maxRetries = 3;
    let retries = 0;
    const retryDelayMs = 1000; // 1 second delay between retries
    
    // Different handling for Node.js and browser environments
    let responseData: any;
    
    if (typeof window === 'undefined' && typeof require !== 'undefined') {
      // In Node.js, use HTTPS module with certificate
      // Import Node.js modules
      const https = require('https');
      const { URL } = require('url');
      
      // Parse the URL
      const parsedUrl = new URL(kmsEndpoint);
      
      while (retries <= maxRetries) {
        try {
          // Make the request using the Node.js https module directly with the certificate
          responseData = await new Promise<any>((resolve, reject) => {
            const options = {
              hostname: parsedUrl.hostname,
              port: parsedUrl.port || 443,
              path: parsedUrl.pathname,
              method: 'GET',
              headers: {
                'Accept': 'application/json',
                'User-Agent': 'attested-ohttp-client-ts/0.1.0'
              },
              ca: trustedCert, // Use the KMS certificate as a trusted CA root
              rejectUnauthorized: true // Enforce TLS verification
            };
            
            const req = https.request(options, (res: any) => {
              // Handle 202 status code (retry)
              if (res.statusCode === 202) {
                if (retries < maxRetries) {
                  return reject({ statusCode: 202, retryable: true });
                } else {
                  return reject(new Error(`Max retries reached (${maxRetries}), giving up. KMS is not ready.`));
                }
              }
              
              // Check for other error status codes
              if (res.statusCode !== 200) {
                return reject(new Error(`HTTP error from KMS: ${res.statusCode}`));
              }
              
              // Collect the response data
              const chunks: Buffer[] = [];
              res.on('data', (chunk: Buffer) => {
                chunks.push(chunk);
              });
              
              res.on('end', () => {
                const responseBody = Buffer.concat(chunks).toString('utf-8');
                try {
                  resolve(JSON.parse(responseBody));
                } catch (error) {
                  reject(new Error(`Failed to parse KMS response as JSON: ${error instanceof Error ? error.message : String(error)}`));
                }
              });
            });
            
            req.on('error', (error: any) => {
              reject(new Error(`HTTPS request to KMS failed: ${error.message}`));
            });
            
            // End the request
            req.end();
          });
          
          // If we got here, we have a successful response
          break;
          
        } catch (error) {
          // Handle retryable errors (like 202 status code)
          if (error && typeof error === 'object' && 'retryable' in error && error.retryable) {
            if (retries < maxRetries) {
              console.log(`KMS returned 202 status code, retrying... (attempt ${retries + 1}/${maxRetries})`);
              retries++;
              // Wait before retrying
              await new Promise(resolve => setTimeout(resolve, retryDelayMs));
              continue;
            }
          }
          
          // Non-retryable error or max retries reached
          throw error instanceof Error 
            ? error 
            : new Error(`Failed to fetch from KMS using HTTPS: ${String(error)}`);
        }
      }
    } else {
      // In browser environment, use fetch (note: browsers don't support custom CA certificates)
      console.warn('Browser environment detected. TLS verification with KMS certificate not supported in browsers.');
      
      while (retries <= maxRetries) {
        try {
          const response = await fetch(kmsEndpoint, {
            method: 'GET',
            headers: {
              'Accept': 'application/json',
              'User-Agent': 'attested-ohttp-client-ts/0.1.0'
            }
          });
          
          // Handle 202 status code (retry)
          if (response.status === 202) {
            if (retries < maxRetries) {
              console.log(`KMS returned 202 status code, retrying... (attempt ${retries + 1}/${maxRetries})`);
              retries++;
              // Wait before retrying
              await new Promise(resolve => setTimeout(resolve, retryDelayMs));
              continue;
            } else {
              throw new Error(`Max retries reached (${maxRetries}), giving up. KMS is not ready.`);
            }
          }
          
          // Handle other error status codes
          if (!response.ok) {
            throw new Error(`HTTP error from KMS: ${response.status} ${response.statusText}`);
          }
          
          // Parse the JSON response
          responseData = await response.json();
          break;
          
        } catch (error) {
          // Check if this is the last retry
          if (retries >= maxRetries) {
            throw new Error(`Failed to fetch from KMS: ${error instanceof Error ? error.message : String(error)}`);
          }

          // Otherwise increment retry counter
          retries++;
          // Wait before retrying
          await new Promise(resolve => setTimeout(resolve, retryDelayMs));
        }
      }
    }

    if (!Array.isArray(responseData) || responseData.length === 0) {
      throw new Error('Invalid response from KMS: Expected an array with at least one element');
    }

    // Extract key config and receipt
    const keyConfig = responseData[0].publicKey;
    const receipt = responseData[0].receipt;
    
    // Verify the receipt using our verifier
    try {
      // Dynamically import the verifier to avoid circular dependencies
      const { verify } = await import('./verifier/index.js');
      
      // Convert receipt to JSON string if it's not already a string
      const receiptJson = typeof receipt === 'string' ? receipt : JSON.stringify(receipt);
      
      // Verify the receipt
      await verify(receiptJson, trustedCert);
    } catch (error) {
      throw new Error(`Attestation verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    
    // If we get here, the receipt is valid, so we can use the key config
    // Parse the key config (expected to be a hex string)
    if (!keyConfig || typeof keyConfig !== 'string') {
      throw new Error('Invalid key configuration received from KMS');
    }
    
    // Convert the key config from hex to bytes
    try {
      return hexToBytes(keyConfig);
    } catch (error) {
      throw new Error(`Invalid key config format: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
