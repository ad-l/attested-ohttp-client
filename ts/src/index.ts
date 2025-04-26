import { Buffer } from 'buffer'; // Use Buffer for binary data handling
import { OhttpClient, OhttpClientBuilder } from './ohttp-client.js';
import { headersToObject, hexToBytes } from './utils.js';
import * as verifier from './verifier/index.js';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// Define the configuration object structure
export interface OhttpClientConfig {
    gatewayUrl: string; // URL of the OHTTP gateway
    requestPath: string; // Path of the encapsulated request
    requestMethod: string; // Method of the encapsulated request (e.g., 'GET', 'POST')
    requestBody?: Uint8Array; // Body of the encapsulated request (optional)
    requestHeaders?: Record<string, string>; // Headers of the encapsulated HTTP request (optional)
    outerRequestHeaders?: Record<string, string>; // HTTP headers of the outer request (optional)
    keyConfig?: Uint8Array | string; // OHTTP key configuration (optional, will attempt to fetch from gateway if not provided)
    kmsCertPath?: string; // Path to trusted KMS certificate (optional, used for attestation verification)
    kmsUrl?: string; // URL of the KMS to obtain HPKE keys from (optional, default is gatewayUrl)
}

// Interface for KMS key configuration response
interface KmsKeyConfiguration {
    publicKey: string;
    receipt: string;
}

// Define the response object structure
export interface OhttpResponse {
    responseHeaders: Record<string, string>; // Encapsulated headers of the response
    responseBody: Uint8Array; // Encapsulated body of the response
}

/**
 * Create an HTTP request from the provided parameters
 */
function createRequest(
    host: string,
    path: string,
    method: string,
    headers: Record<string, string> = {},
    body?: Uint8Array
): Request {
    const url = new URL(path, host);
    
    // Prepare the request options
    const init: RequestInit = {
        method,
        headers
    };
    
    // Add body if provided
    if (body) {
        init.body = body;
    }
    
    return new Request(url.toString(), init);
}

/**
 * Fetch key configuration from the gateway or KMS
 * 
 * This function retrieves the key configuration from either the gateway
 * or a separate KMS server. If the server supports attestation, it will also
 * verify the attestation receipt.
 * 
 * @param config The client configuration with gateway URL and optional KMS settings
 * @returns Promise resolving to the key configuration bytes
 */
async function fetchKeyConfig(config: OhttpClientConfig): Promise<Uint8Array> {
    // Determine the URL to use for fetching the key configuration
    const kmsUrl = config.kmsUrl || config.gatewayUrl;
    const listpubkeysUrl = new URL('/app/listpubkeys', kmsUrl).toString();
    
    console.log(`Contacting key management service at ${listpubkeysUrl}...`);
    
    // Set up retry parameters
    const maxRetries = 3;
    let retries = 0;
    
    // Check if we should use the KMS certificate for TLS verification
    if (config.kmsCertPath && typeof window === 'undefined') {
        // Node.js environment - use https module directly for custom CA support
        try {
            // Import Node.js modules
            const https = require('https');
            const fs = require('fs');
            const path = require('path');
            const { URL } = require('url');
            
            // Read the certificate file
            const cert = fs.readFileSync(config.kmsCertPath, 'utf8');
            
            console.log('Using KMS certificate as root CA for TLS verification.');
            
            // Keep trying until we get a successful response or reach max retries
            while (true) {
                try {
                    // Parse the URL for the https request
                    const parsedUrl = new URL(listpubkeysUrl);
                    
                    // Define the response type
                    interface HttpsResponse {
                        statusCode: number;
                        data: string;
                    }
                    
                    // Make the request using the Node.js https module directly with the certificate
                    const responseData = await new Promise<HttpsResponse>((resolve, reject) => {
                        const req = https.get({
                            hostname: parsedUrl.hostname,
                            port: parsedUrl.port || 443,
                            path: parsedUrl.pathname + parsedUrl.search,
                            method: 'GET',
                            ca: cert, // Use the KMS certificate as a trusted CA root
                            rejectUnauthorized: true // Enforce TLS verification
                        }, (res: any) => {
                            const statusCode = res.statusCode;
                            
                            // Collect the response data
                            let data = '';
                            res.on('data', (chunk: any) => {
                                data += chunk;
                            });
                            
                            res.on('end', () => {
                                resolve({ statusCode, data });
                            });
                        });
                        
                        req.on('error', (error: any) => {
                            reject(error);
                        });
                        
                        req.end();
                    });
                    
                    // Process the response based on status code
                    if (responseData.statusCode === 202) {
                        // Server says to retry
                        if (retries < maxRetries) {
                            retries++;
                            console.log(`Received 202 status code, retrying... (attempt ${retries}/${maxRetries})`);
                            // Wait before retrying
                            await new Promise(resolve => setTimeout(resolve, 1000));
                            continue;
                        } else {
                            throw new Error("Max retries reached, giving up. Cannot reach key management service");
                        }
                    } else if (responseData.statusCode === 200) {
                        // Success, process the response
                        if (!responseData.data) {
                            throw new Error("Empty response from key management service");
                        }
                        
                        // Parse the response and extract the key config with attestation
                        return await processKmsResponse(responseData.data, config.kmsCertPath);
                    } else {
                        throw new Error(`KMS returned unexpected ${responseData.statusCode} status code.`);
                    }
                } catch (error) {
                    if (retries < maxRetries && (error instanceof Error) && error.message.includes('retry')) {
                        // This is a retryable error, continue the loop
                        retries++;
                        console.log(`Retrying after error: ${error.message} (attempt ${retries}/${maxRetries})`);
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        continue;
                    }
                    
                    // Non-retryable error or max retries reached
                    console.error("Error fetching key configuration:", error);
                    throw error;
                }
            }
        } catch (error) {
            console.error("Error setting up TLS or fetching key configuration:", error);
            throw error;
        }
    } else {
        // Browser environment or no cert path provided - use normal fetch
        if (config.kmsCertPath && typeof window !== 'undefined') {
            console.warn('KMS certificate path provided but TLS configuration is not supported in browser environment.');
        }
        
        console.log('Using standard fetch for KMS request (no custom CA).');
        
        // Keep trying until we get a successful response or reach max retries
        while (true) {
            try {
                // Make the request to the KMS with default configuration
                const response = await fetch(listpubkeysUrl);
                
                // Handle response based on status code
                const status = response.status;
                
                if (status === 202) {
                    // Server says to retry
                    if (retries < maxRetries) {
                        retries++;
                        console.log(`Received 202 status code, retrying... (attempt ${retries}/${maxRetries})`);
                        // Wait before retrying
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        continue;
                    } else {
                        throw new Error("Max retries reached, giving up. Cannot reach key management service");
                    }
                } else if (status === 200) {
                    // Success, process the response
                    const jsonText = await response.text();
                    if (!jsonText) {
                        throw new Error("Empty response from key management service");
                    }
                    
                    // Parse the response and extract the key config with attestation
                    return await processKmsResponse(jsonText, config.kmsCertPath);
                } else {
                    throw new Error(`KMS returned unexpected ${status} status code.`);
                }
            } catch (error) {
                console.error("Error fetching key configuration:", error);
                throw error;
            }
        }
    }
}

/**
 * Process the response from the KMS and verify attestation if available
 * 
 * @param jsonResponse The JSON response from the KMS
 * @param certPath Path to the trusted certificate for verification (optional)
 * @returns Promise resolving to the key configuration bytes
 */
async function processKmsResponse(jsonResponse: string, certPath?: string): Promise<Uint8Array> {
    try {
        // Parse the KMS response
        const kmsConfigs: KmsKeyConfiguration[] = JSON.parse(jsonResponse);
        
        if (!kmsConfigs || kmsConfigs.length === 0) {
            throw new Error("No KMS configuration found");
        }
        
        // Use the first configuration (could be extended to pick specific configs)
        const kmsConfig = kmsConfigs[0];
        
        // Verify the attestation receipt if certificate path is provided
        if (certPath && kmsConfig.receipt) {
            console.log("Establishing trust in key management service...");
            
            try {
                // Read the certificate file
                let cert: string;
                if (typeof window === 'undefined') {
                    // Node.js environment
                    cert = fs.readFileSync(certPath, 'utf8');
                } else {
                    // Browser environment - fetch the certificate
                    try {
                        const response = await fetch(certPath);
                        if (!response.ok) {
                            throw new Error(`Failed to fetch certificate: ${response.status} ${response.statusText}`);
                        }
                        cert = await response.text();
                    } catch (error) {
                        throw new Error(`Failed to fetch certificate: ${error instanceof Error ? error.message : String(error)}`);
                    }
                }
                
                // Verify the receipt
                await verifier.verify(kmsConfig.receipt, cert);
                console.log("✓ Attestation verified: The receipt for the OHTTP key is valid");
            } catch (error) {
                throw new Error(`Failed to verify KMS attestation: ${error instanceof Error ? error.message : String(error)}`);
            }
        } else if (kmsConfig.receipt) {
            console.warn("⚠️ Receipt available but no certificate provided for verification");
        } else {
            console.warn("⚠️ No attestation receipt provided by KMS - using unverified key configuration");
        }
        
        // Decode the public key configuration
        return hexToBytes(kmsConfig.publicKey);
    } catch (error) {
        console.error("Failed to process KMS response:", error);
        throw error;
    }
}


/**
 * Process response to extract headers and body
 */
async function processResponse(response: Response): Promise<OhttpResponse> {
    const responseHeaders = headersToObject(response.headers);
    const responseBody = new Uint8Array(await response.arrayBuffer());
    
    return {
        responseHeaders,
        responseBody
    };
}

/**
 * Send an OHTTP request
 * This function implements the Oblivious HTTP protocol using the HPKE-JS library
 * @param config Configuration for the OHTTP request
 * @returns Promise that resolves to the OHTTP response
 */
export async function sendOhttpRequest(config: OhttpClientConfig): Promise<Response> {
    console.log('Sending OHTTP request to', config.gatewayUrl);

    try {
        // Create OHTTP client using attestation if available
        const clientBuilder = new OhttpClientBuilder();
        
        // Check if config already has key configuration
        if (config.keyConfig) {
            // If provided as string (hex), convert to bytes
            if (typeof config.keyConfig === 'string') {
                clientBuilder.withConfigHex(config.keyConfig);
            } else {
                clientBuilder.withConfig(config.keyConfig);
            }
        } else if (config.kmsUrl) {
            // Use KMS attestation if KMS URL is provided
            clientBuilder.withKmsUrl(config.kmsUrl);
            
            // Add KMS certificate path if provided
            if (config.kmsCertPath) {
                clientBuilder.withKmsCertPath(config.kmsCertPath);
            }
        } else {
            // Fetch from gateway with possible attestation verification
            const keyConfig = await fetchKeyConfig(config);
            clientBuilder.withConfig(keyConfig);
        }

        // Build the client
        const ohttpClient = await clientBuilder.build();

        // Create the encapsulated request
        const request = createRequest(
            config.gatewayUrl,
            config.requestPath,
            config.requestMethod,
            config.requestHeaders || {},
            config.requestBody
        );

        let ctx = await ohttpClient.encapsulateRequest(request);
        const outerRequest = ctx.request.request(config.gatewayUrl);
        let response = await fetch(outerRequest);

        // Check if response is OK
        if (!response.ok) {
            throw new Error(`Gateway returned error: ${response.status} ${response.statusText}`);
        }
        
        // Get response content type
        const contentType = response.headers.get('content-type');
        if (contentType !== 'message/ohttp-res') {
            console.warn(`Unexpected content type: ${contentType}. Expected: message/ohttp-res`);
        }
        
        let innerResponse = await ctx.decapsulateResponse(response);
        return innerResponse;
    } catch (error) {
        console.error('OHTTP request failed:', error);
        throw error;
    }
}

/**
 * Send an OHTTP request with streaming response
 * @param config Configuration for the OHTTP request
 * @returns Promise that resolves to a ReadableStream of the response body
 */
export async function sendOhttpRequestStream(config: OhttpClientConfig): Promise<ReadableStream<Uint8Array>> {
    console.log('Sending streaming OHTTP request to', config.gatewayUrl);

    try {
        // Create OHTTP client using attestation if available
        const clientBuilder = new OhttpClientBuilder();
        
        // Check if config already has key configuration
        if (config.keyConfig) {
            // If provided as string (hex), convert to bytes
            if (typeof config.keyConfig === 'string') {
                clientBuilder.withConfigHex(config.keyConfig);
            } else {
                clientBuilder.withConfig(config.keyConfig);
            }
        } else if (config.kmsUrl) {
            // Use KMS attestation if KMS URL is provided
            clientBuilder.withKmsUrl(config.kmsUrl);
            
            // Add KMS certificate path if provided
            if (config.kmsCertPath) {
                clientBuilder.withKmsCertPath(config.kmsCertPath);
            }
        } else {
            // Fetch from gateway with possible attestation verification
            const keyConfig = await fetchKeyConfig(config);
            clientBuilder.withConfig(keyConfig);
        }

        // Build the client
        const ohttpClient = await clientBuilder.build();

        // Create the encapsulated request
        const request = createRequest(
            config.gatewayUrl,
            config.requestPath,
            config.requestMethod,
            config.requestHeaders || {},
            config.requestBody
        );

        let ctx = await ohttpClient.encapsulateRequest(request);
        const outerRequest = ctx.request.request(config.gatewayUrl);
        let response = await fetch(outerRequest);

        // Check if response is OK
        if (!response.ok) {
            throw new Error(`Gateway returned error: ${response.status} ${response.statusText}`);
        }
        
        // Get response content type
        const contentType = response.headers.get('content-type');
        if (contentType !== 'message/ohttp-chunked-res') {
            console.warn(`Unexpected content type: ${contentType}. Expected: message/ohttp-chunked-res`);
        }
        
        let innerResponse = await ctx.decapsulateResponseChunked(response);
        return innerResponse;
    } catch (error) {
        console.error('OHTTP streaming request failed:', error);
        throw error;
    }
}

/**
 * Helper function to serialize a request to binary format
 * This is a simplified implementation - in production, use a proper HTTP binary serializer
 */
function serializeRequest(request: RequestInit): Uint8Array {
    // Create request line: "METHOD PATH HTTP/1.1\r\n"
    const requestLine = `${request.method} / HTTP/1.1\r\n`;
    
    // Create headers block
    let headersBlock = '';
    if (request.headers && request.headers instanceof Headers) {
        request.headers.forEach((value, key) => {
            headersBlock += `${key}: ${value}\r\n`;
        });
    } else if (request.headers && typeof request.headers === 'object') {
        for (const [key, value] of Object.entries(request.headers)) {
            headersBlock += `${key}: ${value}\r\n`;
        }
    }
    
    // Add end of headers marker
    headersBlock += '\r\n';
    
    // Combine parts
    const headersPart = new TextEncoder().encode(requestLine + headersBlock);
    
    // Add body if present
    if (request.body) {
        let bodyBytes: Uint8Array;
        if (request.body instanceof ArrayBuffer) {
            bodyBytes = new Uint8Array(request.body);
        } else if (request.body instanceof Uint8Array) {
            bodyBytes = request.body;
        } else {
            // This is simplified - in production, you'd handle more body types
            bodyBytes = new TextEncoder().encode(String(request.body));
        }
        
        // Combine headers and body
        const combined = new Uint8Array(headersPart.length + bodyBytes.length);
        combined.set(headersPart);
        combined.set(bodyBytes, headersPart.length);
        return combined;
    }
    
    return headersPart;
}

/**
 * Helper function to encapsulate a request using OHTTP
 */
async function encapsulateRequest(client: OhttpClient, request: Uint8Array): Promise<Uint8Array> {
    // This is a placeholder - actual implementation would depend on the OhttpClient
    // In production, this would use the actual encapsulation logic
    // For now, we're simulating the structure
    
    // Create a 16-byte fake key for demonstration
    const fakeEncapsulatedKey = new Uint8Array(16);
    crypto.getRandomValues(fakeEncapsulatedKey);
    
    // Create fake encrypted content for demonstration
    const fakeEncryptedContent = new Uint8Array(request.length);
    fakeEncryptedContent.set(request);
    
    // Structure: [key length (2 bytes)][key][encrypted request]
    const result = new Uint8Array(2 + fakeEncapsulatedKey.length + fakeEncryptedContent.length);
    result[0] = (fakeEncapsulatedKey.length >> 8) & 0xFF;
    result[1] = fakeEncapsulatedKey.length & 0xFF;
    result.set(fakeEncapsulatedKey, 2);
    result.set(fakeEncryptedContent, 2 + fakeEncapsulatedKey.length);
    
    return result;
}

/**
 * Helper function to send an encapsulated request to the gateway
 */
async function sendEncapsulatedRequest(
    gatewayUrl: string,
    encapsulatedRequest: Uint8Array,
    outerHeaders: Record<string, string>
): Promise<Response> {
    // Prepare headers
    const headers = new Headers(outerHeaders);
    headers.set('content-type', 'message/ohttp-req');
    
    // Send the request
    return fetch(gatewayUrl, {
        method: 'POST',
        headers,
        body: encapsulatedRequest
    });
}

// Export everything from ohttp-client.ts to make them available to users of this module
export * from './ohttp-client';
