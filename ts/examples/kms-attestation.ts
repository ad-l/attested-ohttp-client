/**
 * Example demonstrating OHTTP client with CCF-based KMS attestation verification
 * 
 * This example shows how to:
 * 1. Set up an OHTTP client with KMS attestation verification
 * 2. Fetch key configuration from a KMS with receipt verification
 * 3. Make an attested OHTTP request using the verified keys
 */
import { sendOhttpRequest, OhttpClientConfig, sendOhttpRequestStream } from '../src';

// Type-safe check for Node.js environment
const isNodeEnv = typeof window === 'undefined';

// TypeScript-friendly way to access Node.js specific features
declare const __dirname: string;
declare const require: any;
declare const process: { exit: (code: number) => void };
declare const module: { exports: any };

async function main() {
  console.log('Demonstrating OHTTP client with CCF-based KMS attestation verification');
  
  // Certificate path - will be resolved differently in Node.js vs browser
  let certPath: string;
  if (isNodeEnv) {
    // Node.js environment
    const path = require('path');
    certPath = path.resolve(__dirname, '../../certs/kms-cert.pem');
  } else {
    // Browser environment
    certPath = '../../certs/kms-cert.pem';
  }
  
  // Example configuration with KMS certificate path for attestation verification
  const config: OhttpClientConfig = {
    // Gateway URL (relay server)
    gatewayUrl: 'http://confdeepseek.centraluseuap.cloudapp.azure.com/score',
    
    // KMS URL for fetching attested public keys
    // You can also use the same URL as the gateway if it provides its own keys
    kmsUrl: 'https://test-acl-kms.confidential-ledger.azure.com',
    
    // Path to the trusted certificate for validating the KMS attestation
    kmsCertPath: certPath,

    requestBody: new TextEncoder().encode(JSON.stringify({
      model: 'deepseek-ai/DeepSeek-R1',
      messages: [{"role": "user","content": "What is the capital of France?"}],
      stream: false,
    })),
    
    // Target resource path for the encapsulated request
    requestPath: '/v1/chat/completions',
    
    // HTTP method for the encapsulated request
    requestMethod: 'POST',
    
    // Headers for the encapsulated request
    requestHeaders: {
      'accept': 'application/json',
      'content-type': 'application/json',
      'x-attestation-token': "true"
    },
    
    // Headers for the outer request to the gateway
    outerRequestHeaders: {
      'user-agent': 'attested-ohttp-client-ts/0.1.0',
    }
  };

  try {   
    // The client will automatically:
    // 1. Contact the KMS to fetch key configurations
    // 2. Verify the attestation receipt using the provided certificate
    // 3. Use the verified key to create an encrypted OHTTP request
    console.log('Sending attested OHTTP request...');
    
    const reader = (await sendOhttpRequestStream(config)).getReader();
    let decoder = new TextDecoder("utf-8");
    
    console.log('\nRequest successful!');
    reader.read().then(function processText({ done, value }) : any {
      if(value) {
        const frag = decoder.decode(value, { stream: true });
        console.log("Received chunk:", frag);
      }
      if (done) return;
      return reader.read().then(processText);
    }).then(() => {
      console.log("Stream complete");
    });
    decoder.decode();

    console.log('\nDemo completed successfully.');
  } catch (error) {
    console.error('Error during attestation verification or request:', error);
    
    if (error instanceof Error && error.message.includes('attestation')) {
      console.error('\nAttestation verification failed. This could mean:');
      console.error('- The KMS certificate is invalid or not trusted');
      console.error('- The receipt from the KMS is invalid or tampered with');
      console.error('- The KMS is not a legitimate CCF-based service');
    }
  }
}

// Run the example automatically in browser environments
// In Node.js, we'll check if this file is being run directly
if (!isNodeEnv) {
  // Browser environment - run example automatically
  main().catch(console.error);
} else {
  // Node.js environment - check if this module is being run directly
  const isMainModule = require.main === module;
  if (isMainModule) {
    main().catch((error: Error) => {
      console.error('Unhandled error:', error);
      process.exit(1);
    });
  }
}

export default main;
