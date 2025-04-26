/**
 * Example demonstrating basic usage of the attested OHTTP client
 */
import { sendOhttpRequest, OhttpClientConfig, sendOhttpRequestStream } from '../src';

async function main() {
  // Example configuration
  const config: OhttpClientConfig = {
    // Gateway URL (relay server)
    gatewayUrl: 'https://example-gateway.com/.well-known/ohttp-relay',
    
    // Target resource path for the encapsulated request
    requestPath: '/api/data',
    
    // HTTP method for the encapsulated request
    requestMethod: 'POST',
    
    // Body content for the encapsulated request
    // Here we're encoding a JSON object, but it could be any binary data
    requestBody: new TextEncoder().encode(JSON.stringify({ 
      query: 'example-query',
      timestamp: new Date().toISOString()
    })),
    
    // Headers for the encapsulated request
    requestHeaders: {
      'content-type': 'application/json',
      'accept': 'application/json'
    },
    
    // Headers for the outer request to the gateway
    outerRequestHeaders: {
      'user-agent': 'attested-ohttp-client-ts/0.1.0'
    }
    
    // Note: key configuration will be fetched from the gateway
    // if not provided. To specify it directly, use:
    // keyConfig: 'hex-encoded-key-config-string'
    // or
    // keyConfig: new Uint8Array([...]) // Binary key config
  };

  console.log('Sending standard OHTTP request...');
  try {
    // Send a standard OHTTP request
    const response = await sendOhttpRequest(config);
    
    // Log response information
    console.log('Response headers:', response.headers);
    
    // Handle the response based on content type
    if (response.headers.get('content-type')?.includes('application/json')) {
      // Handle JSON response
      const jsonData = await response.json();
      console.log('Parsed JSON response:', jsonData);
    } else {
      let body = await response.text();
      console.log('Response body (first 100 bytes):', body.substring(0, 100), "...");
    }
    
    // Now try a streaming request
    console.log('\nSending streaming OHTTP request...');
    const stream = await sendOhttpRequestStream(config);
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    
    // Process the stream
    console.log('Received streaming response:');
    let streamedData = '';
    let chunkCount = 0;
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      // Process each chunk
      const chunk = decoder.decode(value, { stream: true });
      streamedData += chunk;
      chunkCount++;
      
      console.log(`[Chunk ${chunkCount}] ${chunk.slice(0, 50)}...`);
    }
    
    // Flush the decoder
    streamedData += decoder.decode();
    
    console.log(`Received ${chunkCount} chunks in total`);
    console.log('Complete streamed data:', streamedData.length > 200 ? 
      `${streamedData.slice(0, 200)}... (${streamedData.length} bytes total)` : 
      streamedData);
  } catch (error) {
    console.error('Error occurred:', error);
  }
}

// Run the example
main().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
