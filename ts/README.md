# Attested OHTTP Client for TypeScript

A TypeScript port of the attested Oblivious HTTP (OHTTP) client. This library allows you to make HTTP requests through an OHTTP gateway, providing enhanced privacy by encrypting the request and response data using HPKE (Hybrid Public Key Encryption).

## Features

- Make oblivious HTTP requests through an OHTTP gateway
- Support for binary request/response data
- Support for streaming responses
- Built-in attestation support
- Compliant with the [OHTTP specification](https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-02.html)

## Installation

```bash
npm install attested-ohttp-client-ts
```

## Usage

### Basic Request

```typescript
import { sendOhttpRequest, OhttpClientConfig } from 'attested-ohttp-client-ts';

async function main() {
  // Configure the request
  const config: OhttpClientConfig = {
    gatewayUrl: 'https://example-gateway.com/.well-known/ohttp-relay',
    requestPath: '/api/data',
    requestMethod: 'POST',
    requestBody: new TextEncoder().encode(JSON.stringify({ query: 'example' })),
    requestHeaders: {
      'content-type': 'application/json',
      'accept': 'application/json'
    },
    outerRequestHeaders: {
      'user-agent': 'attested-ohttp-client-ts/0.1.0'
    }
  };

  // Send the request
  const response = await sendOhttpRequest(config);
  
  // Process the response
  console.log('Response headers:', response.responseHeaders);
  const respBody = new TextDecoder().decode(response.responseBody);
  console.log('Response body:', respBody);
}

main().catch(console.error);
```

### Streaming Response

```typescript
import { sendOhttpRequestStream, OhttpClientConfig } from 'attested-ohttp-client-ts';

async function streamExample() {
  const config: OhttpClientConfig = {
    gatewayUrl: 'https://example-gateway.com/.well-known/ohttp-relay',
    requestPath: '/api/stream',
    requestMethod: 'GET',
    requestHeaders: { 'accept': 'text/event-stream' }
  };

  // Get a ReadableStream
  const stream = await sendOhttpRequestStream(config);
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  
  // Process the stream
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    console.log('Chunk:', decoder.decode(value, { stream: true }));
  }
}

streamExample().catch(console.error);
```

### Using a Pre-configured Key

If you have a key configuration, you can provide it directly:

```typescript
const config: OhttpClientConfig = {
  // ... other config options ...
  
  // As a hex string
  keyConfig: '00200001000100204c656cad9da6c99b14f9c6e07492743cc1021fefa8bda92ebd084fb42da7e9e',
  
  // Or as a Uint8Array
  // keyConfig: new Uint8Array([...])
};
```

## Key Management Service (KMS)

For security and key rotation purposes, the library can fetch key configurations from a KMS. By default, if no `keyConfig` is provided, the library will attempt to fetch the configuration from the gateway URL.

## Development

### Prerequisites

- Node.js (v14+)
- npm (v7+)

### Building from Source

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/attested-ohttp-client-ts.git
cd attested-ohttp-client-ts
npm install
npm run build
```

### Running Examples

```bash
npm run build
node dist/examples/basic-usage.js
```

## Documentation

For detailed documentation, please see the [API Reference](API.md).

## License

This project is licensed under the MIT or Apache-2.0 License - see the LICENSE file for details.
