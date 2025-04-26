import { OhttpClientBuilder } from '../src/ohttp-client';
import * as ohttp from '../src/ohttp.js';
import { hexToBytes } from '../src/utils';

// Direct test of the parseKeyConfig method
function testParseKeyConfigDirectly() {
  // Example key config from the task
  const exampleConfigHex = "04001104d5363907e0c3e73d7ec6ac71db7eac9f051b00c94ffeb029dc5314c504fd09a08f7c188709e3ec0a6d78bc8c7b99d9aa62a9f2cda8ecc0967432f965bd890588fcb5cb1eb85eeb44043438c2913ee8d6c2278ceac627894b1d13c3f5c7869b9c000400020002";
  const exampleConfigBytes = hexToBytes(exampleConfigHex);
  
  console.log("Testing key config parsing directly with example value...");
  
  // Create a temporary instance to access the parseKeyConfig method
  // We need to hack a bit since parseKeyConfig is private
  // For testing purposes only!
  
  // Use the parseKeyConfig function directly from ohttp
  const parsedConfig = ohttp.parseKeyConfig(exampleConfigBytes);
  
  console.log("Parsed Config:");
  console.log("KEM ID:", '0x' + parsedConfig.kemId.toString(16));
  console.log("KDF ID:", '0x' + parsedConfig.kdfId.toString(16));
  console.log("AEAD ID:", '0x' + parsedConfig.aeadId.toString(16));
  console.log("Public Key Length:", parsedConfig.publicKey.length);
  
  // Validate the expected values
  const expectedKemId = 0x0011; // DHKEM(P-384, HKDF-SHA384)
  const expectedKdfId = 0x0002; // HKDF-SHA384
  const expectedAeadId = 0x0002; // AES-256-GCM
  
  console.log("\nValidation Results:");
  console.log("KEM ID correct:", parsedConfig.kemId === expectedKemId ? "✅ Yes" : "❌ No");
  console.log("KDF ID correct:", parsedConfig.kdfId === expectedKdfId ? "✅ Yes" : "❌ No");
  console.log("AEAD ID correct:", parsedConfig.aeadId === expectedAeadId ? "✅ Yes" : "❌ No");
  console.log("Public Key has expected length (97):", parsedConfig.publicKey.length === 97 ? "✅ Yes" : "❌ No");
  
  const allCorrect = 
    parsedConfig.kemId === expectedKemId && 
    parsedConfig.kdfId === expectedKdfId && 
    parsedConfig.aeadId === expectedAeadId &&
    parsedConfig.publicKey.length === 97;
  
  console.log("\nOverall parseKeyConfig test result:", allCorrect ? "✅ PASSED" : "❌ FAILED");
  
  return allCorrect;
}

// Also try the normal client build process but catch and handle the error
async function testWithClientBuilder() {
  
  try {
    console.log("\nAttempting to build client with example config...");
    
    // Create a client using the example config
    const clientBuilder = new OhttpClientBuilder().withKmsCertPath("certs/kms-cert.pem").withKmsUrl("https://test-acl-kms.confidential-ledger.azure.com");
    const client = await clientBuilder.build();
    console.log("Successfully created client!");
    const req0 = new Request("http://localhost:5000/v1/chat/completions", {
      method: "POST",
      body: new TextEncoder().encode(JSON.stringify({
        model: 'deepseek-ai/DeepSeek-R1',
        stream: true,
        messages: [{"role": "user","content": "What is the capital of France?"}],
      })),
      headers: {
        "Content-Type": "application/json",
        "x-attestation-token": "true",
      },
    });

    const ctx = await client.encapsulateRequest(req0);
    let req = ctx.request.request("http://confdeepseek.centraluseuap.cloudapp.azure.com/score");
    let res0 = await fetch(req);
    console.log("Response Status:", res0.status);
    console.log("Response Outer Headers:", res0.headers);
    let stream = await ctx.decapsulateResponseChunked(res0);
    let decoder = new TextDecoder("utf-8");

    const reader = stream.getReader();

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
    
    return true;
  } catch (error) {
    console.dir(error);
    console.error("Failed to create client with example config. Error:", error);
    return false;
  }
}

// Run the tests
async function runTests() {
  const parseTestPassed = testParseKeyConfigDirectly();
  
  if (parseTestPassed) {
    console.log("\n🎉 Success! The key configuration parsing is working correctly.");
    console.log("The format of the CBOR key configuration is properly parsed into its components.");
  } else {
    console.error("\n❌ The key configuration parsing is not working correctly.");
  }

  const clientBuildTestPassed = await testWithClientBuilder();
}

runTests().catch(console.error);
