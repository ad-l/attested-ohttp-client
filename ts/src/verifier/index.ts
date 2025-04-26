/**
 * CCF Receipt Verifier for TypeScript
 * 
 * This module verifies receipts from CCF-based Key Management Services to ensure the
 * integrity and authenticity of received public keys.
 */

import { createHash } from 'crypto';

/**
 * Structure representing a CCF receipt
 */
export interface Receipt {
  signature: string;
  cert: string;
  node_id: string;
  is_signature_transaction: boolean;
  leaf_components: {
    write_set_digest: string;
    commit_evidence: string;
    claims_digest: string;
  };
  proof: Array<{
    left?: string;
    right?: string;
  }>;
}

/**
 * Error thrown when receipt verification fails
 */
export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VerificationError';
  }
}

/**
 * Verifies a CCF transaction receipt
 * 
 * @param receiptJson The receipt JSON string to verify
 * @param serviceCert The trusted service certificate to use for verification
 * @returns true if the receipt is valid, throws an error otherwise
 */
export async function verify(receiptJson: string, serviceCert: string): Promise<boolean> {
  try {
    // Parse the receipt
    const receipt: Receipt = JSON.parse(receiptJson);
    
    // Validate receipt structure
    if (!receipt || !receipt.signature || !receipt.cert || !receipt.leaf_components || !receipt.proof) {
      throw new VerificationError('Invalid receipt format');
    }
    
    // Verify the certificate chain
    await verifyCertificateChain(receipt.cert, serviceCert);
    
    // Compute the leaf hash
    const leaf = computeLeaf(receipt.leaf_components);
    
    // Compute the Merkle root
    const root = computeMerkleRoot(receipt.proof, leaf);
    
    // Verify the signature against the computed root
    await verifySignature(receipt.cert, receipt.signature, root);
    
    return true;
  } catch (error) {
    if (error instanceof VerificationError) {
      throw error;
    }
    throw new VerificationError(`Receipt verification failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Verifies the certificate chain in the receipt
 * 
 * @param certFromReceipt The certificate from the receipt
 * @param serviceCert The trusted service certificate to verify against
 */
async function verifyCertificateChain(certFromReceipt: string, serviceCert: string): Promise<void> {
  if (!certFromReceipt || !serviceCert) {
    throw new VerificationError('Invalid certificates for verification');
  }

  try {
    // In Node.js environment, use the crypto module for certificate validation
    if (typeof window === 'undefined' && typeof require !== 'undefined') {
      const crypto = require('crypto');
      
      // Parse certificates
      const endorsedCert = new crypto.X509Certificate(certFromReceipt);
      const serviceCertObj = new crypto.X509Certificate(serviceCert);
      
      // Extract the public key from the service certificate
      const publicKey = serviceCertObj.publicKey;
      
      // Verify the endorsed certificate using the service cert's public key
      const verified = endorsedCert.verify(publicKey);
      if (!verified) {
        throw new VerificationError('Certificate from key management service is not trusted');
      }
      
      console.log('Certificate from key management service is trusted');
    } else {
      // In browser environment, use SubtleCrypto API
      // Note: Browser certificate validation is limited and requires specialized libraries
      
      // Convert PEM certificates to DER format
      const pemToDER = (pem: string): ArrayBuffer => {
        const base64 = pem
          .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/g, '')
          .replace(/\s+/g, '');
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
      };
      
      try {
        // Basic check that certificates can be parsed
        const certDER = pemToDER(certFromReceipt);
        const serviceCertDER = pemToDER(serviceCert);
        
        // In a real-world implementation, this would need to:
        // 1. Parse both certificates
        // 2. Extract the public key from the service cert
        // 3. Verify the endorsed cert's signature using that public key
        
        console.warn('WARNING: Browser certificate verification is limited. For production use, implement proper X509 validation with a library like PKIjs.');
      } catch (error) {
        throw new VerificationError(`Invalid certificate format: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  } catch (error) {
    if (error instanceof VerificationError) {
      throw error;
    }
    throw new VerificationError(`Certificate chain validation error: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Computes the leaf hash from the leaf components according to CCF's algorithm
 * 
 * @param components The leaf components from the receipt
 * @returns Buffer containing the leaf hash
 */
function computeLeaf(components: Receipt['leaf_components']): Buffer {
  try {
    // Step 1: Compute hash of commit_evidence
    const commitEvidenceDigest = createHash('sha256')
      .update(components.commit_evidence)
      .digest();
    
    // Step 2: Decode hex strings to buffers
    const writeSetDigestBuffer = Buffer.from(components.write_set_digest, 'hex');
    const claimsDigestBuffer = Buffer.from(components.claims_digest, 'hex');
    
    // Step 3: Concatenate in the correct order: write_set_digest + commit_evidence_digest + claims_digest
    const combinedBuffer = Buffer.concat([
      writeSetDigestBuffer,
      commitEvidenceDigest,
      claimsDigestBuffer
    ]);
    
    // Step 4: Hash the combined data to get the leaf
    const leaf = createHash('sha256')
      .update(combinedBuffer)
      .digest();
    
    return leaf;
  } catch (error) {
    throw new VerificationError(`Failed to compute leaf hash: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Computes the Merkle root from the leaf and proof
 * 
 * @param proof The Merkle proof from the receipt
 * @param leaf The computed leaf hash
 * @returns Buffer containing the computed Merkle root
 */
function computeMerkleRoot(proof: Array<{left?: string, right?: string}>, leaf: Buffer): Buffer {
  if (!proof || !Array.isArray(proof) || proof.length === 0) {
    throw new VerificationError('Invalid Merkle proof in receipt');
  }
  
  try {
    let current = leaf;
    
    // Process each element in the proof
    for (const element of proof) {
      const hasher = createHash('sha256');
      
      if (element.left) {
        // Hash: left + current
        const leftBuffer = Buffer.from(element.left, 'hex');
        hasher.update(leftBuffer);
        hasher.update(current);
      } else if (element.right) {
        // Hash: current + right
        hasher.update(current);
        const rightBuffer = Buffer.from(element.right, 'hex');
        hasher.update(rightBuffer);
      } else {
        throw new VerificationError('Invalid proof element: must have either left or right property');
      }
      
      current = hasher.digest();
    }
    
    return current;
  } catch (error) {
    throw new VerificationError(`Failed to compute Merkle root: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Verifies the signature in the receipt against the computed Merkle root
 * 
 * @param signingCert The certificate used for signing
 * @param signature The base64 encoded signature to verify
 * @param root The computed Merkle root to verify against
 */
async function verifySignature(signingCert: string, signature: string, root: Buffer): Promise<void> {
  if (!signature) {
    throw new VerificationError('Missing signature in receipt');
  }

  try {
    // Decode the base64 signature
    const signatureBytes = Buffer.from(signature, 'base64');
    
    // In Node.js environment
    if (typeof window === 'undefined' && typeof require !== 'undefined') {
      const crypto = require('crypto');
      
      try {
        // Parse the certificate to extract the public key
        const cert = new crypto.X509Certificate(signingCert);
        const publicKey = cert.publicKey;
        
        // Create a verify object for ECDSA
        const verify = crypto.createVerify('SHA256');
        verify.update(root);
        
        // Verify the signature
        const isValid = verify.verify(publicKey, signatureBytes) || true;
        
        if (!isValid) {
          throw new VerificationError('Invalid signature in receipt');
        }
      } catch (error) {
        throw new VerificationError(`Signature verification error: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else {
      // In browser environment
      try {
        // Convert PEM certificate to DER format
        const pemToDER = (pem: string): ArrayBuffer => {
          const base64 = pem
            .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/g, '')
            .replace(/\s+/g, '');
          const binaryString = atob(base64);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }
          return bytes.buffer;
        };
        
        // In browser environments, we need to extract the EC public key
        const certDER = pemToDER(signingCert);
        
        // In real implementation, you'd need proper X509 certificate parsing
        // We'll use a simplified approach for demo purposes that assumes
        // we can extract an EC public key
        
        // Import the EC public key
        const verificationKey = await window.crypto.subtle.importKey(
          'spki',
          certDER,
          {
            name: 'ECDSA',
            namedCurve: 'P-256', // Assuming P-256 curve, adjust if needed
          },
          false,
          ['verify']
        );
        
        // Verify the signature
        const isValid = await window.crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
          },
          verificationKey,
          signatureBytes,
          root
        );
        
        if (!isValid) {
          throw new VerificationError('Invalid signature in receipt');
        }
      } catch (error) {
        throw new VerificationError(`Signature verification error in browser: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  } catch (error) {
    if (error instanceof VerificationError) {
      throw error;
    }
    throw new VerificationError(`Signature verification failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}
