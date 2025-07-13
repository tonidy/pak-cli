/**
 * Native Apple Secure Enclave Implementation (Standardized)
 *
 * This implementation uses a Swift-based native Node.js addon for direct
 * Security Framework access. It relies on the centralized `format-utils`
 * module to handle all cryptographic formatting, ensuring that it is
 * interoperable with the CLI and Pure JS backends.
 */

import * as path from 'path';
import { sha256 } from '@noble/hashes/sha256';
import {
  SecureEnclaveKeyPair,
  SecureEnclaveCapabilities,
  SecureEnclaveConfig,
  AppleSecureEnclaveAPI
} from '../../types';
import {
  encodeIdentity,
  decodeIdentity,
  encodeRecipient,
  decodeRecipient,
  compressPublicKey,
  decompressPublicKey,
} from '../format-utils';

// Load the native addon
let nativeAddon: any;
try {
  const nativeModulePath = path.join(__dirname, '../../../native');
  nativeAddon = require(nativeModulePath);
} catch (error) {
  const errorMsg = error instanceof Error ? error.message : String(error);
  console.warn('Native Secure Enclave addon not available:', errorMsg);
  console.warn('Falling back to CLI backend. To use native SE, ensure you have Xcode/Swift installed and run: npm run build');
  nativeAddon = null;
}

export class NativeSecureEnclave implements AppleSecureEnclaveAPI {
  private config: SecureEnclaveConfig;
  private keyMapping?: Map<string, Buffer>;

  constructor(config: SecureEnclaveConfig) {
    this.config = config;
    if (!nativeAddon) {
      throw new Error('Native Secure Enclave addon not available. Please build the native module first.');
    }
  }

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin' || !nativeAddon) {
      return false;
    }
    try {
      return nativeAddon.isAvailable();
    } catch (error) {
      return false;
    }
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    const isAvailable = await this.isAvailable();
    return {
      isAvailable,
      supportsKeyGeneration: isAvailable,
      supportsEncryption: isAvailable,
      supportsDecryption: isAvailable,
      supportedAccessControls: isAvailable ? [
        'none', 'passcode', 'any-biometry', 'any-biometry-or-passcode',
        'any-biometry-and-passcode', 'current-biometry', 'current-biometry-and-passcode'
      ] : [],
      platform: process.platform,
      version: 'native-2.0.0',
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    const result = await nativeAddon.generateKeyPair(accessControl);
    
    if (!result || !result.publicKey || !result.privateKey) {
      throw new Error('Invalid key pair returned from native addon');
    }
    
    const rawPublicKey = result.publicKey;
    const privateKeyData = result.privateKey;
    
    const compressedPubKey = compressPublicKey(rawPublicKey);
    
    // For cross-backend compatibility, we'll use the actual private key data
    // truncated to 32 bytes for the identity encoding
    const privateKeyBuffer = Buffer.from(privateKeyData);
    const keyIdentifier = privateKeyBuffer.slice(0, 32);
    
    const identity = encodeIdentity(keyIdentifier);
    const recipient = encodeRecipient(compressedPubKey);

    // Store the mapping from identifier to actual key data
    // This is needed because the native key data is larger than 32 bytes
    if (!this.keyMapping) {
      this.keyMapping = new Map<string, Buffer>();
    }
    
    // Store the key mapping using the identity string as the key
    this.keyMapping.set(identity, privateKeyBuffer);
    
    console.log('[NATIVE] Generated key pair:');
    console.log(`  - identifierHex: ${keyIdentifier.toString('hex').substring(0, 20)}...`);
    console.log(`  - identity: ${identity.substring(0, 50)}...`);
    console.log(`  - recipient: ${recipient}`);
    console.log(`  - keyMapping size: ${this.keyMapping.size}`);

    return {
      identity,
      recipient,
      publicKey: compressedPubKey,
      privateKeyRef: identity, // Use identity for cross-backend compatibility
      accessControl,
      createdAt: new Date()
    };
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    // Look up the actual key data from our mapping using the identity string
    const privateKeyData = this.keyMapping?.get(identity);
    if (!privateKeyData) {
      throw new Error('Key not found in mapping. Native keys must be generated in the same session.');
    }
    
    // The public key must be derived from the private key via the native addon
    const rawPublicKey = await nativeAddon.getPublicKey(privateKeyData);
    const compressedPubKey = compressPublicKey(rawPublicKey);
    const recipient = encodeRecipient(compressedPubKey);

    return {
      identity,
      recipient,
      publicKey: compressedPubKey,
      privateKeyRef: identity,
      accessControl: this.config.accessControl, // Not stored in key
      createdAt: new Date() // Not stored in key
    };
  }

  async deleteKeyPair(identity: string): Promise<boolean> {
    // Look up the actual key data from our mapping using the identity string
    const privateKeyData = this.keyMapping?.get(identity);
    if (!privateKeyData) {
      return false; // Key not found
    }
    
    // Delete from mapping
    if (this.keyMapping) {
      this.keyMapping.delete(identity);
    }
    
    return nativeAddon.deleteKey(privateKeyData);
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    const recipientPublicKey = decodeRecipient(recipient);
    // The native addon expects a 64-byte uncompressed key
    const decompressedKey = decompressPublicKey(recipientPublicKey);
    
    // Get the raw encrypted data from native addon
    const rawEncrypted = await nativeAddon.encrypt(Buffer.from(data), Buffer.from(decompressedKey));
    
    // The native addon returns: ephemeralPublicKey (64 bytes raw) + encryptedData
    // Extract components
    const ephemeralPublicKey = rawEncrypted.slice(0, 64);
    const encryptedData = rawEncrypted.slice(64);
    
    console.log('[NATIVE] Ephemeral key debug:');
    console.log('  - Length:', ephemeralPublicKey.length);
    console.log('  - Hex:', Buffer.from(ephemeralPublicKey).toString('hex').substring(0, 32) + '...');
    
    // The ephemeral key is in raw format (64 bytes), compress it
    const ephemeralCompressed = compressPublicKey(ephemeralPublicKey);
    
    // Create the age file format
    const tag = sha256(recipientPublicKey).slice(0, 4);
    
    // Build the age file
    const header = new TextEncoder().encode('age-encryption.org/v1\n-> piv-p256 ');
    const stanza = new TextEncoder().encode(`${Buffer.from(tag).toString('base64')} ${Buffer.from(ephemeralCompressed).toString('base64')}\n`);
    const body = new TextEncoder().encode(`${Buffer.from(encryptedData).toString('base64')}\n---`);
    
    // Combine all parts
    const finalCiphertext = new Uint8Array(header.length + stanza.length + body.length);
    finalCiphertext.set(header, 0);
    finalCiphertext.set(stanza, header.length);
    finalCiphertext.set(body, header.length + stanza.length);
    
    return finalCiphertext;
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    console.log('[NATIVE] Decrypt called with privateKeyRef:', privateKeyRef?.substring(0, 50) + '...');
    
    // Look up the actual key data from our mapping using the identity string
    const privateKeyData = this.keyMapping?.get(privateKeyRef);
    if (!privateKeyData) {
      console.error('[NATIVE] Key not found in mapping!');
      console.error('  - Looking for:', privateKeyRef?.substring(0, 50) + '...');
      console.error('  - Available keys:', this.keyMapping ? Array.from(this.keyMapping.keys()).map(k => k.substring(0, 50) + '...') : []);
      throw new Error('Native backend requires keys to be generated in the same session due to Secure Enclave constraints.');
    }
    
    // Parse the age file format
    const textDecoder = new TextDecoder();
    const text = textDecoder.decode(ciphertext);
    
    const headerEnd = text.indexOf('\n---');
    if (headerEnd === -1) {
      // If it's not in age format, assume it's raw encrypted data
      return nativeAddon.decrypt(Buffer.from(ciphertext), privateKeyData);
    }
    
    const header = text.substring(0, headerEnd);
    const stanzas = header.split('-> ').slice(1);
    
    for (const stanzaText of stanzas) {
      const lines = stanzaText.trim().split('\n');
      const args = lines[0].split(' ');
      if (args[0] !== 'piv-p256' || args.length < 3) continue;
      
      const ephemeralPublicKey = Buffer.from(args[2], 'base64');
      const encryptedData = Buffer.from(lines[1], 'base64');
      
      // Decompress the ephemeral public key for native addon
      const ephemeralDecompressed = decompressPublicKey(ephemeralPublicKey);
      
      // Combine ephemeral public key and encrypted data for native addon
      const combinedData = Buffer.concat([ephemeralDecompressed, encryptedData]);
      
      try {
        return await nativeAddon.decrypt(combinedData, privateKeyData);
      } catch (e) {
        // This stanza was not for us, continue
        continue;
      }
    }
    
    throw new Error('Decryption failed: no matching recipient stanza found.');
  }

  async identityToRecipient(identity: string): Promise<string> {
    // Look up the actual key data from our mapping using the identity string
    const privateKeyData = this.keyMapping?.get(identity);
    if (!privateKeyData) {
      throw new Error('Key not found in mapping. Native keys must be generated in the same session.');
    }
    
    const rawPublicKey = await nativeAddon.getPublicKey(privateKeyData);
    const compressedPubKey = compressPublicKey(rawPublicKey);
    return encodeRecipient(compressedPubKey);
  }

  // These methods are part of the API but are now either simple validators
  // or have their logic centralized in the manager or format-utils.
  
  validateAccessControl(accessControl: string): boolean {
    const validControls = [
      'none', 'passcode', 'any-biometry', 'any-biometry-or-passcode',
      'any-biometry-and-passcode', 'current-biometry', 'current-biometry-and-passcode'
    ];
    return validControls.includes(accessControl);
  }

  recipientToAgeFormat(publicKey: Uint8Array): string {
    // This is a simple wrapper now, as the main logic is in encodeRecipient.
    // The 'type' parameter is less relevant as we standardize on one format.
    return encodeRecipient(compressPublicKey(publicKey));
  }

  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string } {
    // The core logic is now in format-utils. Access control is not stored in the key.
    const data = decodeIdentity(identity);
    return {
      data,
      accessControl: this.config.accessControl
    };
  }
}