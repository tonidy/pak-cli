/**
 * Pure JavaScript Secure Enclave Implementation (Standardized)
 * 
 * This implementation simulates Secure Enclave operations using standard,
 * interoperable cryptographic formats as defined by the age-plugin-se spec.
 * It uses @noble/curves for P-256 operations and our custom format-utils
 * to ensure all keys and formats are compatible with the CLI and native backends.
 * 
 * Note: As a pure JS implementation, keys are not hardware-backed.
 */

import { p256 } from '@noble/curves/p256';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from 'crypto';

import { 
  SecureEnclaveKeyPair, 
  SecureEnclaveCapabilities, 
  SecureEnclaveConfig 
} from '../../types';
import {
  encodeIdentity,
  decodeIdentity,
  encodeRecipient,
  decodeRecipient,
} from '../format-utils';

export class PureJSSecureEnclave {
  private config: SecureEnclaveConfig;
  // Store raw private keys (as hex strings) since this is not hardware-backed
  private keyStore: Map<string, Uint8Array> = new Map();

  constructor(config: SecureEnclaveConfig) {
    this.config = config;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    return {
      isAvailable: true,
      supportsKeyGeneration: true,
      supportsEncryption: true,
      supportsDecryption: true,
      supportedAccessControls: [
        'none', 'passcode', 'any-biometry', 'any-biometry-or-passcode',
        'any-biometry-and-passcode', 'current-biometry', 'current-biometry-and-passcode'
      ],
      platform: process.platform,
      version: 'pure-js-2.0.0',
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    const privateKey = p256.utils.randomPrivateKey();
    const publicKey = p256.getPublicKey(privateKey, true); // true for compressed

    const identity = encodeIdentity(privateKey);
    const recipient = encodeRecipient(publicKey);
    
    // In this pure-js implementation, the "reference" is the key itself.
    const privateKeyRef = Buffer.from(privateKey).toString('hex');
    this.keyStore.set(privateKeyRef, privateKey);
    
    console.log('[PURE-JS] Generated key pair:');
    console.log('  - privateKeyRef:', privateKeyRef.substring(0, 20) + '...');
    console.log('  - identity:', identity.substring(0, 50) + '...');
    console.log('  - recipient:', recipient);
    console.log('  - keyStore size:', this.keyStore.size);

    return {
      identity,
      recipient,
      publicKey,
      privateKeyRef,
      accessControl,
      createdAt: new Date()
    };
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    console.log('[PURE-JS] Loading key pair from identity:', identity.substring(0, 50) + '...');
    
    // Check if this is a CLI-generated identity (very long format)
    if (identity.length > 200) {
      throw new Error(`CLI-generated identity detected (length: ${identity.length}). CLI-generated identities are not compatible with Pure JS backend. Please use CLI backend with --use-age-binary flag or regenerate keys with Pure JS backend.`);
    }
    
    let privateKey: Uint8Array;
    try {
      privateKey = decodeIdentity(identity);
      
      // For CLI-generated identities that contain more than 32 bytes, take first 32 bytes
      if (privateKey.length > 32) {
        console.log('[PURE-JS] Identity contains', privateKey.length, 'bytes, extracting first 32 bytes');
        privateKey = privateKey.slice(0, 32);
      } else if (privateKey.length !== 32) {
        throw new Error(`Invalid private key length: expected 32, got ${privateKey.length}`);
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('Exceeds length limit')) {
        throw new Error(`CLI-generated identity is too long for Pure JS backend. Please use CLI backend with --use-age-binary flag or regenerate keys with Pure JS backend.`);
      }
      throw error;
    }
    
    const publicKey = p256.getPublicKey(privateKey, true);

    const recipient = encodeRecipient(publicKey);
    const privateKeyRef = Buffer.from(privateKey).toString('hex');
    this.keyStore.set(privateKeyRef, privateKey);
    
    console.log('[PURE-JS] Loaded key:');
    console.log('  - privateKeyRef:', privateKeyRef.substring(0, 20) + '...');
    console.log('  - recipient:', recipient);
    console.log('  - keyStore size:', this.keyStore.size);

    return {
      identity,
      recipient,
      publicKey,
      privateKeyRef,
      accessControl: this.config.accessControl, // Access control is not stored in the key
      createdAt: new Date() // Creation date is not stored, so we use now
    };
  }

  async deleteKeyPair(identity: string): Promise<boolean> {
    const privateKey = decodeIdentity(identity);
    const privateKeyRef = Buffer.from(privateKey).toString('hex');
    return this.keyStore.delete(privateKeyRef);
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    const recipientPublicKey = decodeRecipient(recipient);

    const ephemeralPrivateKey = p256.utils.randomPrivateKey();
    const ephemeralPublicKey = p256.getPublicKey(ephemeralPrivateKey, true);

    const sharedSecret = p256.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);
    
    const salt = new Uint8Array([...ephemeralPublicKey, ...recipientPublicKey]);
    const info = new TextEncoder().encode('piv-p256');
    
    const wrapKey = hkdf(sha256, sharedSecret, salt, info, 32);

    const fileKey = randomBytes(16);
    const sealedFileKey = chacha20poly1305(wrapKey, new Uint8Array(12)).encrypt(fileKey);

    const tag = sha256(recipientPublicKey).slice(0, 4);

    const header = new TextEncoder().encode('age-encryption.org/v1\n-> piv-p256 ');
    const stanza = new TextEncoder().encode(`${Buffer.from(tag).toString('base64')} ${Buffer.from(ephemeralPublicKey).toString('base64')}\n`);
    const body = new TextEncoder().encode(`${Buffer.from(sealedFileKey).toString('base64')}\n---`);
    
    const payloadSalt = new TextEncoder().encode('age-encryption.org/v1/payload');
    const payloadKey = hkdf(sha256, fileKey, payloadSalt, new Uint8Array(), 32);
    const payloadNonce = new Uint8Array(12);
    payloadNonce[11] = 1;

    const encryptedPayload = chacha20poly1305(payloadKey, payloadNonce).encrypt(data);

    const finalCiphertext = new Uint8Array(header.length + stanza.length + body.length + encryptedPayload.length);
    finalCiphertext.set(header, 0);
    finalCiphertext.set(stanza, header.length);
    finalCiphertext.set(body, header.length + stanza.length);
    finalCiphertext.set(encryptedPayload, header.length + stanza.length + body.length);

    return finalCiphertext;
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    console.log('[PURE-JS] Decrypt called:');
    console.log('  - privateKeyRef:', privateKeyRef?.substring(0, 20) + '...');
    
    let privateKey: Uint8Array;
    
    // Always decode from identity string for stateless operation
    if (privateKeyRef.startsWith('AGE-PLUGIN-SE-') || privateKeyRef.startsWith('age-plugin-se-')) {
      console.log('[PURE-JS] Decoding identity string...');
      
      // Check if this is a CLI-generated identity (very long format)
      if (privateKeyRef.length > 200) {
        throw new Error(`CLI-generated identity detected (length: ${privateKeyRef.length}). CLI-generated identities are not compatible with Pure JS backend. Please use CLI backend with --use-age-binary flag or regenerate keys with Pure JS backend.`);
      }
      
      try {
        privateKey = decodeIdentity(privateKeyRef);
        console.log('[PURE-JS] Successfully decoded private key from identity, length:', privateKey.length);
        
        // For CLI-generated identities that contain more than 32 bytes, take first 32 bytes
        if (privateKey.length > 32) {
          console.log('[PURE-JS] Identity contains', privateKey.length, 'bytes, extracting first 32 bytes');
          privateKey = privateKey.slice(0, 32);
        } else if (privateKey.length !== 32) {
          throw new Error(`Invalid private key length: expected 32, got ${privateKey.length}`);
        }
      } catch (error) {
        if (error instanceof Error && error.message.includes('Exceeds length limit')) {
          throw new Error(`CLI-generated identity is too long for Pure JS backend. Please use CLI backend with --use-age-binary flag or regenerate keys with Pure JS backend.`);
        }
        throw error;
      }
    } else {
      // If it's a hex string, convert it to Uint8Array
      console.log('[PURE-JS] Converting hex privateKeyRef to Uint8Array...');
      privateKey = Buffer.from(privateKeyRef, 'hex');
      console.log('[PURE-JS] Hex private key length:', privateKey.length);
      
      // Ensure we have exactly 32 bytes for the private key
      if (privateKey.length !== 32) {
        throw new Error(`Invalid private key length: expected 32, got ${privateKey.length}`);
      }
    }
    const publicKey = p256.getPublicKey(privateKey, true);
    const expectedTag = sha256(publicKey).slice(0, 4);

    const textDecoder = new TextDecoder();
    const text = textDecoder.decode(ciphertext);
    
    const headerEnd = text.indexOf('\n---');
    if (headerEnd === -1) throw new Error('Invalid age file format: missing header separator');
    
    const header = text.substring(0, headerEnd);
    const payload = ciphertext.slice(headerEnd + 4);

    const stanzas = header.split('-> ').slice(1);
    let fileKey: Uint8Array | null = null;

    for (const stanzaText of stanzas) {
        const lines = stanzaText.trim().split('\n');
        const args = lines[0].split(' ');
        if (args[0] !== 'piv-p256' || args.length < 3) continue;

        const tag = Buffer.from(args[1], 'base64');
        if (Buffer.compare(tag, Buffer.from(expectedTag)) !== 0) continue;

        const ephemeralPublicKey = Buffer.from(args[2], 'base64');
        const sealedFileKey = Buffer.from(lines[1], 'base64');

        const sharedSecret = p256.getSharedSecret(privateKey, ephemeralPublicKey);
        const salt = new Uint8Array([...ephemeralPublicKey, ...publicKey]);
        const info = new TextEncoder().encode('piv-p256');
        const wrapKey = hkdf(sha256, sharedSecret, salt, info, 32);

        try {
            fileKey = chacha20poly1305(wrapKey, new Uint8Array(12)).decrypt(sealedFileKey);
            break;
        } catch (e) {
            // This stanza was not for us, continue
        }
    }

    if (!fileKey) {
        throw new Error('Decryption failed: no matching recipient stanza found or invalid key.');
    }

    const payloadSalt = new TextEncoder().encode('age-encryption.org/v1/payload');
    const payloadKey = hkdf(sha256, fileKey, payloadSalt, new Uint8Array(), 32);
    const payloadNonce = new Uint8Array(12);
    payloadNonce[11] = 1;

    return chacha20poly1305(payloadKey, payloadNonce).decrypt(payload);
  }

  async identityToRecipient(identity: string): Promise<string> {
    const privateKey = decodeIdentity(identity);
    const publicKey = p256.getPublicKey(privateKey, true);
    return encodeRecipient(publicKey);
  }

  validateAccessControl(accessControl: string): boolean {
    const validControls = [
      'none', 'passcode', 'any-biometry', 'any-biometry-or-passcode',
      'any-biometry-and-passcode', 'current-biometry', 'current-biometry-and-passcode'
    ];
    return validControls.includes(accessControl);
  }

  recipientToAgeFormat(publicKey: Uint8Array): string {
    const { encodeRecipient, compressPublicKey } = require('../format-utils');
    return encodeRecipient(compressPublicKey(publicKey));
  }

  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string } {
    const data = decodeIdentity(identity);
    return {
      data,
      accessControl: this.config.accessControl
    };
  }
}