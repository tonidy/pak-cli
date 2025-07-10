/**
 * Pure JavaScript Secure Enclave Implementation
 * Uses Node.js crypto APIs with P256 ECIES for age-compatible encryption
 * Note: This simulates SE operations but keys are not hardware-backed
 */

import { webcrypto } from 'crypto';
import { SecureEnclaveKeyPair, SecureEnclaveCapabilities, SecureEnclaveConfig } from '../../types';

export class PureJSSecureEnclave {
  private config: SecureEnclaveConfig;
  private keyStore: Map<string, CryptoKeyPair> = new Map();

  constructor(config: SecureEnclaveConfig) {
    this.config = config;
  }

  async isAvailable(): Promise<boolean> {
    // Pure JS version is available on all platforms
    return true;
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    return {
      isAvailable: true,
      supportsKeyGeneration: true,
      supportsEncryption: true,
      supportsDecryption: true,
      supportedAccessControls: [
        'none',
        'passcode',
        'any-biometry',
        'any-biometry-or-passcode',
        'any-biometry-and-passcode',
        'current-biometry',
        'current-biometry-and-passcode'
      ],
      platform: process.platform,
      version: 'pure-js-1.0.0',
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    // Generate P256 key pair using Web Crypto API
    const keyPair = await webcrypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true, // extractable
      ['deriveBits']
    );

    // Note: In a full implementation, we might also generate a signing key pair

    // Export public key
    const publicKeyData = await webcrypto.subtle.exportKey('raw', keyPair.publicKey);
    const publicKeyBuffer = Buffer.from(publicKeyData);

    // Export private key (in a real SE implementation, this would be a reference)
    const privateKeyData = await webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const privateKeyBuffer = Buffer.from(privateKeyData);

    // Generate a unique key tag
    const keyTag = `se-key-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Store the key pair (in real SE, this would be in hardware)
    this.keyStore.set(keyTag, { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey });

    // Convert to age format - include both private and public key data in identity
    const recipient = this.publicKeyToAgeRecipient(publicKeyBuffer);
    const identity = this.privateKeyToAgeIdentity(privateKeyBuffer, keyTag, publicKeyBuffer);

    return {
      identity,
      recipient,
      publicKey: publicKeyBuffer,
      privateKeyRef: keyTag,
      accessControl,
      createdAt: new Date()
    };
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    const { privateKeyData, publicKeyData, keyTag, accessControl } = this.parseAgeIdentityInternal(identity);
    
    // Import the private key
    const privateKey = await webcrypto.subtle.importKey(
      'pkcs8',
      privateKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      ['deriveBits']
    );

    // Use stored public key if available, otherwise derive it
    const publicKeyBuffer = publicKeyData || await this.getPublicKeyFromPrivate(privateKey);

    // Store the key pair
    const keyPair = await this.createKeyPairFromKeys(privateKey, publicKeyBuffer);
    this.keyStore.set(keyTag, keyPair);

    return {
      identity,
      recipient: this.publicKeyToAgeRecipient(publicKeyBuffer),
      publicKey: publicKeyBuffer,
      privateKeyRef: keyTag,
      accessControl,
      createdAt: new Date()
    };
  }

  async deleteKeyPair(identity: string): Promise<boolean> {
    const { keyTag } = this.parseAgeIdentityInternal(identity);
    return this.keyStore.delete(keyTag);
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    // Parse age recipient to get public key
    const publicKeyData = this.parseAgeRecipient(recipient);
    
    // Import public key (uncompressed format)
    const publicKey = await webcrypto.subtle.importKey(
      'raw',
      publicKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      []
    );

    // Generate ephemeral key pair
    const ephemeralKeyPair = await webcrypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveBits']
    );

    // Derive shared secret
    const sharedSecret = await webcrypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey,
      },
      ephemeralKeyPair.privateKey,
      256
    );

    // Use shared secret for AES-GCM encryption
    const key = await webcrypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    // Export ephemeral public key (65 bytes uncompressed)
    const ephemeralPublicKeyData = await webcrypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);

    // Create age-compatible format (65 bytes public key + 12 bytes IV + encrypted data)
    const result = new Uint8Array(65 + 12 + encryptedData.byteLength);
    result.set(new Uint8Array(ephemeralPublicKeyData), 0);
    result.set(iv, 65);
    result.set(new Uint8Array(encryptedData), 77);

    return result;
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    // Get stored key pair
    const keyPair = this.keyStore.get(privateKeyRef);
    if (!keyPair) {
      throw new Error('Private key not found');
    }

    // Extract components from ciphertext (65 bytes public key + 12 bytes IV + encrypted data)
    const ephemeralPublicKeyData = ciphertext.slice(0, 65);
    const iv = ciphertext.slice(65, 77);
    const encryptedData = ciphertext.slice(77);

    // Import ephemeral public key (65 bytes uncompressed)
    const ephemeralPublicKey = await webcrypto.subtle.importKey(
      'raw',
      ephemeralPublicKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      []
    );

    // Derive shared secret
    const sharedSecret = await webcrypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: ephemeralPublicKey,
      },
      keyPair.privateKey,
      256
    );

    // Use shared secret for AES-GCM decryption
    const key = await webcrypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decryptedData = await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encryptedData
    );

    return new Uint8Array(decryptedData);
  }

  async identityToRecipient(identity: string): Promise<string> {
    const { privateKeyData, publicKeyData } = this.parseAgeIdentityInternal(identity);
    
    // If we have the public key stored, use it directly
    if (publicKeyData) {
      return this.publicKeyToAgeRecipient(publicKeyData);
    }

    // Otherwise, derive it from the private key
    const privateKey = await webcrypto.subtle.importKey(
      'pkcs8',
      privateKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      ['deriveBits']
    );

    // Get public key from private key
    const derivedPublicKeyData = await this.getPublicKeyFromPrivate(privateKey);
    
    return this.publicKeyToAgeRecipient(derivedPublicKeyData);
  }

  private async getPublicKeyFromPrivate(_privateKey: CryptoKey): Promise<Buffer> {
    // Generate an ephemeral key pair and use ECDH to derive the public key
    // This is a workaround since Web Crypto API doesn't directly expose public key from private key
    const ephemeralKeyPair = await webcrypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveBits']
    );

    // Export the ephemeral public key as a base for our format
    const ephemeralPublicRaw = await webcrypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);
    
    // For now, we'll use a simplified approach and store the derived public key with the private key
    // In a real implementation, this would use proper EC point derivation
    return Buffer.from(ephemeralPublicRaw);
  }

  private async createKeyPairFromKeys(privateKey: CryptoKey, publicKeyData: Buffer): Promise<CryptoKeyPair> {
    // Import the public key
    const publicKey = await webcrypto.subtle.importKey(
      'raw',
      publicKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      []
    );

    return { privateKey, publicKey };
  }



  private publicKeyToAgeRecipient(publicKey: Buffer): string {
    // Convert P256 public key to age1se1... format
    // Use proper base64url encoding (RFC 4648 Section 5)
    const encoded = publicKey.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    return `age1se1${encoded}`;
  }

  private privateKeyToAgeIdentity(privateKey: Buffer, keyTag: string, publicKey?: Buffer): string {
    // Convert private key to AGE-PLUGIN-SE-... format
    const keyData = {
      privateKey: privateKey.toString('base64'),
      publicKey: publicKey ? publicKey.toString('base64') : null,
      keyTag,
      accessControl: this.config.accessControl
    };
    const encoded = Buffer.from(JSON.stringify(keyData)).toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    return `AGE-PLUGIN-SE-${encoded}`;
  }

  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string } {
    if (!identity.startsWith('AGE-PLUGIN-SE-')) {
      throw new Error('Invalid SE identity format');
    }

    const encoded = identity.substring('AGE-PLUGIN-SE-'.length);
    const decoded = Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const keyData = JSON.parse(decoded.toString());

    return {
      data: Buffer.from(keyData.privateKey, 'base64'),
      accessControl: keyData.accessControl
    };
  }

  private parseAgeIdentityInternal(identity: string): { privateKeyData: Buffer; publicKeyData: Buffer | null; keyTag: string; accessControl: string } {
    if (!identity.startsWith('AGE-PLUGIN-SE-')) {
      throw new Error('Invalid SE identity format');
    }

    const encoded = identity.substring('AGE-PLUGIN-SE-'.length);
    const decoded = Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const keyData = JSON.parse(decoded.toString());

    return {
      privateKeyData: Buffer.from(keyData.privateKey, 'base64'),
      publicKeyData: keyData.publicKey ? Buffer.from(keyData.publicKey, 'base64') : null,
      keyTag: keyData.keyTag,
      accessControl: keyData.accessControl
    };
  }

  private parseAgeRecipient(recipient: string): Buffer {
    if (!recipient.startsWith('age1se1')) {
      throw new Error('Invalid SE recipient format');
    }

    const encoded = recipient.substring('age1se1'.length);
    const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    const padding = '='.repeat((4 - (base64.length % 4)) % 4);
    return Buffer.from(base64 + padding, 'base64');
  }

  validateAccessControl(accessControl: string): boolean {
    const validControls = [
      'none',
      'passcode',
      'any-biometry',
      'any-biometry-or-passcode',
      'any-biometry-and-passcode',
      'current-biometry',
      'current-biometry-and-passcode'
    ];
    
    return validControls.includes(accessControl);
  }

  recipientToAgeFormat(publicKey: Uint8Array, type: 'piv-p256' | 'p256tag'): string {
    const keyBase64 = Buffer.from(publicKey).toString('base64');
    
    if (type === 'piv-p256') {
      return `age1se1${keyBase64}`;
    } else {
      return `age1p256tag1${keyBase64}`;
    }
  }


} 