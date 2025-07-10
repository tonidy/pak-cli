/**
 * Native Apple Secure Enclave Implementation
 * Uses Swift-based native Node.js addon for direct Security Framework access
 */

import * as path from 'path';
import { SecureEnclaveKeyPair, SecureEnclaveCapabilities, SecureEnclaveConfig, AppleSecureEnclaveAPI } from '../../types';

// Load the native addon
let nativeAddon: any;

try {
  // Try to load the native addon from the native directory
  const nativeModulePath = path.join(__dirname, '../../../native');
  nativeAddon = require(nativeModulePath);
} catch (error) {
  console.warn('Failed to load native Secure Enclave addon:', error instanceof Error ? error.message : String(error));
  nativeAddon = null;
}

export class NativeSecureEnclave implements AppleSecureEnclaveAPI {
  private config: SecureEnclaveConfig;

  constructor(config: SecureEnclaveConfig) {
    this.config = config;
    
    if (!nativeAddon) {
      throw new Error('Native Secure Enclave addon not available. Please build the native module first.');
    }
  }

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin') {
      return false;
    }
    
    if (!nativeAddon) {
      return false;
    }
    
    try {
      return nativeAddon.isAvailable();
    } catch (error) {
      return false;
    }
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    return {
      isAvailable: await this.isAvailable(),
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
      version: 'native-1.0.0',
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    const result = await nativeAddon.generateKeyPair(accessControl);
    
    // Convert to age format
    const recipient = this.publicKeyToAgeRecipient(result.publicKey);
    const identity = this.privateKeyToAgeIdentity(result.privateKey);
    
    return {
      identity,
      recipient,
      publicKey: result.publicKey,
      privateKeyRef: result.privateKey.toString('base64'), // Use base64 as reference
      accessControl,
      createdAt: new Date()
    };
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    const { data, accessControl } = this.parseAgeIdentity(identity);
    
    // In a real implementation, this would load the key from the Secure Enclave
    // For now, we'll reconstruct what we can
    return {
      identity,
      recipient: this.publicKeyToAgeRecipient(Buffer.from(data)),
      publicKey: data,
      privateKeyRef: identity, // Use identity as reference
      accessControl,
      createdAt: new Date()
    };
  }

  async deleteKeyPair(_identity: string): Promise<boolean> {
    // In a real implementation, this would delete the key from the Secure Enclave
    // For now, return true indicating success
    return true;
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    const publicKeyData = this.parseAgeRecipient(recipient);
    const result = await nativeAddon.encrypt(Buffer.from(data), publicKeyData);
    return new Uint8Array(result);
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    // privateKeyRef contains the base64-encoded private key data
    const privateKeyData = Buffer.from(privateKeyRef, 'base64');
    const result = await nativeAddon.decrypt(Buffer.from(ciphertext), privateKeyData);
    return new Uint8Array(result);
  }

  async identityToRecipient(identity: string): Promise<string> {
    const { data } = this.parseAgeIdentity(identity);
    return this.publicKeyToAgeRecipient(Buffer.from(data));
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

  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string } {
    if (!identity.startsWith('AGE-PLUGIN-SE-')) {
      throw new Error('Invalid SE identity format');
    }

    const base64Data = identity.substring('AGE-PLUGIN-SE-'.length);
    const data = Buffer.from(base64Data, 'base64');
    
    return {
      data,
      accessControl: this.config.accessControl
    };
  }

  private publicKeyToAgeRecipient(publicKey: Buffer): string {
    // Convert P256 public key to age1se1... format
    // This requires implementing the age recipient encoding
    const encoded = publicKey.toString('base64');
    return `age1se1${encoded}`;
  }

  private privateKeyToAgeIdentity(privateKey: Buffer): string {
    // Convert private key to AGE-PLUGIN-SE-... format
    const encoded = privateKey.toString('base64');
    return `AGE-PLUGIN-SE-${encoded}`;
  }

  private parseAgeRecipient(recipient: string): Buffer {
    if (!recipient.startsWith('age1se1')) {
      throw new Error('Invalid SE recipient format');
    }

    const encoded = recipient.substring('age1se1'.length);
    return Buffer.from(encoded, 'base64');
  }
}

// Example native module interface (would be implemented in C++/Objective-C)
/*
// secure-enclave.cc
#include <node.h>
#include <Security/Security.h>
#include <LocalAuthentication/LocalAuthentication.h>

namespace SecureEnclaveModule {
  
  void IsAvailable(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    // Check if Secure Enclave is available
    Boolean available = false;
    OSStatus status = SecItemCopyMatching(nullptr, nullptr);
    
    args.GetReturnValue().Set(v8::Boolean::New(isolate, available));
  }
  
  void GenerateKeyPair(const v8::FunctionCallbackInfo<v8::Value>& args) {
    // Implementation would use SecKeyCreateWithData and SecureEnclave APIs
  }
  
  void Initialize(v8::Local<v8::Object> exports) {
    NODE_SET_METHOD(exports, "isAvailable", IsAvailable);
    NODE_SET_METHOD(exports, "generateKeyPair", GenerateKeyPair);
  }
  
  NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
}
*/ 