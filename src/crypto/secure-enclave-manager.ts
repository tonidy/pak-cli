/**
 * Secure Enclave Manager
 * Orchestrates multiple Secure Enclave backends: native, pure JS, and CLI
 */

import * as fs from 'fs';
import * as path from 'path';
import { 
  AppleSecureEnclaveAPI, 
  SecureEnclaveKeyPair, 
  SecureEnclaveCapabilities,
  SecureEnclaveConfig 
} from '../types';
import { NativeSecureEnclave } from './backend/native-secure-enclave';
import { PureJSSecureEnclave } from './backend/pure-js-secure-enclave';
import { CLISecureEnclave } from './backend/age-cli-secure-enclave';

export type SecureEnclaveBackend = 'native' | 'pure-js' | 'cli' | 'auto';

export interface ExtendedSecureEnclaveConfig extends SecureEnclaveConfig {
  backend?: SecureEnclaveBackend;
  preferNative?: boolean;
  fallbackToCli?: boolean;
}

export class SecureEnclaveManager implements AppleSecureEnclaveAPI {
  private pluginPath: string;
  private config: ExtendedSecureEnclaveConfig;
  private backend: AppleSecureEnclaveAPI | null = null;
  private backendType: SecureEnclaveBackend = 'auto';

  constructor(config: ExtendedSecureEnclaveConfig = {
    accessControl: 'any-biometry-or-passcode',
    recipientType: 'piv-p256',
    useNative: true,
    backend: 'auto',
    preferNative: true,
    fallbackToCli: true
  }) {
    this.config = config;
    this.pluginPath = this.findAgePluginSe();
    this.initializeBackend();
  }

  private async initializeBackend(): Promise<void> {
    const requestedBackend = this.config.backend || 'auto';

    if (requestedBackend === 'auto') {
      // Auto-select best available backend
      if (this.config.preferNative && process.platform === 'darwin') {
        try {
          this.backend = new NativeSecureEnclave(this.config);
          if (await this.backend.isAvailable()) {
            this.backendType = 'native';
            return;
          }
        } catch (error) {
          console.warn('Native SE backend not available:', error instanceof Error ? error.message : String(error));
        }
      }

      // Try pure JS backend
      try {
        this.backend = new PureJSSecureEnclave(this.config);
        if (this.backend && await this.backend.isAvailable()) {
          this.backendType = 'pure-js';
          return;
        }
      } catch (error) {
        console.warn('Pure JS SE backend not available:', error instanceof Error ? error.message : String(error));
      }

      // Fall back to CLI
      if (this.config.fallbackToCli) {
        this.backend = new CLISecureEnclave(this.config, this.pluginPath);
        this.backendType = 'cli';
        return;
      }

      throw new Error('No Secure Enclave backend available');
    } else {
      // Use specific backend
      switch (requestedBackend) {
        case 'native':
          this.backend = new NativeSecureEnclave(this.config);
          break;
        case 'pure-js':
          this.backend = new PureJSSecureEnclave(this.config);
          break;
        case 'cli':
          this.backend = new CLISecureEnclave(this.config, this.pluginPath);
          break;
        default:
          throw new Error(`Unknown backend: ${requestedBackend}`);
      }
      this.backendType = requestedBackend;
    }
  }

  async isAvailable(): Promise<boolean> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.isAvailable();
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    const capabilities = await this.backend!.getCapabilities();
    return {
      ...capabilities,
      version: capabilities.version + ` (${this.backendType})`,
    };
  }

  async generateKeyPair(accessControl: string, format?: 'json' | 'bech32'): Promise<SecureEnclaveKeyPair> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.generateKeyPair(accessControl, format);
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.loadKeyPair(identity);
  }

  async deleteKeyPair(identity: string): Promise<boolean> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.deleteKeyPair(identity);
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.encrypt(data, recipient);
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.decrypt(ciphertext, privateKeyRef);
  }

  async identityToRecipient(identity: string): Promise<string> {
    if (!this.backend) {
      await this.initializeBackend();
    }
    return this.backend!.identityToRecipient(identity);
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

  /**
   * Get current backend type
   */
  getCurrentBackend(): SecureEnclaveBackend {
    return this.backendType;
  }

  /**
   * Switch to a different backend
   */
  async switchBackend(backend: SecureEnclaveBackend): Promise<void> {
    this.config.backend = backend;
    this.backend = null;
    await this.initializeBackend();
  }

  /**
   * Find age-plugin-se binary
   */
  private findAgePluginSe(): string {
    const possiblePaths = [
      'age-plugin-se',
      '/usr/local/bin/age-plugin-se',
      '/opt/homebrew/bin/age-plugin-se',
      path.join(process.env.HOME || '', '.local/bin/age-plugin-se')
    ];

    for (const pluginPath of possiblePaths) {
      try {
        fs.accessSync(pluginPath, fs.constants.X_OK);
        return pluginPath;
      } catch (error) {
        continue;
      }
    }

    return '';
  }
}

// Export the main class with the original name for backward compatibility
export const AppleSecureEnclave = SecureEnclaveManager; 