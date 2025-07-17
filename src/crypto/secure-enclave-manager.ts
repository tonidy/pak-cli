/**
 * Secure Enclave Manager
 *
 * This manager now standardizes on the CLI backend for core cryptographic
 * operations to ensure 100% interoperability with the age ecosystem.
 *
 * On macOS, it uses the native Swift addon as a "helper" to accelerate
 * specific operations like identity-to-recipient conversion.
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
import { CLISecureEnclave } from './backend/age-cli-secure-enclave';
import { log } from '../utils/logger';

// 'js' backend is deprecated for interoperability reasons.
export type SecureEnclaveBackend = 'native' | 'cli' | 'auto';

export interface ExtendedSecureEnclaveConfig extends SecureEnclaveConfig {
  backend?: SecureEnclaveBackend;
  preferNative?: boolean;
  useAgeBinary?: boolean; // This will be implicitly true now
}

export class SecureEnclaveManager implements AppleSecureEnclaveAPI {
  private pluginPath: string;
  private config: ExtendedSecureEnclaveConfig;

  // The CLI backend is the primary engine for all crypto operations.
  private cliBackend!: CLISecureEnclave;
  // The native addon is used as a helper for performance optimizations.
  private nativeHelper: NativeSecureEnclave | null = null;

  constructor(config: ExtendedSecureEnclaveConfig = {
    accessControl: 'any-biometry-or-passcode',
    recipientType: 'piv-p256',
    useNative: true, // preferNative is a better name
    backend: 'auto',
    preferNative: true,
  }) {
    this.config = config;
    this.pluginPath = this.findAgePluginSe();
    this.initializeBackends();
  }

  private initializeBackends(): void {
    // The CLI backend is now the single source of truth for crypto operations.
    this.cliBackend = new CLISecureEnclave(this.config, this.pluginPath);

    // On macOS, initialize the native addon as a helper if possible.
    if (process.platform === 'darwin' && this.config.preferNative) {
      try {
        this.nativeHelper = new NativeSecureEnclave(this.config);
      } catch (error) {
        log.warn('Could not initialize native Secure Enclave helper:', error instanceof Error ? error.message : String(error));
        this.nativeHelper = null;
      }
    }
  }

  async isAvailable(): Promise<boolean> {
    // Availability is determined by the primary CLI backend.
    return this.cliBackend.isAvailable();
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    const capabilities = await this.cliBackend.getCapabilities();
    const helperStatus = this.nativeHelper ? `native-helper (${await this.nativeHelper.isAvailable() ? 'active' : 'inactive'})` : 'no-native-helper';
    return {
      ...capabilities,
      version: `${capabilities.version} (${helperStatus})`,
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    // Key generation is always delegated to the CLI backend.
    return this.cliBackend.generateKeyPair(accessControl);
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    return this.cliBackend.loadKeyPair(identity);
  }

  async deleteKeyPair(identity: string): Promise<boolean> {
    return this.cliBackend.deleteKeyPair(identity);
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    // Encryption is always delegated to the CLI backend.
    return this.cliBackend.encrypt(data, recipient);
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    // Decryption is always delegated to the CLI backend.
    return this.cliBackend.decrypt(ciphertext, privateKeyRef);
  }

  async identityToRecipient(identity: string): Promise<string> {
    // Use the native helper for performance if available, otherwise fall back to CLI.
    if (this.nativeHelper && await this.nativeHelper.isAvailable()) {
      try {
        log.trace('[SE Manager] Using native helper for identityToRecipient');
        return await this.nativeHelper.identityToRecipient(identity);
      } catch (error) {
        log.warn('Native helper failed for identityToRecipient, falling back to CLI:', error instanceof Error ? error.message : String(error));
      }
    }
    log.trace('[SE Manager] Using CLI backend for identityToRecipient');
    return this.cliBackend.identityToRecipient(identity);
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

  recipientToAgeFormat(publicKey: Uint8Array): string {
    // This is now a simple wrapper around the CLI backend's implementation.
    return this.cliBackend.recipientToAgeFormat(publicKey);
  }

  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string } {
    // This is now a simple wrapper around the CLI backend's implementation.
    return this.cliBackend.parseAgeIdentity(identity);
  }

  getCurrentBackend(): SecureEnclaveBackend {
    // The concept of multiple backends is removed. We now have a primary and a helper.
    return this.nativeHelper ? 'native' : 'cli';
  }

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