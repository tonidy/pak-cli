/**
 * CLI-based Secure Enclave Implementation (Standardized)
 * 
 * This implementation uses the age-plugin-se binary for all cryptographic
 * operations. It has been updated to use the central `format-utils` for
 * any necessary format parsing to ensure consistency with other backends.
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { 
  AppleSecureEnclaveAPI, 
  SecureEnclaveKeyPair, 
  SecureEnclaveCapabilities,
  SecureEnclaveConfig 
} from '../../types';
import { decodeRecipient, decodeIdentity } from '../format-utils';

export class CLISecureEnclave implements AppleSecureEnclaveAPI {
  private pluginPath: string;
  private config: SecureEnclaveConfig;

  constructor(config: SecureEnclaveConfig, pluginPath: string) {
    this.config = config;
    this.pluginPath = pluginPath;
  }

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin' || !this.pluginPath) {
      return false;
    }
    try {
      const result = await this.runCommand([this.pluginPath, '--version']);
      return result.success;
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
      version: isAvailable ? await this.getPluginVersion() : 'unavailable',
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    if (!this.validateAccessControl(accessControl)) {
      throw new Error(`Invalid access control: ${accessControl}`);
    }

    const tempFile = path.join(process.cwd(), `.age-se-${Date.now()}.key`);
    
    try {
      const result = await this.runCommand([
        this.pluginPath, 'keygen', '--access-control', accessControl, '--output', tempFile
      ]);

      if (!result.success) {
        throw new Error(`Failed to generate SE key: ${result.stderr}`);
      }

      const keyContent = fs.readFileSync(tempFile, 'utf8');
      const recipient = this.extractRecipientFromOutput(result.stdout);
      const identity = keyContent.split('\n').find(line => line.startsWith('AGE-PLUGIN-SE-')) || '';

      if (!identity) {
        throw new Error('Could not find identity in keygen output.');
      }

      const publicKey = decodeRecipient(recipient);

      return {
        identity,
        recipient,
        publicKey,
        privateKeyRef: identity, // For CLI, the identity is the private key reference
        accessControl,
        createdAt: new Date()
      };
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    const recipient = await this.identityToRecipient(identity);
    const publicKey = decodeRecipient(recipient);

    return {
      identity,
      recipient,
      publicKey,
      privateKeyRef: identity,
      accessControl: this.config.accessControl, // Not stored in key
      createdAt: new Date() // Not stored in key
    };
  }

  async deleteKeyPair(_identity: string): Promise<boolean> {
    // The CLI plugin does not support key deletion. Keys are file-based.
    return true;
  }

  async encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array> {
    const result = await this.runCommandWithInput(
      ['age', '--encrypt', '--recipient', recipient],
      data
    );

    if (!result.success) {
      throw new Error(`SE encryption failed: ${result.stderr}`);
    }

    return result.stdout;
  }

  async decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array> {
    const tempFile = path.join(process.cwd(), `.age-se-identity-${Date.now()}.key`);
    
    try {
      // Write a properly formatted identity file
      // The age CLI expects just the identity string without extra comments for plugin identities
      fs.writeFileSync(tempFile, privateKeyRef + '\n');
      
      const result = await this.runCommandWithInput(
        ['age', '--decrypt', '--identity', tempFile],
        ciphertext
      );

      if (!result.success) {
        throw new Error(`SE decryption failed: ${result.stderr}`);
      }

      return result.stdout;
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  }

  async identityToRecipient(identity: string): Promise<string> {
    const tempFile = path.join(process.cwd(), `.age-se-identity-${Date.now()}.key`);
    
    try {
      // Write a properly formatted identity file
      // The age CLI expects just the identity string without extra comments for plugin identities
      fs.writeFileSync(tempFile, identity + '\n');
      
      const result = await this.runCommand([
        this.pluginPath, 'recipients', '--input', tempFile
      ]);

      if (!result.success) {
        throw new Error(`Failed to convert identity to recipient: ${result.stderr}`);
      }

      return result.stdout.trim();
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  }

  validateAccessControl(accessControl: string): boolean {
    const validControls = [
      'none', 'passcode', 'any-biometry', 'any-biometry-or-passcode',
      'any-biometry-and-passcode', 'current-biometry', 'current-biometry-and-passcode'
    ];
    return validControls.includes(accessControl);
  }

  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string } {
    const data = decodeIdentity(identity);
    return {
      data,
      accessControl: this.config.accessControl
    };
  }

  recipientToAgeFormat(publicKey: Uint8Array): string {
    // The CLI backend doesn't use this directly, but we implement it for API consistency.
    // It will format a given public key into the standard recipient format.
    const { encodeRecipient, compressPublicKey } = require('../format-utils');
    return encodeRecipient(compressPublicKey(publicKey));
  }

  private async getPluginVersion(): Promise<string> {
    try {
      const result = await this.runCommand([this.pluginPath, '--version']);
      if (result.success) {
        const match = result.stdout.match(/v?(\d+\.\d+\.\d+)/);
        return match ? match[1] : 'unknown';
      }
    } catch (error) {
      // Ignore errors
    }
    return 'unknown';
  }

  private extractRecipientFromOutput(output: string): string {
    // Match age1se prefix (without the trailing 1)
    const match = output.match(/age1se[a-z0-9]+/);
    if (match) {
      return match[0];
    }
    throw new Error('Could not extract recipient from keygen output');
  }

  private async runCommand(args: string[]): Promise<{ success: boolean; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const proc = spawn(args[0], args.slice(1), { stdio: 'pipe' });
      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (data) => { stdout += data.toString(); });
      proc.stderr.on('data', (data) => { stderr += data.toString(); });
      proc.on('close', (code) => {
        resolve({ success: code === 0, stdout, stderr });
      });
    });
  }

  private async runCommandWithInput(args: string[], input: Uint8Array): Promise<{ success: boolean; stdout: Buffer; stderr: string }> {
    return new Promise((resolve) => {
      const proc = spawn(args[0], args.slice(1), { stdio: 'pipe' });
      const stdoutChunks: Buffer[] = [];
      let stderr = '';
      proc.stdout.on('data', (data) => { stdoutChunks.push(data); });
      proc.stderr.on('data', (data) => { stderr += data.toString(); });
      proc.on('close', (code) => {
        resolve({ success: code === 0, stdout: Buffer.concat(stdoutChunks), stderr });
      });
      proc.stdin.write(input);
      proc.stdin.end();
    });
  }
}