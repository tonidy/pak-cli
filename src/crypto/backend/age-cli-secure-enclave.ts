/**
 * CLI-based Secure Enclave Implementation
 * Uses age-plugin-se binary for Secure Enclave operations
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

export class CLISecureEnclave implements AppleSecureEnclaveAPI {
  private pluginPath: string;
  private config: SecureEnclaveConfig;

  constructor(config: SecureEnclaveConfig, pluginPath: string) {
    this.config = config;
    this.pluginPath = pluginPath;
  }

  async isAvailable(): Promise<boolean> {
    try {
      if (process.platform !== 'darwin') {
        return false;
      }

      if (!this.pluginPath) {
        return false;
      }

      const result = await this.runCommand([this.pluginPath, '--version']);
      return result.success;
    } catch (error) {
      return false;
    }
  }

  async getCapabilities(): Promise<SecureEnclaveCapabilities> {
    const isAvailable = await this.isAvailable();
    
    if (!isAvailable) {
      return {
        isAvailable: false,
        supportsKeyGeneration: false,
        supportsEncryption: false,
        supportsDecryption: false,
        supportedAccessControls: [],
        platform: process.platform,
      };
    }

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
      version: await this.getPluginVersion(),
    };
  }

  async generateKeyPair(accessControl: string): Promise<SecureEnclaveKeyPair> {
    if (!this.validateAccessControl(accessControl)) {
      throw new Error(`Invalid access control: ${accessControl}`);
    }

    const tempFile = path.join(process.cwd(), `.age-se-${Date.now()}.key`);
    
    try {
      const result = await this.runCommand([
        this.pluginPath,
        'keygen',
        '--access-control',
        accessControl,
        '--output',
        tempFile
      ]);

      if (!result.success) {
        throw new Error(`Failed to generate SE key: ${result.stderr}`);
      }

      const keyContent = fs.readFileSync(tempFile, 'utf8');
      const recipient = this.extractRecipientFromOutput(result.stdout);
      
      const lines = keyContent.split('\n').filter(line => line.trim() && !line.startsWith('#'));
      const identity = lines[0];

      this.parseAgeIdentity(identity);
      
      const keyPair: SecureEnclaveKeyPair = {
        identity,
        recipient,
        publicKey: await this.getPublicKeyFromIdentity(identity),
        privateKeyRef: this.getPrivateKeyReference(identity),
        accessControl,
        createdAt: new Date()
      };

      return keyPair;
    } finally {
      try {
        fs.unlinkSync(tempFile);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  }

  async loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair> {
    try {
      const { accessControl } = this.parseAgeIdentity(identity);
      const recipient = await this.identityToRecipient(identity);
      
      return {
        identity,
        recipient,
        publicKey: await this.getPublicKeyFromIdentity(identity),
        privateKeyRef: this.getPrivateKeyReference(identity),
        accessControl,
        createdAt: new Date()
      };
    } catch (error) {
      throw new Error(`Failed to load key pair: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async deleteKeyPair(_identity: string): Promise<boolean> {
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
      fs.writeFileSync(tempFile, privateKeyRef);
      
      const result = await this.runCommandWithInput(
        ['age', '--decrypt', '--identity', tempFile],
        ciphertext
      );

      if (!result.success) {
        throw new Error(`SE decryption failed: ${result.stderr}`);
      }

      return result.stdout;
    } finally {
      try {
        fs.unlinkSync(tempFile);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  }

  async identityToRecipient(identity: string): Promise<string> {
    const tempFile = path.join(process.cwd(), `.age-se-identity-${Date.now()}.key`);
    
    try {
      fs.writeFileSync(tempFile, identity);
      
      const result = await this.runCommand([
        this.pluginPath,
        'recipients',
        '--input',
        tempFile
      ]);

      if (!result.success) {
        throw new Error(`Failed to convert identity to recipient: ${result.stderr}`);
      }

      return result.stdout.trim();
    } finally {
      try {
        fs.unlinkSync(tempFile);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
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

  recipientToAgeFormat(publicKey: Uint8Array, type: 'piv-p256' | 'p256tag'): string {
    const keyBase64 = Buffer.from(publicKey).toString('base64');
    
    if (type === 'piv-p256') {
      return `age1se1${keyBase64}`;
    } else {
      return `age1p256tag1${keyBase64}`;
    }
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
    const match = output.match(/Public key:\s*(age1se1\w+)/);
    if (match) {
      return match[1];
    }
    
    const fallbackMatch = output.match(/age1se1\w+/);
    if (fallbackMatch) {
      return fallbackMatch[0];
    }
    
    throw new Error('Could not extract recipient from output');
  }

  private async getPublicKeyFromIdentity(identity: string): Promise<Uint8Array> {
    const { data } = this.parseAgeIdentity(identity);
    return data.slice(0, 33);
  }

  private getPrivateKeyReference(identity: string): string {
    return identity;
  }

  private async runCommand(args: string[]): Promise<{ success: boolean; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const proc = spawn(args[0], args.slice(1), { stdio: 'pipe' });
      
      let stdout = '';
      let stderr = '';
      
      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      proc.on('close', (code) => {
        resolve({
          success: code === 0,
          stdout,
          stderr
        });
      });
    });
  }

  private async runCommandWithInput(args: string[], input: Uint8Array): Promise<{ success: boolean; stdout: Buffer; stderr: string }> {
    return new Promise((resolve) => {
      const proc = spawn(args[0], args.slice(1), { stdio: 'pipe' });
      
      const stdoutChunks: Buffer[] = [];
      let stderr = '';
      
      proc.stdout.on('data', (data) => {
        stdoutChunks.push(data);
      });
      
      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      proc.on('close', (code) => {
        resolve({
          success: code === 0,
          stdout: Buffer.concat(stdoutChunks),
          stderr
        });
      });
      
      proc.stdin.write(input);
      proc.stdin.end();
    });
  }
} 