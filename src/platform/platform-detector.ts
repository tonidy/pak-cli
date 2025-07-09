/**
 * Platform Detection for Cross-Platform Support
 */

import * as os from 'os';
import * as fs from 'fs';
import { OSType } from '../types';

export class PlatformDetector {
  private cachedOS?: OSType;

  /**
   * Detect the current operating system
   */
  detectOS(): OSType {
    if (this.cachedOS) {
      return this.cachedOS;
    }

    const platform = os.platform();
    
    switch (platform) {
      case 'darwin':
        this.cachedOS = 'macos';
        break;
      case 'linux':
        // Check if we're running under WSL
        if (this.isWSL()) {
          this.cachedOS = 'wsl';
        } else {
          this.cachedOS = 'linux';
        }
        break;
      case 'win32':
        this.cachedOS = 'windows';
        break;
      default:
        this.cachedOS = 'unknown';
    }

    return this.cachedOS;
  }

  /**
   * Check if running under Windows Subsystem for Linux
   */
  private isWSL(): boolean {
    try {
      // Check for WSL indicator in /proc/version
      if (fs.existsSync('/proc/version')) {
        const version = fs.readFileSync('/proc/version', 'utf8');
        return version.toLowerCase().includes('microsoft');
      }
    } catch {
      // Ignore errors
    }
    return false;
  }

  /**
   * Check if the current platform supports a specific feature
   */
  supportsFeature(feature: string): boolean {
    const osType = this.detectOS();
    
    switch (feature) {
      case 'keychain':
        return osType === 'macos';
      case 'libsecret':
        return osType === 'linux';
      case 'credential-manager':
        return osType === 'windows' || osType === 'wsl';
      case 'secure-enclave':
        return osType === 'macos';
      case 'dev-shm':
        return osType === 'linux';
      default:
        return false;
    }
  }

  /**
   * Get the appropriate temporary directory for the current platform
   */
  getTempDirectory(): string {
    const osType = this.detectOS();
    
    switch (osType) {
      case 'windows':
      case 'wsl':
        return process.env.TEMP || process.env.TMP || '/tmp';
      case 'linux':
        // Prefer /dev/shm (in-memory) on Linux if available
        if (fs.existsSync('/dev/shm') && fs.statSync('/dev/shm').isDirectory()) {
          return '/dev/shm';
        }
        return '/tmp';
      case 'macos':
      default:
        return '/tmp';
    }
  }

  /**
   * Get platform-specific command variants
   */
  getCommandVariant(command: string): string {
    const osType = this.detectOS();
    
    switch (command) {
      case 'powershell':
        return osType === 'wsl' ? 'powershell.exe' : 'powershell';
      case 'cmdkey':
        return osType === 'wsl' ? 'cmdkey.exe' : 'cmdkey';
      default:
        return command;
    }
  }
} 