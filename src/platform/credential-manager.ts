/**
 * Cross-Platform Credential Management
 */

import { CredentialService } from '../types';
import { PlatformDetector } from './platform-detector';

export class CredentialManager implements CredentialService {
  constructor(private platformDetector: PlatformDetector) {}

  /**
   * Store a credential in the platform-specific credential store
   */
  async store(service: string, username: string, password: string): Promise<boolean> {
    const osType = this.platformDetector.detectOS();
    
    switch (osType) {
      case 'windows':
      case 'wsl':
        return this.storeWindows(service, username, password);
      case 'linux':
        return this.storeLinux(service, username, password);
      case 'macos':
        return this.storeMacOS(service, username, password);
      default:
        return false;
    }
  }

  /**
   * Retrieve a credential from the platform-specific credential store
   */
  async retrieve(service: string, username: string): Promise<string | null> {
    const osType = this.platformDetector.detectOS();
    
    switch (osType) {
      case 'windows':
      case 'wsl':
        return this.retrieveWindows(service, username);
      case 'linux':
        return this.retrieveLinux(service, username);
      case 'macos':
        return this.retrieveMacOS(service, username);
      default:
        return null;
    }
  }

  /**
   * Remove a credential from the platform-specific credential store
   */
  async remove(service: string, username: string): Promise<boolean> {
    const osType = this.platformDetector.detectOS();
    
    switch (osType) {
      case 'windows':
      case 'wsl':
        return this.removeWindows(service, username);
      case 'linux':
        return this.removeLinux(service, username);
      case 'macos':
        return this.removeMacOS(service, username);
      default:
        return false;
    }
  }

  /**
   * Check if credential storage is available on the current platform
   */
  async isAvailable(): Promise<boolean> {
    const osType = this.platformDetector.detectOS();
    
    switch (osType) {
      case 'windows':
      case 'wsl':
        return this.isWindowsAvailable();
      case 'linux':
        return this.isLinuxAvailable();
      case 'macos':
        return this.isMacOSAvailable();
      default:
        return false;
    }
  }

  // Windows credential management
  private async storeWindows(service: string, username: string, password: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    const powershell = this.platformDetector.getCommandVariant('powershell');
    
    try {
      // Try PowerShell first
      const psScript = `
        $securePassword = ConvertTo-SecureString -String "${password}" -AsPlainText -Force;
        $credential = New-Object System.Management.Automation.PSCredential("${username}", $securePassword);
        [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null;
        $vault = New-Object Windows.Security.Credentials.PasswordVault;
        try { $vault.Remove($vault.Retrieve("${service}", "${username}")) } catch {};
        $vault.Add((New-Object Windows.Security.Credentials.PasswordCredential("${service}", "${username}", "${password}")))
      `;
      
      const ps = spawn(powershell, ['-Command', psScript], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        ps.on('close', (code) => {
          if (code === 0) {
            resolve(true);
          } else {
            // Fallback to cmdkey
            resolve(this.storeCmdkey(service, username, password));
          }
        });
      });
    } catch {
      // Fallback to cmdkey
      return this.storeCmdkey(service, username, password);
    }
  }

  private async storeCmdkey(service: string, username: string, password: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    const cmdkey = this.platformDetector.getCommandVariant('cmdkey');
    
    try {
      const cmd = spawn(cmdkey, ['/generic:' + service, '/user:' + username, '/pass:' + password], {
        stdio: 'pipe'
      });
      
      return new Promise((resolve) => {
        cmd.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  private async retrieveWindows(service: string, username: string): Promise<string | null> {
    const { spawn } = await import('child_process');
    const powershell = this.platformDetector.getCommandVariant('powershell');
    
    try {
      const psScript = `
        [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null;
        $vault = New-Object Windows.Security.Credentials.PasswordVault;
        try {
          $credential = $vault.Retrieve("${service}", "${username}");
          $credential.RetrievePassword();
          Write-Output $credential.Password
        } catch { exit 1 }
      `;
      
      const ps = spawn(powershell, ['-Command', psScript], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        let output = '';
        ps.stdout.on('data', (data) => {
          output += data.toString();
        });
        
        ps.on('close', (code) => {
          if (code === 0) {
            resolve(output.trim());
          } else {
            resolve(null);
          }
        });
      });
    } catch {
      return null;
    }
  }

  private async removeWindows(service: string, _username: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    const cmdkey = this.platformDetector.getCommandVariant('cmdkey');
    
    try {
      const cmd = spawn(cmdkey, ['/delete:' + service], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        cmd.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  private async isWindowsAvailable(): Promise<boolean> {
    const { spawn } = await import('child_process');
    const powershell = this.platformDetector.getCommandVariant('powershell');
    
    try {
      const ps = spawn(powershell, ['-Command', 'Get-Command cmdkey'], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        ps.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  // Linux credential management using secret-tool
  private async storeLinux(service: string, username: string, password: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    
    try {
      const secretTool = spawn('secret-tool', [
        'store',
        '--label', `pa: ${service}`,
        'service', service,
        'username', username
      ], { stdio: 'pipe' });
      
      secretTool.stdin.write(password);
      secretTool.stdin.end();
      
      return new Promise((resolve) => {
        secretTool.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  private async retrieveLinux(service: string, username: string): Promise<string | null> {
    const { spawn } = await import('child_process');
    
    try {
      const secretTool = spawn('secret-tool', [
        'lookup',
        'service', service,
        'username', username
      ], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        let output = '';
        secretTool.stdout.on('data', (data) => {
          output += data.toString();
        });
        
        secretTool.on('close', (code) => {
          if (code === 0) {
            resolve(output.trim());
          } else {
            resolve(null);
          }
        });
      });
    } catch {
      return null;
    }
  }

  private async removeLinux(service: string, username: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    
    try {
      const secretTool = spawn('secret-tool', [
        'clear',
        'service', service,
        'username', username
      ], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        secretTool.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  private async isLinuxAvailable(): Promise<boolean> {
    const { spawn } = await import('child_process');
    
    try {
      const which = spawn('which', ['secret-tool'], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        which.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  // macOS credential management using Keychain
  private async storeMacOS(service: string, username: string, password: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    
    try {
      // Delete existing entry first
      await this.removeMacOS(service, username);
      
      // Add new entry
      const security = spawn('security', [
        'add-generic-password',
        '-s', service,
        '-a', username,
        '-w', password
      ], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        security.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }

  private async retrieveMacOS(service: string, username: string): Promise<string | null> {
    const { spawn } = await import('child_process');
    
    try {
      const security = spawn('security', [
        'find-generic-password',
        '-s', service,
        '-a', username,
        '-w'
      ], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        let output = '';
        security.stdout.on('data', (data) => {
          output += data.toString();
        });
        
        security.on('close', (code) => {
          if (code === 0) {
            resolve(output.trim());
          } else {
            resolve(null);
          }
        });
      });
    } catch {
      return null;
    }
  }

  private async removeMacOS(service: string, username: string): Promise<boolean> {
    const { spawn } = await import('child_process');
    
    try {
      const security = spawn('security', [
        'delete-generic-password',
        '-s', service,
        '-a', username
      ], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        security.on('close', () => resolve(true)); // Always return true, even if not found
      });
    } catch {
      return false;
    }
  }

  private async isMacOSAvailable(): Promise<boolean> {
    const { spawn } = await import('child_process');
    
    try {
      const which = spawn('which', ['security'], { stdio: 'pipe' });
      
      return new Promise((resolve) => {
        which.on('close', (code) => resolve(code === 0));
      });
    } catch {
      return false;
    }
  }
} 