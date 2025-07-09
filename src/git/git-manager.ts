/**
 * Git Repository Manager
 */

import { GitRepository } from '../types';

export class GitManager implements GitRepository {
  constructor(private workingDirectory: string) {}

  /**
   * Check if the directory is a git repository
   */
  async isInitialized(): Promise<boolean> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    try {
      const gitDir = path.join(this.workingDirectory, '.git');
      const stat = await fs.stat(gitDir);
      return stat.isDirectory();
    } catch {
      return false;
    }
  }

  /**
   * Initialize a new git repository
   */
  async init(): Promise<void> {
    try {
      await this.runGitCommand(['init', '-q']);
      
      // Set default user config if not set globally
      try {
        await this.runGitCommand(['config', 'user.name']);
      } catch {
        await this.runGitCommand(['config', 'user.name', 'pa']);
      }
      
      try {
        await this.runGitCommand(['config', 'user.email']);
      } catch {
        await this.runGitCommand(['config', 'user.email', '']);
      }
    } catch (error) {
      throw new Error(`Failed to initialize git repository: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Add a file to the git index
   */
  async add(file: string): Promise<void> {
    try {
      await this.runGitCommand(['add', file]);
    } catch (error) {
      throw new Error(`Failed to git add ${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Commit changes with a message
   */
  async commit(message: string): Promise<void> {
    try {
      await this.runGitCommand(['commit', '-qm', message]);
    } catch (error) {
      throw new Error(`Failed to git commit: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Add a file and commit in one operation
   */
  async addAndCommit(file: string, message: string): Promise<void> {
    await this.add(file);
    await this.commit(message);
  }

  /**
   * Run a git command in the working directory
   */
  private async runGitCommand(args: string[]): Promise<string> {
    const { spawn } = await import('child_process');
    
    return new Promise((resolve, reject) => {
      const git = spawn('git', args, {
        cwd: this.workingDirectory,
        stdio: 'pipe'
      });
      
      let stdout = '';
      let stderr = '';
      
      git.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      git.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      git.on('close', (code) => {
        if (code === 0) {
          resolve(stdout.trim());
        } else {
          reject(new Error(`Git command failed with code ${code}: ${stderr}`));
        }
      });
      
      git.on('error', (error) => {
        reject(error);
      });
    });
  }
} 