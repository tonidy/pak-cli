/**
 * File System Manager
 */

import { FileSystem } from '../types';

export class FileManager implements FileSystem {
  /**
   * Check if a file or directory exists
   */
  async exists(path: string): Promise<boolean> {
    const fs = await import('fs/promises');
    
    try {
      await fs.access(path);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Read file contents
   */
  async read(path: string): Promise<string> {
    const fs = await import('fs/promises');
    
    try {
      return await fs.readFile(path, 'utf8');
    } catch (error) {
      throw new Error(`Failed to read file ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Write data to a file
   */
  async write(path: string, data: string): Promise<void> {
    const fs = await import('fs/promises');
    
    try {
      await fs.writeFile(path, data, 'utf8');
    } catch (error) {
      throw new Error(`Failed to write file ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Write binary data to a file
   */
  async writeBinary(path: string, data: Uint8Array): Promise<void> {
    const fs = await import('fs/promises');
    
    try {
      await fs.writeFile(path, data);
    } catch (error) {
      throw new Error(`Failed to write binary file ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Create a directory (recursively)
   */
  async mkdir(path: string): Promise<void> {
    const fs = await import('fs/promises');
    
    try {
      await fs.mkdir(path, { recursive: true });
    } catch (error) {
      throw new Error(`Failed to create directory ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Remove a file or directory
   */
  async remove(path: string): Promise<void> {
    const fs = await import('fs/promises');
    
    try {
      const stat = await fs.stat(path);
      if (stat.isDirectory()) {
        await fs.rmdir(path);
      } else {
        await fs.unlink(path);
      }
    } catch (error) {
      throw new Error(`Failed to remove ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * List files in a directory
   */
  async list(directory: string, pattern?: string): Promise<string[]> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    try {
      const files = await fs.readdir(directory);
      const fullPaths: string[] = [];
      
      for (const file of files) {
        const fullPath = path.join(directory, file);
        const stat = await fs.stat(fullPath);
        
        if (stat.isFile()) {
          if (pattern) {
            // Simple pattern matching (supports *.ext)
            if (pattern.startsWith('*')) {
              const extension = pattern.slice(1);
              if (file.endsWith(extension)) {
                fullPaths.push(fullPath);
              }
            } else if (file.includes(pattern)) {
              fullPaths.push(fullPath);
            }
          } else {
            fullPaths.push(fullPath);
          }
        } else if (stat.isDirectory()) {
          // Recursively list subdirectories
          const subFiles = await this.list(fullPath, pattern);
          fullPaths.push(...subFiles);
        }
      }
      
      return fullPaths;
    } catch (error) {
      throw new Error(`Failed to list directory ${directory}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get file statistics
   */
  async stat(path: string): Promise<{ size: number; isFile: boolean; isDirectory: boolean; mtime: Date }> {
    const fs = await import('fs/promises');
    
    try {
      const stat = await fs.stat(path);
      return {
        size: stat.size,
        isFile: stat.isFile(),
        isDirectory: stat.isDirectory(),
        mtime: stat.mtime
      };
    } catch (error) {
      throw new Error(`Failed to stat ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Copy a file
   */
  async copy(source: string, destination: string): Promise<void> {
    const fs = await import('fs/promises');
    
    try {
      await fs.copyFile(source, destination);
    } catch (error) {
      throw new Error(`Failed to copy ${source} to ${destination}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Move/rename a file
   */
  async move(source: string, destination: string): Promise<void> {
    const fs = await import('fs/promises');
    
    try {
      await fs.rename(source, destination);
    } catch (error) {
      throw new Error(`Failed to move ${source} to ${destination}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
} 