/**
 * User Interface for CLI Interactions
 */

import { UserInteraction } from '../types';
import { log } from './logger';

export class UserInterface implements UserInteraction {
  /**
   * Ask user for confirmation (y/N)
   */
  async confirm(message: string): Promise<boolean> {
    const readline = await import('readline');
    
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    return new Promise((resolve) => {
      // Enable raw input for single character response
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(true);
      }
      
      rl.question(`${message} [y/N]: `, (answer) => {
        if (process.stdin.isTTY) {
          process.stdin.setRawMode(false);
        }
        
        rl.close();
        
        // Print the answer since raw mode doesn't echo
        log.output(answer);
        
        const normalized = answer.toLowerCase().trim();
        resolve(normalized === 'y' || normalized === 'yes');
      });
    });
  }

  /**
   * Prompt user for input
   */
  async prompt(message: string, hidden: boolean = false): Promise<string> {
    const readline = await import('readline');
    
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    return new Promise((resolve) => {
      if (hidden) {
        // Hide input for passwords
        if (process.stdin.isTTY) {
          process.stdout.write(`${message}: `);
          process.stdin.setRawMode(true);
          
          let input = '';
          const onData = (char: Buffer) => {
            const str = char.toString();
            
            if (str === '\r' || str === '\n') {
              // Enter pressed
              process.stdin.setRawMode(false);
              process.stdin.removeListener('data', onData);
              process.stdout.write('\n');
              rl.close();
              resolve(input);
            } else if (str === '\u007f' || str === '\b') {
              // Backspace
              if (input.length > 0) {
                input = input.slice(0, -1);
              }
            } else if (str === '\u0003') {
              // Ctrl+C
              process.stdin.setRawMode(false);
              process.stdin.removeListener('data', onData);
              rl.close();
              process.exit(1);
            } else {
              // Regular character
              input += str;
            }
          };
          
          process.stdin.on('data', onData);
        } else {
          // Fallback for non-TTY
          rl.question(`${message}: `, (answer) => {
            rl.close();
            resolve(answer);
          });
        }
      } else {
        // Normal input
        rl.question(`${message}: `, (answer) => {
          rl.close();
          resolve(answer);
        });
      }
    });
  }

  /**
   * Select from a list using fzf
   */
  async selectFromList(items: string[], prompt: string = 'Select: '): Promise<string | null> {
    const { spawn } = await import('child_process');
    
    return new Promise((resolve, reject) => {
      const fzf = spawn('fzf', [
        '--height', '40%',
        '--reverse',
        '--no-multi',
        '--prompt', prompt
      ], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      // Send items to fzf
      fzf.stdin.write(items.join('\n'));
      fzf.stdin.end();
      
      let output = '';
      fzf.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      fzf.on('close', (code) => {
        if (code === 0) {
          resolve(output.trim() || null);
        } else {
          resolve(null);
        }
      });
      
      fzf.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * Display a message to the user
   */
  message(text: string): void {
    log.output(text);
  }

  /**
   * Display an error message
   */
  error(text: string): void {
    console.error(`Error: ${text}`);
  }

  /**
   * Display a warning message
   */
  warning(text: string): void {
    console.warn(`Warning: ${text}`);
  }

  /**
   * Display a success message
   */
  success(text: string): void {
    log.output(`✓ ${text}`);
  }

  /**
   * Display an info message
   */
  info(text: string): void {
    log.info(`ℹ ${text}`);
  }

  /**
   * Display a spinner/loading message
   */
  spinner(text: string): { stop: () => void } {
    const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let frameIndex = 0;
    let running = true;
    
    const interval = setInterval(() => {
      if (running) {
        process.stdout.write(`\r${frames[frameIndex]} ${text}`);
        frameIndex = (frameIndex + 1) % frames.length;
      }
    }, 100);
    
    return {
      stop: () => {
        running = false;
        clearInterval(interval);
        process.stdout.write('\r');
      }
    };
  }

  /**
   * Clear the current line
   */
  clearLine(): void {
    if (process.stdout.isTTY) {
      process.stdout.write('\r\x1b[K');
    }
  }

  /**
   * Move cursor up
   */
  cursorUp(lines: number = 1): void {
    if (process.stdout.isTTY) {
      process.stdout.write(`\x1b[${lines}A`);
    }
  }

  /**
   * Move cursor down
   */
  cursorDown(lines: number = 1): void {
    if (process.stdout.isTTY) {
      process.stdout.write(`\x1b[${lines}B`);
    }
  }

  /**
   * Show a progress bar
   */
  progressBar(current: number, total: number, width: number = 40): void {
    const percentage = Math.round((current / total) * 100);
    const filled = Math.round((current / total) * width);
    const empty = width - filled;
    
    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    process.stdout.write(`\r[${bar}] ${percentage}%`);
    
    if (current === total) {
      process.stdout.write('\n');
    }
  }

  /**
   * Display a table
   */
  table(data: Array<Record<string, string>>, headers?: string[]): void {
    if (data.length === 0) return;
    
    const keys = headers || Object.keys(data[0]);
    const columnWidths = keys.map(key => 
      Math.max(key.length, ...data.map(row => String(row[key] || '').length))
    );
    
    // Header
    const headerRow = keys.map((key, i) => key.padEnd(columnWidths[i])).join(' | ');
    log.output(headerRow);
    log.output(keys.map((_, i) => '-'.repeat(columnWidths[i])).join('-|-'));
    
    // Rows
    data.forEach(row => {
      const rowStr = keys.map((key, i) => 
        String(row[key] || '').padEnd(columnWidths[i])
      ).join(' | ');
      log.output(rowStr);
    });
  }
} 