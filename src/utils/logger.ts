/**
 * Logging utility with verbosity support
 */

export enum LogLevel {
  ERROR = 0,   // Always shown (console.error remains unchanged)
  WARN = 1,    // Warnings and important messages 
  INFO = 2,    // General informational messages (default console.log)
  DEBUG = 3,   // Debug information (-v)
  TRACE = 4    // Detailed tracing (-vv and above)
}

class Logger {
  private static instance: Logger;
  private verbosity: number = 0; // 0 = quiet, 1 = -v, 2 = -vv, etc.

  private constructor() {}

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  setVerbosity(level: number): void {
    this.verbosity = level;
  }

  getVerbosity(): number {
    return this.verbosity;
  }

  // Keep console.error unchanged - always shown
  error(...args: any[]): void {
    console.error(...args);
  }

  // Warning messages (shown when verbosity >= 1)
  warn(...args: any[]): void {
    if (this.verbosity >= 1) {
      console.log(...args);
    }
  }

  // General info messages (shown when verbosity >= 1)
  info(...args: any[]): void {
    if (this.verbosity >= 1) {
      console.log(...args);
    }
  }

  // Debug messages (shown when verbosity >= 2)
  debug(...args: any[]): void {
    if (this.verbosity >= 2) {
      console.log(...args);
    }
  }

  // Trace messages (shown when verbosity >= 3)
  trace(...args: any[]): void {
    if (this.verbosity >= 3) {
      console.log(...args);
    }
  }

  // Direct output that should always be shown (like password output)
  output(...args: any[]): void {
    console.log(...args);
  }
}

// Export singleton instance
export const logger = Logger.getInstance();

// Convenience functions
export const log = {
  error: (...args: any[]) => logger.error(...args),
  warn: (...args: any[]) => logger.warn(...args),
  info: (...args: any[]) => logger.info(...args),
  debug: (...args: any[]) => logger.debug(...args),
  trace: (...args: any[]) => logger.trace(...args),
  output: (...args: any[]) => logger.output(...args),
}; 