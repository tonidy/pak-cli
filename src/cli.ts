#!/usr/bin/env node

/**
 * PAK (Password Age Kit) - CLI Interface
 * 
 * Command-line interface for the JavaScript pa password manager
 */

import { program } from 'commander';
import { PasswordManager } from './password-manager';
import { PaError } from './types';
import { logger } from './utils/logger';
import * as fs from 'fs';
import * as path from 'path';

// Get version from package.json
function getPackageVersion(): string {
  try {
    const packagePath = path.join(__dirname, '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    return packageJson.version;
  } catch {
    return '0.3.11'; // fallback version
  }
}

// Check if -v should show version (when used alone, not with commands)
function shouldShowVersionForV(): boolean {
  const args = process.argv.slice(2); // Remove 'node' and script name
  
  // Find -v flag
  let hasV = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-v') {
      hasV = true;
      break;
    }
  }
  
  if (!hasV) return false;
  
  // List of known commands
  const commands = ['add', 'a', 'show', 's', 'list', 'l', 'edit', 'e', 'del', 'd', 'find', 'f', 'git', 'g', 'version', 'se-info', 'convert'];
  
  // Check if any command is present
  for (let i = 0; i < args.length; i++) {
    if (commands.includes(args[i])) {
      return false; // -v is being used with a command, so it's for verbosity
    }
  }
  
  return true; // -v is used alone (possibly with global options), so show version
}

// Global options
program
  .option('-b, --backend <backend>', 'Secure Enclave backend to use: native, js, cli, auto', 'auto')
  .option('--use-age-binary', 'Force use of age binary (CLI backend)')
  .option('--no-use-age-binary', 'Disable age binary usage')
  .option('--use-native-se', 'Force use of native Secure Enclave')
  .option('--no-use-native-se', 'Disable native Secure Enclave')
  .option('-v, --verbose', 'Enable verbose output (level 1)')
  .option('-vv', 'Enable more verbose output (level 2)')
  .option('-vvv', 'Enable very verbose output (level 3)')
  .option('-vvvv', 'Enable extremely verbose output (level 4)')

  .version(getPackageVersion(), '-V, --version', 'Show version')
  .description('PAK (Password Age Kit) - A simple password manager using age encryption');

// Helper function to parse verbosity level from commander options
function parseVerbosity(options: any): number {
  let verbosity = 0;
  
  if (options.verbose) verbosity = Math.max(verbosity, 1);
  if (options.vv) verbosity = Math.max(verbosity, 2);
  if (options.vvv) verbosity = Math.max(verbosity, 3);
  if (options.vvvv) verbosity = Math.max(verbosity, 4);
  
  return verbosity;
}

// Helper function to get configuration from global options
function getConfigFromOptions(options: any) {
  const config: any = {};
  
  // Set verbosity level in logger
  const verbosity = parseVerbosity(options);
  logger.setVerbosity(verbosity);
  
  // Backend selection
  if (options.backend && options.backend !== 'auto') {
    config.seBackend = options.backend;
  }
  
  // Age binary configuration
  if (options.useAgeBinary !== undefined) {
    config.useAgeBinary = options.useAgeBinary;
  }
  
  // Native SE configuration
  if (options.useNativeSe !== undefined) {
    config.useNativeSecureEnclave = options.useNativeSe;
  }
  
  return config;
}

// Helper function to show version information
async function showVersion() {
  try {
    const pm = new PasswordManager();
    const version = pm.getVersion();
    
    logger.output(`pak version: ${version.version}`);
    logger.output(`release date: ${version.releaseDate}`);
    logger.output(`commit: ${version.commit}`);
  } catch (error) {
    if (error instanceof PaError) {
      console.error(`pak: ${error.message}.`);
    } else {
      console.error(`pak: ${error}.`);
    }
    process.exit(1);
  }
}

// Add command
program
  .command('add <name>')
  .alias('a')
  .description('Add a password entry')
  .option('-g, --generate', 'Generate a password automatically', true)
  .option('-l, --length <length>', 'Password length', '50')
  .option('-p, --pattern <pattern>', 'Password pattern', 'A-Za-z0-9-_')
  .action(async (name: string, options, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      await pm.add(name, {
        generate: options.generate,
        length: parseInt(options.length),
        pattern: options.pattern
      });
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Show command
program
  .command('show <name>')
  .alias('s')
  .description('Show password for an entry')
  .action(async (name: string, _, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      const password = await pm.show(name);
      logger.output(password);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// List command
program
  .command('list')
  .alias('l')
  .description('List all password entries')
  .action(async (_, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      const passwords = await pm.list();
      if (passwords.length === 0) {
        logger.output('no passwords found');
      } else {
        passwords.forEach(p => logger.output(p));
      }
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Edit command
program
  .command('edit <name>')
  .alias('e')
  .description('Edit a password entry with $EDITOR')
  .action(async (name: string, _, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      await pm.edit(name);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Delete command
program
  .command('del <name>')
  .alias('d')
  .description('Delete a password entry')
  .action(async (name: string, _, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      await pm.delete(name);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Find command
program
  .command('find [command]')
  .alias('f')
  .description('Fuzzy search passwords with fzf')
  .action(async (cmd: string, _, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      await pm.find({ command: cmd as 'show' | 'edit' | 'del' });
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Git command
program
  .command('git [args...]')
  .alias('g')
  .description('Run git command in the password directory')
  .action(async (args: string[], _, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      await pm.git(args);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Version command (keep existing for 'version' command)
program
  .command('version')
  .description('Show version information')
  .action(async () => {
    await showVersion();
  });

// SE Info command
program
  .command('se-info')
  .description('Show Secure Enclave support information')
  .action(async (_, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      await pm.getSecureEnclaveInfo();
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Convert command
program
  .command('convert <recipient> <format>')
  .description('Convert recipient between formats (se/yubikey)')
  .action(async (recipient: string, format: string, _, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      
      if (format !== 'se' && format !== 'yubikey') {
        throw new PaError(`invalid format '${format}'. Use 'se' or 'yubikey'`);
      }
      
      const converted = await pm.convertRecipient(recipient, format as 'se' | 'yubikey');
      logger.output(converted);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pak: ${error.message}.`);
      } else {
        console.error(`pak: ${error}.`);
      }
      process.exit(1);
    }
  });

// Custom help
program.configureHelp({
  formatHelp: () => {
    return `  pak
    a simple password manager

  commands:
    [a]dd  [name] - Add a password entry.
    [d]el  [name] - Delete a password entry.
    [e]dit [name] - Edit a password entry with \\$EDITOR (default: vi).
    [f]ind [cmd]  - Fuzzy search passwords with fzf (show|edit|del).
    [g]it  [cmd]  - Run git command in the password dir.
    [l]ist        - List all entries.
    [s]how [name] - Show password for an entry.
    version       - Show version information.
    se-info       - Show Secure Enclave support information.
    convert <recipient> <format> - Convert recipient between 'se' and 'yubikey' formats.

  global options:
    -b, --backend <backend>     - Set Secure Enclave backend: native, js, cli, auto (default: auto)
    --use-age-binary        - Force use of age binary (CLI backend)
    --no-use-age-binary     - Disable age binary usage
    --use-native-se         - Force use of native Secure Enclave
    --no-use-native-se      - Disable native Secure Enclave
    -v, --verbose           - Show version (when alone) or enable verbose output (level 1)
    -vv                     - Enable more verbose output (level 2)
    -vvv                    - Enable very verbose output (level 3)
    -vvvv                   - Enable extremely verbose output (level 4)
    -V, --version           - Show version information

  env vars:
    data directory:   export PA_DIR=~/.local/share/pa
    password length:  export PA_LENGTH=50
    password pattern: export PA_PATTERN=A-Za-z0-9-_
    disable tracking: export PA_NOGIT=
    disable keyring:  export PA_NO_KEYRING=1
    editor command:   export EDITOR=nano
    age binary:       export PA_USE_AGE_BINARY=1
    age binary path:  export PA_AGE_BINARY_PATH=/opt/homebrew/bin/age

  secure enclave env vars:
    access control:   export PA_SE_ACCESS_CONTROL=any-biometry-or-passcode
    auto confirm:     export PA_SE_AUTO_CONFIRM=1
    backend:          export PA_SE_BACKEND=native (native|js|cli|auto)

  platform support:
    - macOS: Keychain integration, Secure Enclave (age-plugin-se)
    - Linux: libsecret/secret-tool integration
    - Windows: Credential Manager integration (WSL/MSYS2/Cygwin)
    - Hardware: YubiKey (age-plugin-yubikey) on all platforms

  backend selection:
    native    - Use native Swift Secure Enclave addon (fastest, hardware-backed)
    js        - Use pure JavaScript implementation (fast, software-based)
    cli       - Use age-plugin-se binary (slowest, hardware-backed)
    auto      - Automatically choose best available backend (default)
`;
  }
});

// Handle no arguments - show help
if (process.argv.length === 2) {
  program.help();
}

// Set up signal handlers
process.on('SIGINT', () => {
  // Ensure terminal is in usable state
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }
  process.exit(130);
});

process.on('SIGTERM', () => {
  // Ensure terminal is in usable state
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }
  process.exit(143);
});

// Main async function to handle CLI execution
async function main() {
  // Check if -v should show version (when used alone)
  if (shouldShowVersionForV()) {
    await showVersion();
    process.exit(0);
  }

  // Parse command line arguments normally
  program.parse(process.argv);
}

// Run the main function
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
}); 