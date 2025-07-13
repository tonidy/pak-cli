#!/usr/bin/env node

/**
 * PAK (Password Age Kit) - CLI Interface
 * 
 * Command-line interface for the JavaScript pa password manager
 */

import { program } from 'commander';
import { PasswordManager } from './password-manager';
import { PaError } from './types';

// Global options
program
  .option('-b, --backend <backend>', 'Secure Enclave backend to use: native, js, cli, auto', 'auto')
  .option('--use-age-binary', 'Force use of age binary (CLI backend)')
  .option('--no-use-age-binary', 'Disable age binary usage')
  .option('--use-native-se', 'Force use of native Secure Enclave')
  .option('--no-use-native-se', 'Disable native Secure Enclave')
  .version('0.3.4', '-v, --version', 'Show version')
  .description('PAK (Password Age Kit) - A simple password manager using age encryption');

// Helper function to get configuration from global options
function getConfigFromOptions(options: any) {
  const config: any = {};
  
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
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
      console.log(password);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
        console.log('no passwords found');
      } else {
        passwords.forEach(p => console.log(p));
      }
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
      }
      process.exit(1);
    }
  });

// Version command
program
  .command('version')
  .alias('v')
  .description('Show version information')
  .action(async (_, command) => {
    try {
      const config = getConfigFromOptions(command.parent?.opts() || {});
      const pm = new PasswordManager({ config });
      const version = pm.getVersion();
      console.log(`pa version: ${version.version}`);
      console.log(`release date: ${version.releaseDate}`);
      console.log(`commit: ${version.commit}`);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
      }
      process.exit(1);
    }
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
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
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
      console.log(converted);
    } catch (error) {
      if (error instanceof PaError) {
        console.error(`pa: ${error.message}.`);
      } else {
        console.error(`pa: ${error}.`);
      }
      process.exit(1);
    }
  });

// Handle version flags
program
  .option('-v, --version', 'Show version information')
  .action((options) => {
    if (options.version) {
      try {
        const pm = new PasswordManager();
        const version = pm.getVersion();
        
        console.log(`pa version: ${version.version}`);
        console.log(`release date: ${version.releaseDate}`);
        console.log(`commit: ${version.commit}`);
      } catch (error) {
        if (error instanceof PaError) {
          console.error(`pa: ${error.message}.`);
        } else {
          console.error(`pa: ${error}.`);
        }
        process.exit(1);
      }
    }
  });

// Custom help
program.configureHelp({
  formatHelp: () => {
    return `  pa
    a simple password manager

  commands:
    [a]dd  [name] - Add a password entry.
    [d]el  [name] - Delete a password entry.
    [e]dit [name] - Edit a password entry with \\$EDITOR (default: vi).
    [f]ind [cmd]  - Fuzzy search passwords with fzf (show|edit|del).
    [g]it  [cmd]  - Run git command in the password dir.
    [l]ist        - List all entries.
    [s]how [name] - Show password for an entry.
    [v]ersion     - Show version information.
    se-info       - Show Secure Enclave support information.
    convert <recipient> <format> - Convert recipient between 'se' and 'yubikey' formats.

  global options:
    -b, --backend <backend>     - Set Secure Enclave backend: native, js, cli, auto (default: auto)
    --use-age-binary        - Force use of age binary (CLI backend)
    --no-use-age-binary     - Disable age binary usage
    --use-native-se         - Force use of native Secure Enclave
    --no-use-native-se      - Disable native Secure Enclave

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

// Parse command line arguments
program.parse(); 