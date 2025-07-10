#!/usr/bin/env node

/**
 * PAK (Password Age Kit) - CLI Interface
 * 
 * Command-line interface for the JavaScript pa password manager
 */

import { Command } from 'commander';
import { PasswordManager } from './password-manager';
import { PaError } from './types';

const program = new Command();

// Set up the CLI program
program
  .name('pa')
  .description('a simple password manager')
  .version('1.0.0');

// Add command
program
  .command('add <name>')
  .alias('a')
  .description('Add a password entry')
  .option('-g, --generate', 'Generate a password automatically', true)
  .option('-l, --length <length>', 'Password length', '50')
  .option('-p, --pattern <pattern>', 'Password pattern', 'A-Za-z0-9-_')
  .action(async (name: string, options) => {
    try {
      const pm = new PasswordManager();
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

// Delete command
program
  .command('del <name>')
  .alias('d')
  .description('Delete a password entry')
  .action(async (name: string) => {
    try {
      const pm = new PasswordManager();
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

// Edit command
program
  .command('edit <name>')
  .alias('e')
  .description('Edit a password entry with $EDITOR (default: vi)')
  .action(async (name: string) => {
    try {
      const pm = new PasswordManager();
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

// Find command
program
  .command('find [command]')
  .alias('f')
  .description('Fuzzy search passwords with fzf (show|edit|del)')
  .action(async (command?: string) => {
    try {
      const pm = new PasswordManager();
      let findCommand: 'show' | 'edit' | 'del' | undefined;
      
      if (command) {
        if (command.startsWith('s')) {
          findCommand = 'show';
        } else if (command.startsWith('e')) {
          findCommand = 'edit';
        } else if (command.startsWith('d')) {
          findCommand = 'del';
        } else {
          throw new PaError(`unsupported find command '${command}'. Use: show, edit, del`);
        }
      }
      
      await pm.find(findCommand ? { command: findCommand } : {});
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
  .command('git <args...>')
  .alias('g')
  .description('Run git command in the password dir')
  .action(async (args: string[]) => {
    try {
      const pm = new PasswordManager();
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

// List command
program
  .command('list')
  .alias('l')
  .description('List all entries')
  .action(async () => {
    try {
      const pm = new PasswordManager();
      const entries = await pm.list();
      entries.forEach(entry => console.log(entry));
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
  .action(async (name: string) => {
    try {
      const pm = new PasswordManager();
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

// Secure Enclave info command
program
  .command('se-info')
  .description('Show Secure Enclave support information')
  .action(async () => {
    try {
      const pm = new PasswordManager();
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

// Convert recipient command
program
  .command('convert <recipient> <format>')
  .description('Convert recipient between Secure Enclave and YubiKey formats')
  .action(async (recipient: string, format: string) => {
    try {
      const pm = new PasswordManager();
      
      if (format !== 'se' && format !== 'yubikey') {
        throw new PaError(`invalid format '${format}'. Use 'se' or 'yubikey'`);
      }
      
      const convertedRecipient = await pm.convertRecipient(recipient, format as 'se' | 'yubikey');
      console.log(convertedRecipient);
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
  .action(() => {
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

  env vars:
    data directory:   export PA_DIR=~/.local/share/pa
    password length:  export PA_LENGTH=50
    password pattern: export PA_PATTERN=A-Za-z0-9-_
    disable tracking: export PA_NOGIT=
    disable keyring:  export PA_NO_KEYRING=1
    editor command:   export EDITOR=nano

  secure enclave env vars:
    access control:   export PA_SE_ACCESS_CONTROL=any-biometry-or-passcode
    auto confirm:     export PA_SE_AUTO_CONFIRM=1

  platform support:
    - macOS: Keychain integration, Secure Enclave (age-plugin-se)
    - Linux: libsecret/secret-tool integration
    - Windows: Credential Manager integration (WSL/MSYS2/Cygwin)
    - Hardware: YubiKey (age-plugin-yubikey) on all platforms
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