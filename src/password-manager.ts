/**
 * PAK (Password Age Kit) - Password Manager
 * 
 * JavaScript port of the pa shell script password manager
 */

import * as path from 'path';
import * as os from 'os';
import { 
  PakConfig, 
  VersionInfo, 
  GitInfo, 
  CommandOptions,
  FindOptions,
  PlatformCapabilities,
  PasswordManagerOptions,
  PaError
} from './types';
import { PlatformDetector } from './platform/platform-detector';
import { CredentialManager } from './platform/credential-manager';
import { AgeManager } from './crypto/age-manager';
import { GitManager } from './git/git-manager';
import { FileManager } from './utils/file-manager';
import { RandomGenerator } from './utils/random-generator';
import { UserInterface } from './utils/user-interface';

export class PasswordManager {
  private config: PakConfig;
  private platformDetector: PlatformDetector;
  private credentialManager: CredentialManager;
  private ageManager: AgeManager;
  private gitManager: GitManager;
  private fileManager: FileManager;
  private randomGenerator: RandomGenerator;
  private userInterface: UserInterface;
  
  private paDir: string;
  private identitiesFile: string;
  private recipientsFile: string;
  private passwordsDir: string;
  private gitEnabled: boolean = false;
  private initialized: boolean = false;

  // Version information
  private static readonly PA_VERSION = '__VERSION__';
  private static readonly PA_RELEASE_DATE = '__RELEASE_DATE__';
  private static readonly PA_COMMIT = '__COMMIT__';

  constructor(options: PasswordManagerOptions = {}) {
    this.config = {
      paDir: process.env.PA_DIR || path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'pa'),
      paLength: parseInt(process.env.PA_LENGTH || '50'),
      paPattern: process.env.PA_PATTERN || 'A-Za-z0-9-_',
      paNoGit: process.env.PA_NOGIT !== undefined,
      paNoKeyring: process.env.PA_NO_KEYRING === '1',
      editor: process.env.EDITOR || 'vi',
      ...options.config
    };

    // Validate PA_DIR is absolute
    if (!path.isAbsolute(this.config.paDir!)) {
      throw new PaError(`PA_DIR must be an absolute path (got '${this.config.paDir}')`);
    }

    this.paDir = this.config.paDir!;
    this.identitiesFile = path.join(this.paDir, 'identities');
    this.recipientsFile = path.join(this.paDir, 'recipients');
    this.passwordsDir = path.join(this.paDir, 'passwords');

    // Initialize dependencies
    this.platformDetector = new PlatformDetector();
    this.credentialManager = new CredentialManager(this.platformDetector);
    this.ageManager = new AgeManager(this.config);
    this.gitManager = new GitManager(this.passwordsDir);
    this.fileManager = new FileManager();
    this.randomGenerator = new RandomGenerator();
    this.userInterface = new UserInterface();
  }

  /**
   * Initialize the password manager
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Check if age and age-keygen are available
    const capabilities = await this.getPlatformCapabilities();
    if (!capabilities.age) {
      throw new PaError('age not found, install per https://age-encryption.org');
    }
    if (!capabilities.ageKeygen) {
      throw new PaError('age-keygen not found, install per https://age-encryption.org');
    }

    // Create directories
    await this.fileManager.mkdir(this.passwordsDir);

    // Change to passwords directory
    process.chdir(this.passwordsDir);

    // Disable globbing for security
    if (process.platform !== 'win32') {
      process.env.set = '-f';
    }

    // Check git availability and initialize if needed
    this.gitEnabled = !this.config.paNoGit && capabilities.git;
    if (this.gitEnabled) {
      await this.initializeGit();
    }

    // Initialize encryption keys
    await this.initializeEncryption();

    this.initialized = true;
  }

  /**
   * Add a password entry
   */
  async add(name: string, options: CommandOptions = {}): Promise<void> {
    await this.ensureInitialized();
    
    // Check if password already exists
    const passwordFile = path.join(this.passwordsDir, `${name}.age`);
    if (await this.fileManager.exists(passwordFile)) {
      throw new PaError(`password '${name}' already exists`);
    }

    let password: string;

    if (options.generate !== false && await this.userInterface.confirm('generate a password?')) {
      // Generate password
      const length = options.length || this.config.paLength!;
      const pattern = options.pattern || this.config.paPattern!;
      
      try {
        password = this.randomGenerator.generateChars(length, pattern);
      } catch (error) {
        throw new PaError("couldn't generate a password");
      }
    } else {
      // Prompt for password
      password = await this.userInterface.prompt('enter a password', true);
      if (!password) {
        throw new PaError("password can't be empty");
      }

      const password2 = await this.userInterface.prompt('enter a password (again)', true);
      if (password !== password2) {
        throw new PaError("passwords don't match");
      }
    }

    // Create category directory if needed
    const categoryDir = path.dirname(passwordFile);
    if (categoryDir !== this.passwordsDir) {
      try {
        await this.fileManager.mkdir(categoryDir);
      } catch (error) {
        const categoryName = path.relative(this.passwordsDir, categoryDir);
        throw new PaError(`couldn't create category '${categoryName}'`);
      }
    }

    // Encrypt and save password
    try {
      const encryptedData = await this.ageManager.encrypt(password);
      await this.fileManager.write(passwordFile, Buffer.from(encryptedData).toString());
      console.log(`saved '${name}' to the store.`);
    } catch (error) {
      throw new PaError(`couldn't encrypt ${name}.age`);
    }

    // Git commit if enabled
    if (this.gitEnabled) {
      await this.gitManager.addAndCommit(passwordFile, `add '${name}'`);
    }
  }

  /**
   * Show a password entry
   */
  async show(name: string): Promise<string> {
    await this.ensureInitialized();
    
    const passwordFile = path.join(this.passwordsDir, `${name}.age`);
    if (!await this.fileManager.exists(passwordFile)) {
      throw new PaError(`password '${name}' doesn't exist`);
    }

    try {
      const encryptedData = await this.fileManager.read(passwordFile);
      return await this.decryptWithKey(Buffer.from(encryptedData));
    } catch (error) {
      throw new PaError(`couldn't decrypt ${name}.age`);
    }
  }

  /**
   * List all password entries
   */
  async list(): Promise<string[]> {
    await this.ensureInitialized();
    
    try {
      const files = await this.fileManager.list(this.passwordsDir, '*.age');
      return files
        .map(file => file.replace(/\.age$/, ''))
        .map(file => path.relative(this.passwordsDir, file))
        .sort();
    } catch (error) {
      return [];
    }
  }

  /**
   * Delete a password entry
   */
  async delete(name: string): Promise<void> {
    await this.ensureInitialized();
    
    const passwordFile = path.join(this.passwordsDir, `${name}.age`);
    if (!await this.fileManager.exists(passwordFile)) {
      throw new PaError(`password '${name}' doesn't exist`);
    }

    const confirmed = await this.userInterface.confirm(`delete password '${name}'?`);
    if (!confirmed) {
      return;
    }

    try {
      await this.fileManager.remove(passwordFile);
      
      // Try to remove empty parent directories
      let parentDir = path.dirname(passwordFile);
      while (parentDir !== this.passwordsDir) {
        try {
          const files = await this.fileManager.list(parentDir);
          if (files.length === 0) {
            await this.fileManager.remove(parentDir);
            parentDir = path.dirname(parentDir);
          } else {
            break;
          }
        } catch {
          break;
        }
      }
    } catch (error) {
      throw new PaError(`couldn't delete ${name}.age`);
    }

    // Git commit if enabled
    if (this.gitEnabled) {
      await this.gitManager.addAndCommit(passwordFile, `delete '${name}'`);
    }
  }

  /**
   * Edit a password entry
   */
  async edit(name: string): Promise<void> {
    await this.ensureInitialized();
    
    const passwordFile = path.join(this.passwordsDir, `${name}.age`);
    const isNew = !await this.fileManager.exists(passwordFile);

    // Create temporary file
    const tmpDir = this.getTempDirectory();
    const tmpFile = path.join(tmpDir, `pa.${this.randomGenerator.generateChars(10, 'A-Za-z0-9')}`);

    try {
      // Decrypt existing password to temp file
      if (!isNew) {
        const decrypted = await this.show(name);
        await this.fileManager.write(tmpFile, decrypted);
      }

      // Launch editor
      const editorCmd = this.config.editor!;
      const { spawn } = await import('child_process');
      
      await new Promise<void>((resolve, reject) => {
        const editor = spawn(editorCmd, [tmpFile], {
          stdio: 'inherit'
        });
        
        editor.on('close', (code) => {
          if (code === 0) {
            resolve();
          } else {
            reject(new PaError(`editor '${editorCmd}' exited with code ${code}`));
          }
        });
        
        editor.on('error', () => {
          reject(new PaError(`editor '${editorCmd}' not found. Set EDITOR environment variable or install vi`));
        });
      });

      // Check if file has content
      const content = await this.fileManager.read(tmpFile);
      if (content.trim()) {
        // Create category directory if needed
        const categoryDir = path.dirname(passwordFile);
        if (categoryDir !== this.passwordsDir) {
          await this.fileManager.mkdir(categoryDir);
        }

        // Encrypt and save
        const encryptedData = await this.ageManager.encrypt(content);
        await this.fileManager.write(passwordFile, Buffer.from(encryptedData).toString());

        if (isNew) {
          console.log(`saved '${name}' to the store.`);
        }

        // Git commit if enabled
        if (this.gitEnabled) {
          await this.gitManager.addAndCommit(passwordFile, `edit '${name}'`);
        }
      }
    } finally {
      // Clean up temp file
      try {
        await this.fileManager.remove(tmpFile);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Find passwords using fuzzy search
   */
  async find(options: FindOptions = {}): Promise<void> {
    await this.ensureInitialized();
    
    const capabilities = await this.getPlatformCapabilities();
    if (!capabilities.fzf) {
      throw new PaError('fzf not found, install from https://github.com/junegunn/fzf');
    }

    const passwords = await this.list();
    if (passwords.length === 0) {
      throw new PaError('no passwords found');
    }

    try {
      const selected = await this.userInterface.selectFromList(
        passwords, 
        options.prompt || 'Select password: '
      );

      if (!selected) {
        throw new PaError('no password selected');
      }

      // Execute command if provided
      if (options.command) {
        switch (options.command) {
          case 'show':
            const password = await this.show(selected);
            console.log(password);
            break;
          case 'edit':
            await this.edit(selected);
            break;
          case 'del':
            await this.delete(selected);
            break;
          default:
            throw new PaError(`unsupported find command '${options.command}'. Use: show, edit, del`);
        }
      } else {
        // Default action is to show
        const password = await this.show(selected);
        console.log(password);
      }
    } catch (error) {
      if (error instanceof PaError) {
        throw error;
      }
      throw new PaError('fzf selection failed');
    }
  }

  /**
   * Get version information
   */
  getVersion(): VersionInfo {
    const isDevVersion = PasswordManager.PA_VERSION === '__VERSION__';
    
    if (isDevVersion) {
      // Try to get git info for development version
      const gitInfo = this.getGitInfo();
      
      return {
        version: gitInfo.tag || 'development',
        releaseDate: gitInfo.date || 'development',
        commit: gitInfo.commit || 'unknown',
        isDevelopment: true
      };
    } else {
      return {
        version: PasswordManager.PA_VERSION,
        releaseDate: PasswordManager.PA_RELEASE_DATE,
        commit: PasswordManager.PA_COMMIT,
        isDevelopment: false
      };
    }
  }

  /**
   * Run git command in password directory
   */
  async git(args: string[]): Promise<void> {
    await this.ensureInitialized();
    
    if (!this.gitEnabled) {
      throw new PaError('git is not enabled or not available');
    }

    const { spawn } = await import('child_process');
    const git = spawn('git', args, {
      cwd: this.passwordsDir,
      stdio: 'inherit'
    });

    return new Promise((resolve, reject) => {
      git.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new PaError(`git command failed with code ${code}`));
        }
      });
    });
  }

  /**
   * Get platform capabilities
   */
  async getPlatformCapabilities(): Promise<PlatformCapabilities> {
    const { execSync } = await import('child_process');
    
    const checkCommand = (cmd: string): boolean => {
      try {
        execSync(`command -v ${cmd}`, { stdio: 'ignore' });
        return true;
      } catch {
        return false;
      }
    };

    return {
      credentialStore: await this.credentialManager.isAvailable(),
      secureEnclave: checkCommand('age-plugin-se'),
      yubikey: checkCommand('age-plugin-yubikey'),
      fzf: checkCommand('fzf'),
      git: checkCommand('git'),
      age: checkCommand('age') || checkCommand('rage'),
      ageKeygen: checkCommand('age-keygen') || checkCommand('rage-keygen')
    };
  }

  // Private methods

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  private async initializeGit(): Promise<void> {
    if (!await this.gitManager.isInitialized()) {
      await this.gitManager.init();
      
      // Configure git for age files
      const { execSync } = await import('child_process');
      execSync('git config diff.age.binary true', { cwd: this.passwordsDir });
      execSync(`git config diff.age.textconv "age --decrypt -i '${this.identitiesFile}'"`, { cwd: this.passwordsDir });
      
      // Create .gitattributes
      await this.fileManager.write(
        path.join(this.passwordsDir, '.gitattributes'),
        '*.age diff=age\n'
      );
      
      await this.gitManager.addAndCommit('.', 'initial commit');
    }
  }

  private async initializeEncryption(): Promise<void> {
    const hasIdentity = await this.fileManager.exists(this.identitiesFile);
    const hasRecipient = await this.fileManager.exists(this.recipientsFile);
    
    if (!hasIdentity || !hasRecipient) {
      // Check for hardware plugins first
      const capabilities = await this.getPlatformCapabilities();
      
      if (capabilities.secureEnclave) {
        await this.initializeSecureEnclave();
      } else if (capabilities.yubikey) {
        await this.initializeYubikey();
      } else {
        await this.initializeStandardKeys();
      }
    }

    // Load identities and recipients into AgeManager
    try {
      const identities = await this.ageManager.loadIdentitiesFromFile(this.identitiesFile);
      this.ageManager.setIdentities(identities);
    } catch (error) {
      // If we can't load identities, we'll create them
      console.log('Could not load identities, will create new ones if needed');
    }

    try {
      const recipients = await this.ageManager.loadRecipientsFromFile(this.recipientsFile);
      this.ageManager.setRecipients(recipients);
    } catch (error) {
      // If we can't load recipients, we'll create them
      console.log('Could not load recipients, will create new ones if needed');
    }
  }

  private async initializeSecureEnclave(): Promise<void> {
    const confirmed = await this.userInterface.confirm('generate secure enclave identity?');
    if (!confirmed) return;

    console.log('Choose access control for Secure Enclave key:');
    console.log('1) any-biometry (Touch ID/Face ID)');
    console.log('2) any-biometry-or-passcode (Touch ID/Face ID or device passcode)');
    console.log('3) passcode (device passcode only)');
    console.log('4) current-biometry (current enrolled biometrics only)');
    
    const choice = await this.userInterface.prompt('Enter choice [1-4, default: 2]');
    
    const accessControlMap: Record<string, string> = {
      '1': 'any-biometry',
      '2': 'any-biometry-or-passcode',
      '3': 'passcode',
      '4': 'current-biometry'
    };
    
    const accessControl = accessControlMap[choice] || 'any-biometry-or-passcode';
    
    const { execSync } = await import('child_process');
    
    try {
      execSync(`age-plugin-se keygen --access-control="${accessControl}" -o "${this.identitiesFile}"`, {
        stdio: 'inherit'
      });
      
      execSync(`age-plugin-se recipients -i "${this.identitiesFile}" -o "${this.recipientsFile}"`, {
        stdio: 'inherit'
      });
    } catch (error) {
      throw new PaError('failed to generate Secure Enclave identity file');
    }
  }

  private async initializeYubikey(): Promise<void> {
    const confirmed = await this.userInterface.confirm('generate yubikey identity?');
    if (!confirmed) return;

    const { execSync } = await import('child_process');
    
    try {
      const identity = execSync(
        'age-plugin-yubikey --generate --name "pa identity" --pin-policy never --touch-policy always',
        { encoding: 'utf8' }
      );
      
      await this.fileManager.write(this.identitiesFile, identity);
      
      const recipients = execSync('age-plugin-yubikey -l', { encoding: 'utf8' });
      await this.fileManager.write(this.recipientsFile, recipients);
    } catch (error) {
      throw new PaError('failed to generate YubiKey identity file');
    }
  }

  private async initializeStandardKeys(): Promise<void> {
    const osType = this.platformDetector.detectOS();
    
    if (osType !== 'unknown' && !this.config.paNoKeyring) {
      const useKeyring = await this.userInterface.confirm('use system credential storage for encryption keys?');
      
      if (useKeyring) {
        // Generate with passphrase and store in keyring
        const keyPassphrase = this.randomGenerator.generateChars(32, 'A-Za-z0-9');
        
        try {
          const identity = await this.ageManager.generateIdentity();
          await this.fileManager.write(this.identitiesFile, identity);
          
          const stored = await this.credentialManager.store(
            'pa-encryption-key',
            process.env.USER || 'user',
            keyPassphrase
          );
          
          if (stored) {
            console.log('encryption key passphrase stored in system credential store');
          } else {
            console.log('warning: couldn\'t store passphrase in credential store, using file-based storage');
            // Regenerate without passphrase
            const newIdentity = await this.ageManager.generateIdentity();
            await this.fileManager.write(this.identitiesFile, newIdentity);
          }
        } catch (error) {
          throw new PaError("couldn't generate age identity");
        }
      } else {
        const identity = await this.ageManager.generateIdentity();
        await this.fileManager.write(this.identitiesFile, identity);
      }
    } else {
      const identity = await this.ageManager.generateIdentity();
      await this.fileManager.write(this.identitiesFile, identity);
    }

    // Generate recipient file if it doesn't exist
    if (!await this.fileManager.exists(this.recipientsFile)) {
      const identity = await this.fileManager.read(this.identitiesFile);
      const recipient = await this.ageManager.identityToRecipient(identity);
      await this.fileManager.write(this.recipientsFile, recipient);
    }
  }

  private async decryptWithKey(encryptedData: Uint8Array): Promise<string> {
    // First try without passphrase using loaded identities
    try {
      return await this.ageManager.decrypt(encryptedData);
    } catch {
      // Continue to try with passphrase
    }

    // Try with stored passphrase if available
    const osType = this.platformDetector.detectOS();
    if (osType !== 'unknown' && !this.config.paNoKeyring) {
      try {
        const passphrase = await this.credentialManager.retrieve(
          'pa-encryption-key',
          process.env.USER || 'user'
        );
        
        if (passphrase) {
          return await this.ageManager.decryptWithPassphrase(encryptedData, passphrase);
        }
      } catch {
        // Continue to prompt for passphrase
      }
    }

    // Prompt for passphrase
    const userPassphrase = await this.userInterface.prompt('Enter passphrase for encryption key', true);
    if (!userPassphrase) {
      throw new PaError('no passphrase provided');
    }

    return await this.ageManager.decryptWithPassphrase(encryptedData, userPassphrase);
  }

  private getTempDirectory(): string {
    const osType = this.platformDetector.detectOS();
    
    switch (osType) {
      case 'windows':
      case 'wsl':
        return process.env.TEMP || process.env.TMP || '/tmp';
      case 'linux':
        // Prefer /dev/shm (in-memory) on Linux
        return require('fs').existsSync('/dev/shm') && 
               require('fs').statSync('/dev/shm').isDirectory() ? '/dev/shm' : '/tmp';
      default:
        return '/tmp';
    }
  }

  private getGitInfo(): GitInfo {
    try {
      const { execSync } = require('child_process');
      const scriptDir = path.dirname(__filename);
      
      if (require('fs').existsSync(path.join(scriptDir, '.git'))) {
        const originalCwd = process.cwd();
        process.chdir(scriptDir);
        
        try {
          const tag = execSync('git describe --tags 2>/dev/null || git describe --always 2>/dev/null || echo "no-tag"', 
            { encoding: 'utf8' }).trim();
          const commit = execSync('git rev-parse --short HEAD 2>/dev/null || echo "no-commit"', 
            { encoding: 'utf8' }).trim();
          const status = execSync('git status --porcelain 2>/dev/null', 
            { encoding: 'utf8' }).trim();
          const date = execSync('git log -1 --format=%cd --date=short 2>/dev/null || echo "unknown"', 
            { encoding: 'utf8' }).trim();
          
          return {
            tag: status ? `${tag}-dirty` : tag,
            commit,
            status,
            date
          };
        } finally {
          process.chdir(originalCwd);
        }
      }
    } catch {
      // Ignore errors
    }
    
    return {};
  }
} 