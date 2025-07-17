/**
 * Cryptographic Interoperability Test Suite (v2)
 *
 * This suite validates that the refactored Secure Enclave manager is fully
 * interoperable with the official `age` and `age-plugin-se` command-line tools.
 */

import { SecureEnclaveManager } from '../src/crypto/secure-enclave-manager';
import { expect } from 'chai';
import { describe, it, before, after } from 'mocha';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

describe('Cross-Tool Crypto Interoperability', function () {
  this.timeout(30000); // Increase timeout for CLI commands

  // Only run these tests on macOS where the tools are available
  if (process.platform !== 'darwin') {
    console.log('Skipping interoperability tests on non-macOS platform.');
    return;
  }

  const fixturesDir = path.join(__dirname, 'fixtures');
  const keyPath = path.join(fixturesDir, 'interop-key.txt');
  const encryptedByPakPath = path.join(fixturesDir, 'encrypted-by-pak.age');
  const encryptedByCliPath = path.join(fixturesDir, 'encrypted-by-cli.age');
  const testData = 'pak-lib interoperability test!';

  let referenceIdentity: string;
  let referenceRecipient: string;
  let manager: SecureEnclaveManager;

  before(function () {
    // 1. Ensure age and age-plugin-se are installed
    try {
      execSync('which age && which age-plugin-se');
    } catch (error) {
      this.skip();
    }

    // 2. Create fixtures directory
    if (!fs.existsSync(fixturesDir)) {
      fs.mkdirSync(fixturesDir);
    }

    // 3. Generate a standard key using the CLI tool
    console.log('[TEST] Generating reference key with age-plugin-se...');
    const keygenOutput = execSync(`age-plugin-se keygen --output ${keyPath} 2>&1`, { encoding: 'utf8' });
    const keyContent = fs.readFileSync(keyPath, 'utf8');
    referenceIdentity = keyContent.split('\n').find(line => line.startsWith('AGE-PLUGIN-SE-'))!;
    // The recipient (public key) is printed to stderr. Use a regex to find it robustly.
    const recipientMatch = keygenOutput.match(/(age1se[a-z0-9]+)/);
    referenceRecipient = recipientMatch ? recipientMatch[0] : '';

    expect(referenceIdentity).to.exist;
    expect(referenceRecipient).to.exist;

    // 4. Initialize the manager
    manager = new SecureEnclaveManager({
      preferNative: true,
      accessControl: 'none',
      recipientType: 'piv-p256',
      useNative: true,
    });
  });

  after(() => {
    // Clean up fixture files
    if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
    if (fs.existsSync(encryptedByPakPath)) fs.unlinkSync(encryptedByPakPath);
    if (fs.existsSync(encryptedByCliPath)) fs.unlinkSync(encryptedByCliPath);
  });

  it('pak-lib should correctly derive a recipient from a CLI-generated identity', async () => {
    console.log('[TEST] Validating identity-to-recipient conversion...');
    const derivedRecipient = await manager.identityToRecipient(referenceIdentity);
    expect(derivedRecipient).to.equal(referenceRecipient);
  });

  it('A file encrypted by pak-lib should be decryptable by the age CLI', async () => {
    console.log('[TEST] Encrypting with pak-lib...');
    const ciphertext = await manager.encrypt(Buffer.from(testData), referenceRecipient);
    fs.writeFileSync(encryptedByPakPath, ciphertext);

    console.log('[TEST] Decrypting with age CLI...');
    const decrypted = execSync(`age --decrypt -i ${keyPath} ${encryptedByPakPath}`, { encoding: 'utf8' });
    expect(decrypted).to.equal(testData);
  });

  it('A file encrypted by the age CLI should be decryptable by pak-lib', async () => {
    console.log('[TEST] Encrypting with age CLI...');
    // Use 'printf' for portability to prevent a trailing newline from being added to the encrypted data.
    execSync(`printf "%s" "${testData}" | age -r "${referenceRecipient}" -o ${encryptedByCliPath}`);
    const ciphertext = fs.readFileSync(encryptedByCliPath);

    console.log('[TEST] Decrypting with pak-lib...');
    const decrypted = await manager.decrypt(ciphertext, referenceIdentity);
    expect(Buffer.from(decrypted).toString()).to.equal(testData);
  });
});