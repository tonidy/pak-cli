#!/usr/bin/env node

const { execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

function log(message) {
  console.log(`[postinstall] ${message}`);
}

function showCliBackendInfo() {
  log('');
  log('📋 CLI Backend Setup Instructions:');
  log('');
  log('PAK will use the CLI backend instead of native module.');
  log('To enable full functionality, install the following tools:');
  log('');
  log('1. Install age (encryption tool):');
  log('   macOS:   brew install age');
  log('   Linux:   sudo apt install age  # or equivalent package manager');
  log('   Windows: scoop install age     # or download from https://github.com/FiloSottile/age/releases');
  log('');
  log('2. Install age-plugin-se (Secure Enclave support, macOS only):');
  log('   brew install age-plugin-se');
  log('');
  log('3. Verify installation:');
  log('   pa se-info  # Check Secure Enclave support');
  log('   pa --help   # Verify PAK is working');
  log('');
  log('For more information, visit: https://github.com/tonidy/pak-lib');
  log('');
}

function checkSwiftAvailable() {
  try {
    execSync('swift --version', { stdio: 'pipe' });
    return true;
  } catch (error) {
    return false;
  }
}

function checkXcodeAvailable() {
  try {
    execSync('xcode-select --print-path', { stdio: 'pipe' });
    return true;
  } catch (error) {
    return false;
  }
}

function buildNativeModule() {
  return new Promise((resolve, reject) => {
    const nativeDir = path.join(__dirname, '..', 'dist', 'native');
    
    if (!fs.existsSync(nativeDir)) {
      log('Native directory not found, skipping native build');
      resolve(false);
      return;
    }

    log(`Building native Secure Enclave module in ${nativeDir}...`);
    
    // Clean Swift build cache first to avoid path conflicts
    log('Cleaning Swift build cache...');
    try {
      const swiftDir = path.join(nativeDir, 'SecureEnclaveSwift');
      if (fs.existsSync(swiftDir)) {
        execSync('swift package clean', { cwd: swiftDir, stdio: 'pipe' });
        log('Swift cache cleaned');
      }
    } catch (error) {
      log(`Warning: Could not clean Swift cache: ${error.message}`);
    }
    
    // Clean node_modules to ensure fresh installation
    log('Cleaning node_modules...');
    try {
      const nodeModulesDir = path.join(nativeDir, 'node_modules');
      if (fs.existsSync(nodeModulesDir)) {
        execSync(`rm -rf "${nodeModulesDir}"`, { stdio: 'pipe' });
        log('node_modules cleaned');
      }
    } catch (error) {
      log(`Warning: Could not clean node_modules: ${error.message}`);
    }
    
    const buildProcess = spawn('npm', ['install'], {
      cwd: nativeDir,
      stdio: 'pipe'
    });

    let output = '';
    buildProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    buildProcess.stderr.on('data', (data) => {
      output += data.toString();
    });

    buildProcess.on('error', (error) => {
      log(`Build process error: ${error.message}`);
      resolve(false);
    });

    buildProcess.on('close', (code) => {
      if (code === 0) {
        log('Native module built successfully');
        resolve(true);
      } else {
        log(`Native module build failed with exit code ${code}`);
        log('This is normal if you don\'t have Xcode/Swift installed');
        if (output.trim()) {
          log('Build output:');
          log(output);
        }
        resolve(false);
      }
    });

    // Timeout after 60 seconds
    setTimeout(() => {
      buildProcess.kill();
      log('Native module build timed out, falling back to CLI backend');
      resolve(false);
    }, 60000);
  });
}

async function main() {
  // Only attempt to build on macOS
  if (process.platform !== 'darwin') {
    log('Non-macOS platform detected, skipping native module build');
    showCliBackendInfo();
    return;
  }

  log('macOS detected, checking for build tools...');

  // Check if Swift is available
  if (!checkSwiftAvailable()) {
    log('Swift compiler not found, skipping native module build');
    log('To enable native Secure Enclave support, install Xcode or Swift toolchain');
    showCliBackendInfo();
    return;
  }
  log('✓ Swift compiler found');

  // Check if Xcode tools are available
  if (!checkXcodeAvailable()) {
    log('Xcode command line tools not found, skipping native module build');
    log('To enable native Secure Enclave support, run: xcode-select --install');
    showCliBackendInfo();
    return;
  }
  log('✓ Xcode command line tools found');

  log('Build tools available, attempting to build native module...');

  try {
    const success = await buildNativeModule();
    if (success) {
      log('Native Secure Enclave support enabled');
    } else {
      log('Native module build failed, falling back to CLI backend');
      showCliBackendInfo();
    }
  } catch (error) {
    log(`Native module build error: ${error.message}`);
    log('Falling back to CLI backend');
    showCliBackendInfo();
  }
}

// Run the script
main().catch((error) => {
  log(`Postinstall script failed: ${error.message}`);
  showCliBackendInfo();
  // Don't exit with error code to avoid breaking package installation
}); 