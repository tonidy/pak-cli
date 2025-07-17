const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const packageJsonPath = path.join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

const version = packageJson.version;
let commit = 'unknown';
try {
  commit = execSync('git rev-parse --short HEAD').toString().trim();
} catch (e) {
  console.warn('Warning: Could not get git commit hash');
}
const releaseDate = new Date().toISOString().split('T')[0];

// Update password-manager.js
const passwordManagerPath = path.join(__dirname, '..', 'dist', 'src', 'password-manager.js');

if (fs.existsSync(passwordManagerPath)) {
  let content = fs.readFileSync(passwordManagerPath, 'utf8');

  // Replace version placeholders ONLY in the static property assignments
  // Use more specific patterns to avoid replacing in the version check logic
  content = content.replace(/PA_VERSION = ['"]__VERSION__['"]/g, `PA_VERSION = '${version}'`);
  content = content.replace(/PA_RELEASE_DATE = ['"]__RELEASE_DATE__['"]/g, `PA_RELEASE_DATE = '${releaseDate}'`);
  content = content.replace(/PA_COMMIT = ['"]__COMMIT__['"]/g, `PA_COMMIT = '${commit}'`);

  fs.writeFileSync(passwordManagerPath, content, 'utf8');

  console.log(`Version information set in ${passwordManagerPath}`);
  console.log(`  Version: ${version}`);
  console.log(`  Release Date: ${releaseDate}`);
  console.log(`  Commit: ${commit}`);
} else {
  console.error(`Error: ${passwordManagerPath} not found. Make sure to run 'tsc' before this script.`);
  process.exit(1);
}

// Also update cli.js to fix the fallback version
const cliPath = path.join(__dirname, '..', 'dist', 'src', 'cli.js');

if (fs.existsSync(cliPath)) {
  let cliContent = fs.readFileSync(cliPath, 'utf8');
  
  // Replace the fallback version in getPackageVersion function
  cliContent = cliContent.replace(/return ['"]0\.5\.0['"];(\s*\/\/ fallback version)/g, `return '${version}';$1`);
  
  fs.writeFileSync(cliPath, cliContent, 'utf8');
  console.log(`Fallback version updated in ${cliPath}`);
}