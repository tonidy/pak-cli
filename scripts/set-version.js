const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const packageJsonPath = path.join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

const version = packageJson.version;
const commit = execSync('git rev-parse --short HEAD').toString().trim();
const releaseDate = new Date().toISOString().split('T')[0];

const filePath = path.join(__dirname, '..', 'dist', 'src', 'password-manager.js');

if (fs.existsSync(filePath)) {
  let content = fs.readFileSync(filePath, 'utf8');

  content = content.replace(/__VERSION__/g, version);
  content = content.replace(/__RELEASE_DATE__/g, releaseDate);
  content = content.replace(/__COMMIT__/g, commit);

  fs.writeFileSync(filePath, content, 'utf8');

  console.log(`Version information set in ${filePath}`);
  console.log(`  Version: ${version}`);
  console.log(`  Release Date: ${releaseDate}`);
  console.log(`  Commit: ${commit}`);
} else {
  console.error(`Error: ${filePath} not found. Make sure to run 'tsc' before this script.`);
  process.exit(1);
}