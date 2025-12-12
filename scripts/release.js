#!/usr/bin/env node
/*!
 * Release script for @eecc/rsa-multikey
 * 
 * Usage:
 *   node scripts/release.js [version] [--dry-run]
 * 
 * Examples:
 *   node scripts/release.js patch
 *   node scripts/release.js minor
 *   node scripts/release.js major
 *   node scripts/release.js 1.2.3
 *   node scripts/release.js patch --dry-run
 */

import { readFileSync, writeFileSync } from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

// Parse command line arguments
const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const versionArg = args.find(arg => !arg.startsWith('--'));

if (!versionArg) {
  console.error('Usage: node scripts/release.js [version|patch|minor|major] [--dry-run]');
  console.error('Examples:');
  console.error('  node scripts/release.js patch');
  console.error('  node scripts/release.js minor');
  console.error('  node scripts/release.js major');
  console.error('  node scripts/release.js 1.2.3');
  process.exit(1);
}

// Read current package.json
const packagePath = join(rootDir, 'package.json');
const packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
const currentVersion = packageJson.version;

// Calculate new version
let newVersion;
if (versionArg === 'patch' || versionArg === 'minor' || versionArg === 'major') {
  const [major, minor, patch] = currentVersion.split('.').map(Number);
  
  switch (versionArg) {
    case 'major':
      newVersion = `${major + 1}.0.0`;
      break;
    case 'minor':
      newVersion = `${major}.${minor + 1}.0`;
      break;
    case 'patch':
      newVersion = `${major}.${minor}.${patch + 1}`;
      break;
  }
} else if (/^\d+\.\d+\.\d+$/.test(versionArg)) {
  newVersion = versionArg;
} else {
  console.error(`Invalid version: ${versionArg}`);
  console.error('Version must be "patch", "minor", "major", or a semantic version (e.g., "1.2.3")');
  process.exit(1);
}

console.log(`Current version: ${currentVersion}`);
console.log(`New version: ${newVersion}`);

if (dryRun) {
  const currentBranch = execSync('git rev-parse --abbrev-ref HEAD', { 
    encoding: 'utf8', 
    cwd: rootDir 
  }).trim();
  console.log('\n[DRY RUN] Would perform the following actions:');
  console.log(`  1. Update package.json version to ${newVersion}`);
  console.log(`  2. Run: git add package.json`);
  console.log(`  3. Run: git commit -m "chore: release v${newVersion}"`);
  console.log(`  4. Run: git tag -a v${newVersion} -m "Release v${newVersion}"`);
  console.log(`  5. Run: git push origin ${currentBranch}`);
  console.log(`  6. Run: git push origin v${newVersion}`);
  process.exit(0);
}

// Check if working directory is clean
try {
  const gitStatus = execSync('git status --porcelain', { encoding: 'utf8', cwd: rootDir });
  if (gitStatus.trim()) {
    console.error('Error: Working directory is not clean. Please commit or stash changes first.');
    console.error('\nUncommitted changes:');
    console.error(gitStatus);
    process.exit(1);
  }
} catch (error) {
  console.error('Error checking git status:', error.message);
  process.exit(1);
}

// Check if we're on main branch
let currentBranch;
try {
  currentBranch = execSync('git rev-parse --abbrev-ref HEAD', { 
    encoding: 'utf8', 
    cwd: rootDir 
  }).trim();
  
  if (currentBranch !== 'main' && currentBranch !== 'master') {
    console.error(`Error: Not on main/master branch. Current branch: ${currentBranch}`);
    console.error('Please switch to main/master branch before releasing.');
    process.exit(1);
  }
} catch (error) {
  console.error('Error checking git branch:', error.message);
  process.exit(1);
}

// Update package.json
console.log('\nUpdating package.json...');
packageJson.version = newVersion;
writeFileSync(packagePath, JSON.stringify(packageJson, null, 2) + '\n');

// Stage package.json
console.log('Staging package.json...');
execSync('git add package.json', { cwd: rootDir, stdio: 'inherit' });

// Commit
console.log(`Committing version bump...`);
execSync(`git commit -m "chore: release v${newVersion}"`, { 
  cwd: rootDir, 
  stdio: 'inherit' 
});

// Create tag
console.log(`Creating tag v${newVersion}...`);
execSync(`git tag -a v${newVersion} -m "Release v${newVersion}"`, { 
  cwd: rootDir, 
  stdio: 'inherit' 
});

// Push commits
console.log('Pushing commits to origin...');
execSync(`git push origin ${currentBranch}`, { 
  cwd: rootDir, 
  stdio: 'inherit' 
});

// Push tag (this will trigger GitHub Actions workflows)
console.log(`Pushing tag v${newVersion} to origin...`);
execSync(`git push origin v${newVersion}`, { 
  cwd: rootDir, 
  stdio: 'inherit' 
});

console.log(`\n✅ Successfully released v${newVersion}!`);
console.log('\nThe GitHub Actions workflows will now:');
console.log('  1. Run tests');
console.log('  2. Publish to npm');
console.log('  3. Create a GitHub release');

