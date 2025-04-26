/**
 * Build script for attested-ohttp-client-ts
 * 
 * This script:
 * 1. Cleans the dist directory
 * 2. Runs the TypeScript compiler
 * 3. Copies necessary files to the dist directory
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Project paths
const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_DIR = path.resolve(ROOT_DIR, 'dist');
const SRC_DIR = path.resolve(ROOT_DIR, 'src');
const EXAMPLES_DIR = path.resolve(ROOT_DIR, 'examples');

// Files to copy to dist folder
const FILES_TO_COPY = [
  'README.md',
  'LICENSE',
  'package.json'
];

console.log('📦 Building attested-ohttp-client-ts...');

// Step 1: Clean dist directory
console.log('🧹 Cleaning dist directory...');
if (fs.existsSync(DIST_DIR)) {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(DIST_DIR, { recursive: true });

// Step 2: Run TypeScript compiler
console.log('🔨 Running TypeScript compiler for source files...');
try {
  execSync('npx tsc', { stdio: 'inherit', cwd: ROOT_DIR });
  console.log('✅ TypeScript compilation successful');
} catch (error) {
  console.error('❌ TypeScript compilation failed:', error.message);
  process.exit(1);
}

// Step 3: Compile examples
console.log('🔨 Running TypeScript compiler for examples...');
try {
  execSync('npx tsc -p ./examples/tsconfig.json', { stdio: 'inherit', cwd: ROOT_DIR });
  console.log('✅ Examples compilation successful');
} catch (error) {
  console.error('❌ Examples compilation failed:', error.message);
  process.exit(1);
}

// Step 4: Copy necessary files
console.log('📋 Copying files to dist directory...');
FILES_TO_COPY.forEach(file => {
  const sourcePath = path.resolve(ROOT_DIR, file);
  const destPath = path.resolve(DIST_DIR, file);
  
  if (fs.existsSync(sourcePath)) {
    // Create destination directory if it doesn't exist
    const destDir = path.dirname(destPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }
    
    // Copy the file
    fs.copyFileSync(sourcePath, destPath);
    console.log(`  - Copied ${file}`);
  } else {
    console.warn(`  - Warning: ${file} not found, skipping`);
  }
});

// Step 5: Update package.json in dist
console.log('📝 Updating package.json for distribution...');
const packageJsonPath = path.join(DIST_DIR, 'package.json');
if (fs.existsSync(packageJsonPath)) {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  
  // Remove development-only properties and scripts
  delete packageJson.devDependencies;
  delete packageJson.scripts.dev;
  packageJson.scripts.build = 'echo "Already built"';
  
  // Set main and types
  packageJson.main = 'src/index.js';
  packageJson.types = 'src/index.d.ts';
  
  // Write updated package.json
  fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2), 'utf8');
  console.log('  - Updated package.json');
}

console.log('✨ Build complete!');
console.log('\nYou can test the library by running:');
console.log('  node dist/examples/basic-usage.js');
