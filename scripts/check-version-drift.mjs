import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

try {
  const versionFile = fs.readFileSync(path.join(rootDir, 'VERSION'), 'utf-8').trim();
  
  const rootPkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf-8'));
  const rootPkgVersion = rootPkg.version;
  
  const serverPkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'packages/server/package.json'), 'utf-8'));
  const serverPkgVersion = serverPkg.version;

  if (versionFile !== rootPkgVersion || versionFile !== serverPkgVersion) {
    console.error('❌ Version drift detected!');
    console.error(`  VERSION file: ${versionFile}`);
    console.error(`  package.json: ${rootPkgVersion}`);
    console.error(`  packages/server/package.json: ${serverPkgVersion}`);
    console.error('All version strings must match exactly to pass CI.');
    process.exit(1);
  }

  console.log('✅ Versions are synchronized across all sources of truth.');
} catch (err) {
  console.error('❌ Error checking versions:', err.message);
  process.exit(1);
}