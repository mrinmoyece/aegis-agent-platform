import { spawnSync } from 'node:child_process';

const allowed = new Set([
  '0BSD',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'BlueOak-1.0.0',
  'CC0-1.0',
  'ISC',
  'MIT',
  'Python-2.0',
]);
const packageManager = process.env.npm_execpath;

if (!packageManager) {
  throw new Error('Run the license check through the pinned package manager');
}

const result = spawnSync(
  process.execPath,
  [packageManager, 'licenses', 'list', '--prod', '--json'],
  { encoding: 'utf8' },
);
if (result.status !== 0) {
  throw new Error(
    result.stderr || 'Unable to enumerate production dependency licenses',
  );
}

const report = JSON.parse(result.stdout);
const rejected = Object.keys(report).filter((license) => !allowed.has(license));
if (rejected.length > 0) {
  throw new Error(`Disallowed or unreviewed licenses: ${rejected.sort().join(', ')}`);
}
console.log(`Reviewed production licenses: ${Object.keys(report).sort().join(', ')}`);
