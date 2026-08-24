import { readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const root = resolve('dist');
const budgets = {
  '.css': 100 * 1024,
  '.html': 50 * 1024,
  '.js': 350 * 1024,
};
let total = 0;

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}

for (const path of files(root)) {
  const size = statSync(path).size;
  const name = relative(root, path);
  total += size;
  if (name.endsWith('.map')) {
    throw new Error(`Production source map is forbidden: ${name}`);
  }
  const extension = Object.keys(budgets).find((suffix) => name.endsWith(suffix));
  if (extension && size > budgets[extension]) {
    throw new Error(`${name} exceeds its ${String(budgets[extension])}-byte budget`);
  }
}
if (total > 500 * 1024) {
  throw new Error(`Production bundle exceeds 512000 bytes: ${String(total)}`);
}
console.log(`Production bundle is ${String(total)} bytes with no source maps`);
