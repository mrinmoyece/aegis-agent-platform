import { readFileSync } from 'node:fs';

const configuration = readFileSync('nginx.conf', 'utf8');
const index = readFileSync('index.html', 'utf8');

for (const forbidden of ["'unsafe-inline'", "'unsafe-eval'"]) {
  if (configuration.includes(forbidden)) {
    throw new Error(`CSP contains forbidden source ${forbidden}`);
  }
}
if (!configuration.includes("frame-ancestors 'none'")) {
  throw new Error('CSP must deny framing');
}
if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(index) || /<style[\s>]/i.test(index)) {
  throw new Error('Inline script or style found in the application shell');
}
console.log('CSP and application shell prohibit inline and eval scripts');
