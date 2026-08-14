const FORMULA_PREFIX = /^[\t\r]*[=+\-@]/;
const SENSITIVE_KEY =
  /(authorization|credential|password|private.?key|prompt|secret|token)/i;
const BEARER_VALUE = /\bBearer\s+\S+/gi;
const SAFE_DOWNLOAD_TYPES = new Set([
  'application/json',
  'application/pdf',
  'text/csv',
  'text/plain',
]);
const SAFE_SCHEMES = new Set(['evidence:', 'event:', 'memory:', 'audit:', 'artifact:']);

export function redactText(value: string): string {
  return value.replace(BEARER_VALUE, '[REDACTED]');
}

export function redactRecord(
  value: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      SENSITIVE_KEY.test(key) ? '[REDACTED]' : redactUnknown(item),
    ]),
  );
}

function redactUnknown(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactText(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactUnknown);
  }
  if (typeof value === 'object' && value !== null) {
    return redactRecord(value as Record<string, unknown>);
  }
  return value;
}

export function csvCell(value: string): string {
  const neutralized = FORMULA_PREFIX.test(value) ? `'${value}` : value;
  return `"${neutralized.replaceAll('"', '""')}"`;
}

export function safeCitation(value: string): string | null {
  try {
    const parsed = new URL(value);
    return SAFE_SCHEMES.has(parsed.protocol) ? parsed.toString() : null;
  } catch {
    return null;
  }
}

export function assertSafeDownload(
  contentType: string,
  filename: string,
  size: number,
): void {
  const normalizedType = contentType.split(';', 1)[0]?.trim().toLowerCase();
  if (!normalizedType || !SAFE_DOWNLOAD_TYPES.has(normalizedType)) {
    throw new Error('Download content type is not allowed');
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename) || filename.includes('..')) {
    throw new Error('Download filename is not allowed');
  }
  if (!Number.isSafeInteger(size) || size < 0 || size > 10 * 1024 * 1024) {
    throw new Error('Download exceeds the size limit');
  }
}

export async function copyBoundedText(
  value: string,
  clipboard: Pick<Clipboard, 'writeText'> = navigator.clipboard,
): Promise<void> {
  if (value.length === 0 || value.length > 4_096) {
    throw new Error('Clipboard value is outside the allowed bound');
  }
  await clipboard.writeText(redactText(value));
}
