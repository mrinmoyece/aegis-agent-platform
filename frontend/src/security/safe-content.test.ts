import { describe, expect, it, vi } from 'vitest';

import {
  assertSafeDownload,
  copyBoundedText,
  csvCell,
  redactRecord,
  safeCitation,
} from './safe-content';

describe('safe content utilities', () => {
  it.each(['=2+2', '+cmd', '-1+2', '@SUM(A1:A2)'])(
    'neutralizes spreadsheet formula %s',
    (value) => {
      expect(csvCell(value)).toBe(`"'${value}"`);
    },
  );

  it('recursively redacts sensitive keys and bearer values', () => {
    expect(
      redactRecord({
        prompt: 'raw',
        nested: { authorization: 'Bearer abc', safe: 'Bearer token' },
      }),
    ).toEqual({
      prompt: '[REDACTED]',
      nested: { authorization: '[REDACTED]', safe: '[REDACTED]' },
    });
    expect(
      redactRecord({ values: ['Bearer private', 7, null], safe: 'public' }),
    ).toEqual({
      values: ['[REDACTED]', 7, null],
      safe: 'public',
    });
  });

  it('allows only reviewed citation schemes', () => {
    expect(safeCitation('event://checkout/41')).toContain('event://checkout/41');
    expect(safeCitation('javascript:alert(1)')).toBeNull();
    expect(safeCitation('https://attacker.invalid')).toBeNull();
    expect(safeCitation('not a url')).toBeNull();
  });

  it('rejects unsafe download types, filenames, and sizes', () => {
    expect(() => assertSafeDownload('text/csv', 'report.csv', 1024)).not.toThrow();
    expect(() => assertSafeDownload('text/html', 'report.html', 10)).toThrow();
    expect(() => assertSafeDownload('text/plain', '../secret.txt', 10)).toThrow();
    expect(() =>
      assertSafeDownload('application/json', 'report.json', 20 * 1024 * 1024),
    ).toThrow();
  });

  it('bounds and redacts clipboard text', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    await copyBoundedText('Bearer top-secret', { writeText });
    expect(writeText).toHaveBeenCalledWith('[REDACTED]');
    await expect(copyBoundedText('', { writeText })).rejects.toThrow();
    await expect(copyBoundedText('x'.repeat(4_097), { writeText })).rejects.toThrow();
  });
});
