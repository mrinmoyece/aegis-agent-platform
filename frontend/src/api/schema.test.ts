import { describe, expect, it } from 'vitest';

import { demoSession, demoSnapshot } from '../demo/data';
import {
  operatorItemSchema,
  operatorSnapshotSchema,
  sessionBootstrapSchema,
} from './schema';

describe('runtime response schemas', () => {
  it('accepts canonical generated-contract-compatible data', () => {
    expect(operatorSnapshotSchema.parse(demoSnapshot)).toEqual(demoSnapshot);
    expect(sessionBootstrapSchema.parse(demoSession)).toEqual(demoSession);
  });

  it('rejects unknown properties and over-bounded sections', () => {
    expect(() =>
      operatorSnapshotSchema.parse({ ...demoSnapshot, raw_prompt: 'injected' }),
    ).toThrow();
    expect(() =>
      operatorSnapshotSchema.parse({
        ...demoSnapshot,
        sections: {
          timeline: Array.from({ length: 101 }, () => ({
            ...demoSnapshot.sections.timeline?.[0],
          })),
        },
      }),
    ).toThrow();
  });

  it('renders injected evidence only as bounded strings', () => {
    const item = operatorItemSchema.parse({
      ...demoSnapshot.sections.timeline?.[0],
      title: '<img src=x onerror=alert(1)>',
      summary: '<script>steal()</script>',
    });
    expect(item.title).toContain('<img');
    expect(item.summary).toContain('<script>');
  });

  it('rejects secret-shaped unbounded response metadata', () => {
    expect(() =>
      operatorItemSchema.parse({
        ...demoSnapshot.sections.timeline?.[0],
        metadata: Object.fromEntries(
          Array.from({ length: 33 }, (_, index) => [`key-${String(index)}`, index]),
        ),
      }),
    ).toThrow('metadata is too large');
  });
});
