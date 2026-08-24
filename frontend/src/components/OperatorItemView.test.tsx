import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { demoSnapshot } from '../demo/data';
import { OperatorItemView } from './OperatorItemView';

describe('OperatorItemView', () => {
  it('renders injected evidence as text without creating executable elements', () => {
    const item = demoSnapshot.sections.timeline?.[0];
    if (item === undefined) throw new Error('timeline fixture missing');
    const title = '<img src=x onerror=alert(1)>';
    const summary = '<script>window.effect=true</script>';

    const { container } = render(
      <OperatorItemView item={{ ...item, title, summary }} supportMode={false} />,
    );

    expect(screen.getByRole('heading', { name: title })).toBeVisible();
    expect(screen.getByText(summary)).toBeVisible();
    expect(container.querySelector('img, script')).toBeNull();
  });
});
