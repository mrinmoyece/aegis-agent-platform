import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it } from 'vitest';

import { App } from './App';

describe('operator accessibility', () => {
  it('has no automatically detectable WCAG 2.2 AA violations', async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    await user.click(screen.getByRole('button', { name: 'Start synthetic demo' }));
    await screen.findByRole('heading', { name: 'Health & SLOs' });
    const result = await axe.run(container, {
      runOnly: {
        type: 'tag',
        values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'],
      },
    });
    expect(result.violations).toEqual([]);
  });
});
