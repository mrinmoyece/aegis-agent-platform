import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';

import { App } from './App';

beforeEach(() => {
  window.history.replaceState(null, '', '#health');
});

async function signIn() {
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole('button', { name: 'Start synthetic demo' }));
  await screen.findByRole('heading', { name: 'Health & SLOs' });
  return user;
}

describe('operator application', () => {
  it('requires an explicit synthetic session and labels readiness honestly', () => {
    render(<App />);
    expect(
      screen.getByRole('heading', {
        name: 'Operate from facts, not browser state',
      }),
    ).toBeVisible();
    expect(screen.getByText(/Production readiness:/)).toHaveTextContent('false');
  });

  it('supports keyboard navigation across operator screens', async () => {
    const user = await signIn();
    const navigation = screen.getByRole('navigation', {
      name: 'Operator sections',
    });
    await user.click(
      within(navigation).getByRole('link', { name: /Controlled actions/ }),
    );
    expect(
      await screen.findByRole('heading', { name: 'Controlled actions' }),
    ).toBeVisible();
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Ambiguous provider acknowledgement is not success',
    );
  });

  it('uses an explicit review and typed confirmation for approval', async () => {
    const user = await signIn();
    await user.click(screen.getByRole('link', { name: /Approval inbox/ }));
    await user.click(screen.getByRole('button', { name: 'Review exact scope' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Plan digest')).toBeVisible();
    const submit = within(dialog).getByRole('button', { name: 'Record grant' });
    expect(submit).toBeDisabled();
    await user.type(
      within(dialog).getByLabelText(/Type APPROVE to confirm/),
      'APPROVE',
    );
    expect(submit).toBeEnabled();
    await user.click(submit);
    expect(await within(dialog).findByText('Decision recorded')).toBeVisible();
    expect(dialog).toHaveTextContent(/verification is pending/i);
    expect(dialog).toHaveTextContent('not an action-success signal');
  });

  it('clears tenant-scoped data before tenant re-authentication', async () => {
    const user = await signIn();
    await user.click(
      screen.getByRole('button', { name: 'Change tenant / re-authenticate' }),
    );
    expect(
      await screen.findByRole('button', { name: 'Start synthetic demo' }),
    ).toBeVisible();
    expect(
      screen.queryByText('Checkout latency after synthetic deployment'),
    ).toBeNull();
  });

  it('supports high contrast and support-mode redaction without persistence', async () => {
    const user = await signIn();
    await user.selectOptions(screen.getByLabelText('Theme'), 'contrast');
    expect(document.documentElement.dataset.theme).toBe('contrast');
    await user.click(screen.getByRole('button', { name: 'Support mode off' }));
    await user.click(screen.getByRole('link', { name: /Incident overview/ }));
    await waitFor(() =>
      expect(screen.getAllByText(/\[redacted\]/i).length).toBeGreaterThan(0),
    );
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });
});
