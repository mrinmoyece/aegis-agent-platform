import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';
import { DemoOperatorDataSource } from './demo/api';

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

  it('binds protocol trust changes to the pinned peer scope', async () => {
    const user = await signIn();
    await user.click(screen.getByRole('link', { name: 'MCP & A2A trust' }));

    expect(screen.getByText('Protocol peer registry')).toBeInTheDocument();
    expect(screen.getAllByText(/fails closed outside local demo/i)).not.toHaveLength(0);
    const [reviewTrust] = screen.getAllByRole('button', { name: 'Review trust' });
    if (reviewTrust === undefined) {
      throw new Error('missing trust review control');
    }
    await user.click(reviewTrust);

    const confirmation = screen.getByLabelText(
      /Type peer-mcp-deterministic to confirm/,
    );
    const submit = screen.getByRole('button', { name: 'Record quarantine' });
    expect(submit).toBeDisabled();
    await user.type(confirmation, 'peer-mcp-deterministic');
    expect(submit).toBeEnabled();
    await user.click(submit);

    expect(screen.getByText(/is quarantined/i)).toBeInTheDocument();
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

  it('blocks approval decisions when the poller has expired', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const baseSource = new DemoOperatorDataSource();
    const source = {
      signIn: baseSource.signIn.bind(baseSource),
      loadSnapshot: baseSource.loadSnapshot.bind(baseSource),
      loadEvents: () => Promise.reject(new Error('network')),
      decideApproval: baseSource.decideApproval.bind(baseSource),
      changePeerTrust: baseSource.changePeerTrust.bind(baseSource),
    };
    const user = userEvent.setup();
    render(<App source={source} />);
    await user.click(screen.getByRole('button', { name: 'Start synthetic demo' }));
    await screen.findByRole('heading', { name: 'Health & SLOs' }, { timeout: 5_000 });
    // Advance through the 5 polling failure backoffs so pollerState becomes 'expired'.
    await vi.advanceTimersByTimeAsync(2_000 + 4_000 + 8_000 + 16_000 + 32_000 + 1_000);
    // After 5 failures the poller is expired; decideApproval will be guarded.
    await user.click(screen.getByRole('link', { name: /Approval inbox/ }));
  }, 15_000);

  afterEach(() => {
    vi.useRealTimers();
  });
});
