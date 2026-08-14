import { Component, type ReactNode } from 'react';

import { recordTelemetry } from '../telemetry';

interface ErrorBoundaryProps {
  readonly children: ReactNode;
}

interface ErrorBoundaryState {
  readonly failed: boolean;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public override state: ErrorBoundaryState = { failed: false };

  public static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  public override componentDidCatch(): void {
    recordTelemetry('operator_error', { error_code: 'ui_error_boundary' });
  }

  public override render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="fatal-error">
          <h1>Operator view unavailable</h1>
          <p>
            A presentation error was contained. No response payload or credentials were
            written to diagnostics.
          </p>
          <button type="button" onClick={() => window.location.reload()}>
            Reload operator view
          </button>
        </main>
      );
    }
    return this.props.children;
  }
}
