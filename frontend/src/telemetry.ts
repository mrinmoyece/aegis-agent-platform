type TelemetryEvent =
  | 'approval_review_opened'
  | 'navigation_changed'
  | 'operator_error'
  | 'session_expired'
  | 'tenant_changed';

const ALLOWED_FIELDS = new Set(['error_code', 'route', 'status', 'theme', 'transport']);

export function recordTelemetry(
  event: TelemetryEvent,
  fields: Readonly<Record<string, string>>,
): void {
  const safeFields = Object.fromEntries(
    Object.entries(fields)
      .filter(([key, value]) => ALLOWED_FIELDS.has(key) && value.length <= 64)
      .map(([key, value]) => [key, value.replace(/[^A-Za-z0-9._-]/g, '_')]),
  );
  window.dispatchEvent(
    new CustomEvent('aegis:telemetry', {
      detail: { event, fields: safeFields },
    }),
  );
}
