# Operator accessibility target and manual checklist

The Layer 13 target is WCAG 2.2 AA. Automated tests use semantic Testing Library
queries and axe-core, but passing automation is not an independent accessibility
audit or production browser/assistive-technology qualification.

## Implemented controls

- Skip link, header/navigation/main landmarks, one page heading, ordered timelines,
  definition lists, progress elements, labeled forms, and native dialog semantics.
- Keyboard-operable navigation, approvals, tenant clearing, theme controls, detail
  disclosure, and bounded focus movement to main content or the review dialog.
- Visible focus, non-color status text/icons, restrained severity semantics,
  light/dark/high-contrast themes, responsive layouts, and reduced-motion media
  handling.
- Polite bounded live announcements for navigation, session, and mutation state.
- Internationalized dates/numbers with explicit server time and no client-derived
  approval authority.
- Loading, empty, stale, degraded, error, offline-equivalent, ambiguous, and
  verification-pending language that does not imply success.
- Paginated/bounded API records and fixed-size demo charts/timelines; large data is
  never injected into the DOM without bounds.

## Manual release checklist

1. Complete sign-in, every navigation item, approval grant/deny, tenant switch, and
   support-mode flow with keyboard only; verify no focus trap except the modal.
2. Verify focus starts at the dialog close control, returns predictably, and the
   skip link reaches main content.
3. Test 200% and 400% zoom at 320 CSS pixels without loss of actions or two-axis
   scrolling for ordinary content.
4. Test light, dark, high-contrast, forced-colors, and reduced-motion settings.
5. Check critical status, risk, stale/unknown, and action ambiguity without relying
   on color.
6. Run current stable NVDA/Firefox and JAWS/Chrome on Windows and
   VoiceOver/Safari on macOS/iOS for headings, landmarks, dialog labels, tables,
   status announcements, and approval errors.
7. Confirm expiry/countdown information remains understandable when client clocks
   differ; the server still makes the decision.
8. Confirm support-mode redaction remains apparent to screen-reader users.
9. Review copy for neutral grant/deny prominence and absence of approval dark
   patterns.
10. Record browser, assistive-technology, OS, findings, owner, and remediation.

Items 3-10 require deployment release evidence and are not claimed complete by the
repository's deterministic CI.
