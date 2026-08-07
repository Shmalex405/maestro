// Hard guard against re-typing the wizard-composed prompt on remount.
//
// Both terminal-view.tsx (Claude brain) and codex-terminal-view.tsx
// (Codex brain) auto-type assessment.options.pending_prompt into the
// fresh REPL on first spawn. The cloud-side clear (updateOptions with
// pending_prompt removed) is the cross-session safety net, but two
// failure modes caused the prompt to land in the input box every time
// the user navigated back to the assessment:
//   (a) updateOptions silently failed (cloud unreachable, network blip),
//       so pending_prompt stayed set in the cloud-side row.
//   (b) updateOptions succeeded BUT React Query held a stale Assessment
//       in cache, so the next mount's `assessment` prop still carried
//       pending_prompt for a beat — long enough for the auto-typer to
//       fire again before the refetch landed.
//
// THIS Set is the authoritative answer to "did we already type for this
// assessment in this app session". Shared across the Claude and Codex
// views so switching tabs after a successful type doesn't re-fire on
// the other brain. Resets on app restart (by which time the cloud-side
// clear has almost certainly completed).
export const autoTypedAssessmentIds = new Set<string>();
