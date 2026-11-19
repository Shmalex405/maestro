/**
 * Copy and link handling for the assessment terminals (Claude and Codex).
 *
 * The panes run tmux with `mouse on` (for wheel scrolling), so a plain
 * mouse drag is captured by tmux and copied into tmux's own buffer — it never
 * reached the system clipboard. And the web-links addon's default handler
 * calls window.open, which the app window blocks, so clicking a link did
 * nothing.
 *
 * Deliberately user-initiated only: the terminal shows output from systems
 * under test, which can be attacker-controlled. So there is no OSC 52
 * support (that would let any program in the container silently set — or
 * read — the user's clipboard); copying happens only on an explicit
 * gesture, and only http(s) links are opened.
 *
 * Gestures:
 *   - Shift+drag selects text even while tmux/Claude track the mouse
 *     (xterm.js forces a local selection when Shift is held).
 *   - Ctrl+Shift+C, or right-click on a selection, copies it.
 *   - Shift+click on an http(s) link opens it in the default browser.
 *     (A plain click is forwarded to tmux/Claude while they track the
 *     mouse; Shift keeps it in xterm, where the link provider sees it.
 *     tmux also strips OSC 8 embedded links unless told the outer terminal
 *     supports them, so plain-text URLs are what reliably work.)
 */
import type { Terminal } from '@xterm/xterm';

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    const { toast } = await import('sonner');
    toast.success('Copied to clipboard');
  } catch (err) {
    const { toast } = await import('sonner');
    toast.error('Could not copy', { description: err instanceof Error ? err.message : String(err) });
  }
}

/**
 * Wire up Ctrl+Shift+C and right-click copy of the current selection, and
 * route embedded (OSC 8) hyperlinks — e.g. Claude's "Security guide" link —
 * through the same http(s)-only opener as plain-text URLs. Returns a
 * function that removes the DOM listener.
 */
export function installTerminalCopy(term: Terminal, element: HTMLElement): () => void {
  term.options.linkHandler = {
    activate: (event, text) => openTerminalLink(event, text),
    allowNonHttpProtocols: false,
  };

  term.attachCustomKeyEventHandler((event) => {
    const isCopy =
      event.type === 'keydown' &&
      event.ctrlKey &&
      event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === 'c';
    if (!isCopy) return true;
    const selection = term.getSelection();
    if (selection) void copyText(selection);
    // Never forward Ctrl+Shift+C to the app, selection or not.
    return false;
  });

  // Right-click with a selection copies it. When tmux/Claude track the
  // mouse, xterm forwards the right button to them on mousedown (tmux then
  // opens its own pane menu — Kill, Respawn, ...), so the press and release
  // must be swallowed in the capture phase, before xterm sees them. Without
  // a selection, right-click is left alone.
  const swallowRightButton = (event: MouseEvent) => {
    if (event.button !== 2 || !term.hasSelection()) return;
    event.preventDefault();
    event.stopImmediatePropagation();
  };
  const onContextMenu = (event: MouseEvent) => {
    const selection = term.getSelection();
    if (!selection) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    void copyText(selection);
    term.clearSelection();
  };
  const capture = { capture: true } as const;
  element.addEventListener('mousedown', swallowRightButton, capture);
  element.addEventListener('mouseup', swallowRightButton, capture);
  element.addEventListener('contextmenu', onContextMenu, capture);
  return () => {
    element.removeEventListener('mousedown', swallowRightButton, capture);
    element.removeEventListener('mouseup', swallowRightButton, capture);
    element.removeEventListener('contextmenu', onContextMenu, capture);
  };
}

/**
 * Handler for WebLinksAddon: open http(s) links in the system browser.
 * Anything else (file:, javascript:, custom schemes) is ignored.
 */
export function openTerminalLink(_event: MouseEvent, uri: string): void {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  void import('@tauri-apps/plugin-opener')
    .then(({ openUrl }) => openUrl(url.toString()))
    .catch(async (err: unknown) => {
      const { toast } = await import('sonner');
      toast.error('Could not open link', {
        description: err instanceof Error ? err.message : String(err),
      });
    });
}
