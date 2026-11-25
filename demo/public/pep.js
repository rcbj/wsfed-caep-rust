// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The Policy enforcement tab: every two seconds it fetches the fragment the
// server draws (and escapes) from the PEP's status, so the counters and the
// times stay current. A pane the person closed stays closed across the
// redraw. A hidden page does not poll; a 401 means the sign-in is gone.
const panel = document.getElementById('pep-panel');
const EVERY_MS = 2000;

async function refresh() {
  if (!panel || document.hidden) return;
  try {
    const answer = await fetch('/pep-status.html', { credentials: 'same-origin', cache: 'no-store' });
    if (answer.status === 401) {
      window.location.assign('/');
      return;
    }
    if (!answer.ok) return;
    const closed = [...panel.querySelectorAll('details[id]')].filter((pane) => !pane.open).map((pane) => pane.id);
    panel.innerHTML = await answer.text();
    for (const id of closed) {
      const pane = document.getElementById(id);
      if (pane) pane.open = false;
    }
  } catch (err) {
    // The demo is restarting: keep what is shown and try on the next tick.
  }
}

if (panel) {
  setInterval(refresh, EVERY_MS);
  document.addEventListener('visibilitychange', refresh);
}
