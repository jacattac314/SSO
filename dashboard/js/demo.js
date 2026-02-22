// === Demo Mode ===
window.Demo = (function () {
  'use strict';

  // How long to pause on each step type (ms)
  const DELAYS = {
    nav:        1000,
    selectFlow: 1400,
    advance:    1700,
    failure:    3200,
    done:       3500,
  };

  // Full demo sequence: login flow + error scenarios
  const sequence = [
    // ── Phase 1: Login Flow ──────────────────────────────────────────────────
    {
      type: 'nav', panel: 'simulator',
      phase: 'Login Flow',
      desc: 'Starting OIDC + PKCE authentication walkthrough...',
    },
    {
      type: 'selectFlow', flow: 'oidc',
      phase: 'Login Flow',
      desc: 'Step 1/10 — Login Entry Point: user navigates to the login URL',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 2/10 — PKCE parameters generated; browser redirected to Identity Provider',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 3/10 — Identity Provider authenticates the user\'s credentials',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 4/10 — Callback received: state & CSRF token validated (one-time use)',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 5/10 — Authorization code exchanged; PKCE code verifier confirmed',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 6/10 — Identity claims extracted; attribute mappings applied',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 7/10 — User record upserted via just-in-time provisioning',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 8/10 — Opaque 256-bit session token created and stored',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 9/10 — HttpOnly session cookie set; user redirected to application',
    },
    {
      type: 'advance',
      phase: 'Login Flow',
      desc: 'Step 10/10 — Login complete! Session validated on every subsequent request',
    },

    // ── Phase 2: Error Scenarios ─────────────────────────────────────────────
    {
      type: 'nav', panel: 'failures',
      phase: 'Error Scenarios',
      desc: 'Now showing: what happens when errors occur and why...',
    },
    {
      type: 'failure', id: 'expired-state',
      phase: 'Error Scenarios',
      desc: 'Error: OIDC state expired — user took more than 10 minutes at the Identity Provider',
    },
    {
      type: 'failure', id: 'pkce-mismatch',
      phase: 'Error Scenarios',
      desc: 'Error: PKCE mismatch — possible man-in-the-middle attack on the auth flow detected',
    },
    {
      type: 'failure', id: 'user-deactivated',
      phase: 'Error Scenarios',
      desc: 'Error: Account deactivated — SCIM deprovisioning immediately enforced at login',
    },
    {
      type: 'failure', id: 'idle-timeout',
      phase: 'Error Scenarios',
      desc: 'Error: Session idle timeout — user inactive 30+ minutes, must re-authenticate',
    },

    // ── Done ─────────────────────────────────────────────────────────────────
    {
      type: 'done',
      phase: 'Complete',
      desc: 'Demo complete! Use the tabs above to explore flows, tokens, failures, and security gaps.',
    },
  ];

  // Internal state
  var running  = false;
  var index    = 0;
  var timer    = null;
  var bar      = null;

  // ── Public API ──────────────────────────────────────────────────────────────

  function start() {
    if (running) { stop(); return; }
    running = true;
    index   = 0;
    createBar();
    updatePlayBtn(true);
    tick();
  }

  function stop() {
    running = false;
    clearTimeout(timer);
    cleanupFailures();
    removeBar();
    updatePlayBtn(false);
  }

  // ── Tick loop ───────────────────────────────────────────────────────────────

  function tick() {
    if (!running) return;
    if (index >= sequence.length) { stop(); return; }

    var item = sequence[index];
    updateBar(item);
    execute(item);
    index++;

    var delay = item.type === 'done' ? DELAYS.done : (DELAYS[item.type] || 1500);
    if (item.type === 'done') {
      timer = setTimeout(stop, delay);
    } else {
      timer = setTimeout(tick, delay);
    }
  }

  // ── Action executors ────────────────────────────────────────────────────────

  function execute(item) {
    switch (item.type) {
      case 'nav':        doNav(item.panel); break;
      case 'selectFlow': doSelectFlow(item.flow); break;
      case 'advance':    doAdvance(); break;
      case 'failure':    doFailure(item.id); break;
    }
  }

  function doNav(panel) {
    // Use the existing nav tab click handler
    var tab = document.querySelector('.nav-tab[data-panel="' + panel + '"]');
    if (tab) tab.click();
  }

  function doSelectFlow(flow) {
    // Click the protocol button — it also resets to step 0 internally
    var btn = document.querySelector('.proto-btn[data-flow="' + flow + '"]');
    if (btn) btn.click();
  }

  function doAdvance() {
    var next = document.getElementById('sim-next');
    if (next && !next.disabled) next.click();
  }

  function doFailure(id) {
    // Deactivate whatever is currently active first
    cleanupFailures();
    var toggle = document.querySelector('.failure-toggle[data-toggle="' + id + '"]');
    if (toggle) {
      // Only click if not already active (cleanup may have deactivated)
      if (!toggle.classList.contains('active')) toggle.click();
      // Scroll into view so the user can see the activated toggle
      toggle.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function cleanupFailures() {
    var active = document.querySelector('.failure-toggle.active');
    if (active) active.click(); // click again → deactivates via the toggle handler
  }

  // ── Demo bar UI ─────────────────────────────────────────────────────────────

  function createBar() {
    if (bar) return;
    var el = document.createElement('div');
    el.id = 'demo-bar';
    el.innerHTML = [
      '<div class="demo-bar-inner">',
        '<div class="demo-bar-left">',
          '<div class="demo-pulse"></div>',
          '<div class="demo-bar-text">',
            '<span class="demo-bar-phase" id="demo-bar-phase"></span>',
            '<span class="demo-bar-desc"  id="demo-bar-desc"></span>',
          '</div>',
        '</div>',
        '<div class="demo-bar-right">',
          '<div class="demo-progress-wrap">',
            '<div class="demo-progress-fill" id="demo-progress-fill"></div>',
          '</div>',
          '<span class="demo-bar-count" id="demo-bar-count"></span>',
          '<button class="demo-stop-btn" id="demo-stop-btn">&#9632; Stop</button>',
        '</div>',
      '</div>',
    ].join('');
    document.body.appendChild(el);
    bar = el;
    document.getElementById('demo-stop-btn').addEventListener('click', stop);
  }

  function removeBar() {
    if (bar) { bar.remove(); bar = null; }
  }

  function updateBar(item) {
    var phaseEl    = document.getElementById('demo-bar-phase');
    var descEl     = document.getElementById('demo-bar-desc');
    var fillEl     = document.getElementById('demo-progress-fill');
    var countEl    = document.getElementById('demo-bar-count');
    if (!phaseEl) return;

    phaseEl.textContent = item.phase;
    descEl.textContent  = item.desc;

    var pct = Math.round((index / (sequence.length - 1)) * 100);
    fillEl.style.width  = pct + '%';
    countEl.textContent = (index + 1) + '\u202f/\u202f' + sequence.length;
  }

  // ── Play button state ───────────────────────────────────────────────────────

  function updatePlayBtn(active) {
    var btn = document.getElementById('demo-play-btn');
    if (!btn) return;
    if (active) {
      btn.innerHTML = '&#9632; Stop Demo';
      btn.classList.add('demo-btn-active');
    } else {
      btn.innerHTML = '&#9654; Play Demo';
      btn.classList.remove('demo-btn-active');
    }
  }

  return { start: start, stop: stop };
})();
