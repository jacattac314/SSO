// === Main Navigation & Initialization ===
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    initNav();
    // Modules self-initialize via their own DOMContentLoaded or are called here
    if (window.Architecture) window.Architecture.init();
    if (window.Simulator) window.Simulator.init();
    if (window.Tokens) window.Tokens.init();
    if (window.Failures) window.Failures.init();
    if (window.Security) window.Security.init();
  });

  function initNav() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('panel-' + tab.dataset.panel);
        if (target) target.classList.add('active');
      });
    });
  }
})();
