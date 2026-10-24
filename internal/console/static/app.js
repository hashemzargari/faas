// FASS console — the only JavaScript we write. HTMX does the polling and the
// object drawer; this file turns data-confirm attributes into a native confirm
// dialog so destructive writes need a second click, and disables htmx's eval
// (our CSP does not allow unsafe-eval).
(function () {
  'use strict';

  if (window.htmx && window.htmx.config) {
    // We never use hx-on:/js: expressions, so eval is not needed.
    window.htmx.config.allowEval = false;
    window.htmx.config.historyCacheSize = 0;
  }

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || !form.getAttribute) return;
    var message = form.getAttribute('data-confirm');
    if (message && !window.confirm(message)) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  });

  // Show a subtle "updating" hint when htmx issues a request.
  document.addEventListener('htmx:beforeRequest', function (event) {
    var target = event.target;
    if (target && target.classList) target.classList.add('htmx-busy');
  });
  document.addEventListener('htmx:afterRequest', function (event) {
    var target = event.target;
    if (target && target.classList) target.classList.remove('htmx-busy');
  });
})();
