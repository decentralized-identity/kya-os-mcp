/**
 * Shared consent page (the canonical example consent UI).
 *
 * Extracted from examples/consent-basic so every example's consent screen has a
 * consistent look. It is a single self-contained styled HTML document — no
 * external bundle, no dependencies — so it works for examples that have their own
 * npm package (consent-basic, consent-persistence) AND for ones that run off the
 * repo root (node-server). consent-full intentionally keeps the richer
 * @kya-os/consent production component as its showcase.
 *
 * The Approve button POSTs `{ tool, scopes, agentDid, resumeToken }` to
 * `approvePath` and adapts to whichever backend answers:
 *   - `{ delegationToken }` → shows the credential to copy/paste (VC flow:
 *      consent-basic, node-server).
 *   - `{ approved: true }` / `{ success: true }` → shows a "retry, no re-paste"
 *      message (holder-of-key flow: consent-persistence).
 */

export interface ConsentPageOptions {
  /** Tool the agent wants to call (display only). */
  tool: string;
  /** Comma-separated requested scopes (display only). */
  scopes: string;
  /** Agent DID requesting authorization (display only). */
  agentDid: string;
  /** Endpoint the Approve button POSTs to. Default '/approve'. */
  approvePath?: string;
}

/** Escape a user-controlled string for safe interpolation into HTML (text + attributes). */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Render the canonical consent page HTML. All reflected values are escaped.
 */
export function renderConsentPage(opts: ConsentPageOptions): string {
  const tool = escapeHtml(opts.tool);
  const scopes = escapeHtml(opts.scopes);
  const agentDid = escapeHtml(opts.agentDid);
  const approvePath = escapeHtml(opts.approvePath ?? '/approve');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KYA-OS Consent</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f1117; color: #e1e4e8; min-height: 100vh;
      display: flex; align-items: center; justify-content: center; padding: 1rem;
    }
    .card {
      background: #1c1f26; border: 1px solid #30363d; border-radius: 12px;
      padding: 2rem; max-width: 480px; width: 100%;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4);
    }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 1.5rem; color: #f0f6fc; }
    .field { margin-bottom: 1rem; }
    .field .label {
      display: block; font-size: 0.75rem; font-weight: 500; text-transform: uppercase;
      letter-spacing: 0.05em; color: #8b949e; margin-bottom: 0.25rem;
    }
    .field .value {
      font-size: 0.95rem; color: #c9d1d9; word-break: break-all;
      padding: 0.5rem 0.75rem; background: #161b22; border: 1px solid #21262d; border-radius: 6px;
    }
    .actions { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
    button {
      flex: 1; padding: 0.625rem 1rem; border: none; border-radius: 6px;
      font-size: 0.875rem; font-weight: 600; cursor: pointer; transition: opacity 0.15s;
    }
    button:hover { opacity: 0.9; }
    button:focus-visible { outline: 2px solid #58a6ff; outline-offset: 2px; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-approve { background: #238636; color: #fff; }
    .btn-deny { background: #da3633; color: #fff; }
    #status { margin-top: 1rem; padding: 0.75rem; border-radius: 6px; font-size: 0.85rem; display: none; }
    #status.success { display: block; background: #0d1117; border: 1px solid #238636; color: #3fb950; }
    #status.error { display: block; background: #0d1117; border: 1px solid #da3633; color: #f85149; }
    #status.denied { display: block; background: #0d1117; border: 1px solid #d29922; color: #e3b341; }
    #delegation-output { display: none; margin-top: 1rem; }
    #delegation-output textarea {
      width: 100%; min-height: 120px; background: #161b22; color: #c9d1d9;
      border: 1px solid #21262d; border-radius: 6px; padding: 0.5rem;
      font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; resize: vertical;
    }
    .btn-copy { background: #388bfd; color: #fff; margin-top: 0.5rem; }
  </style>
</head>
<body>
  <main class="card" role="dialog" aria-labelledby="consent-title">
    <h1 id="consent-title">Agent Consent Request</h1>

    <div class="field">
      <span class="label" id="label-tool">Tool</span>
      <div class="value" id="field-tool" aria-labelledby="label-tool">${tool}</div>
    </div>

    <div class="field">
      <span class="label" id="label-scopes">Requested Scopes</span>
      <div class="value" id="field-scopes" aria-labelledby="label-scopes">${scopes}</div>
    </div>

    <div class="field">
      <span class="label" id="label-agent">Agent DID</span>
      <div class="value" id="field-agent" aria-labelledby="label-agent">${agentDid}</div>
    </div>

    <div class="actions">
      <button class="btn-approve" id="btn-approve" type="button" aria-label="Approve delegation for this tool">Approve</button>
      <button class="btn-deny" id="btn-deny" type="button" aria-label="Deny delegation request">Deny</button>
    </div>

    <div id="status" role="alert" aria-live="polite"></div>

    <div id="delegation-output">
      <span class="label">Delegation Token</span>
      <textarea id="delegation-json" readonly aria-label="Delegation token JSON"></textarea>
      <button class="btn-copy" id="btn-copy" type="button">Copy to Clipboard</button>
    </div>
  </main>

  <script>
    (function () {
      var APPROVE_PATH = ${JSON.stringify(approvePath)};
      var tool = document.getElementById('field-tool').textContent;
      var scopes = document.getElementById('field-scopes').textContent;
      var agentDid = document.getElementById('field-agent').textContent;
      var resumeToken = new URLSearchParams(window.location.search).get('resume_token') || '';
      var statusEl = document.getElementById('status');
      var approveBtn = document.getElementById('btn-approve');
      var denyBtn = document.getElementById('btn-deny');

      function setStatus(msg, cls) { statusEl.textContent = msg; statusEl.className = cls; }

      approveBtn.addEventListener('click', function () {
        approveBtn.disabled = true; denyBtn.disabled = true;
        setStatus('Authorizing...', '');

        fetch(APPROVE_PATH, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tool: tool, scopes: scopes, agentDid: agentDid, resumeToken: resumeToken }),
        })
          .then(function (res) { return res.json(); })
          .then(function (data) {
            if (data.delegationToken) {
              // VC flow: show the credential to copy and re-paste into the tool call.
              setStatus('Delegation approved. Copy the credential below and retry the tool with "_kyaos_delegation".', 'success');
              var outputEl = document.getElementById('delegation-output');
              var jsonEl = document.getElementById('delegation-json');
              jsonEl.value = typeof data.delegationToken === 'string'
                ? data.delegationToken
                : JSON.stringify(data.delegationToken, null, 2);
              outputEl.style.display = 'block';
              document.getElementById('btn-copy').addEventListener('click', function () {
                jsonEl.select();
                navigator.clipboard.writeText(jsonEl.value).then(function () {
                  setStatus('Copied to clipboard!', 'success');
                });
              });
            } else if (data.approved || data.success) {
              // Holder-of-key flow: nothing to paste — the agent re-proves possession.
              setStatus('Approved. Retry the tool — no re-paste needed; your holder-of-key proof resolves the grant.', 'success');
            } else {
              setStatus('Error: ' + (data.message || data.error || 'Unknown error'), 'error');
              approveBtn.disabled = false; denyBtn.disabled = false;
            }
          })
          .catch(function (err) {
            setStatus('Network error: ' + err.message, 'error');
            approveBtn.disabled = false; denyBtn.disabled = false;
          });
      });

      denyBtn.addEventListener('click', function () {
        approveBtn.disabled = true; denyBtn.disabled = true;
        setStatus('Request denied. No authorization was issued.', 'denied');
      });

      approveBtn.focus();
    })();
  </script>
</body>
</html>`;
}
