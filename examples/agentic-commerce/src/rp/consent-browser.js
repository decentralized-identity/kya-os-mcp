// The package renders capabilities and owns selection. This adapter submits its
// decision to the RP after any required confirmation of the exact signed grant.
const bridge = JSON.parse(
  document.querySelector('#consent-ui-data').textContent,
);
const consent = document.querySelector('consent-capabilities-screen');
const status = document.querySelector('#decision-status');
const checkStatus = document.querySelector('#check-consent-status');
await customElements.whenDefined('consent-capabilities-screen');
consent.capabilities = bridge.capabilities;
consent.agentMetadata = bridge.agentMetadata;
consent.disabled = bridge.needsRegistration;
let busy = false;
let completed = false;
let requiresReconciliation = false;
const b64u = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
const bytes = (value) =>
  Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (char) =>
    char.charCodeAt(0),
  );

function updateControls() {
  consent.loading = busy || requiresReconciliation;
  checkStatus.hidden = !requiresReconciliation;
  checkStatus.disabled = busy;
}

function showResult(title, icon) {
  completed = true;
  requiresReconciliation = false;
  consent.hidden = true;
  const result = document.querySelector('#consent-result');
  result.hidden = false;
  result.querySelector('.result-icon').textContent = icon;
  document.querySelector('#result-title').textContent = title;
  document.querySelector('#result-feedback').append(document.querySelector('#decision-feedback'));
  document.querySelector('#close-consent-window').hidden = false;
  document.querySelector('#result-title').focus();
  window.scrollTo(0, 0);
}

function finishDecision(decision, human, passkeyConfirmed = false) {
  showResult(decision === 'approve' ? 'Grant issued' : 'Grant denied', decision === 'approve' ? '✓' : '×');
  status.dataset.state = 'success';
  status.textContent =
    decision === 'deny'
      ? 'Grant denied. No credential was issued.'
      : human && passkeyConfirmed
        ? `Grant issued. ${human.displayName || 'Your Google account'} → passkey confirmed → signed grant → Acme Shopping Agent. Retry the same order in Claude.`
        : 'Grant issued. Retry the same order in Claude.';
}

// A failed fetch can lose a committed decision. Read the token-bound record;
// never repeat the decision POST to discover whether it succeeded.
async function reconcileDecision() {
  requiresReconciliation = true;
  status.dataset.state = 'pending';
  status.textContent = 'Checking whether your decision was recorded…';
  try {
    const response = await fetch(
      `/consent/status?resume_token=${encodeURIComponent(bridge.fields.session_id)}`,
      { cache: 'no-store' },
    );
    const result = await response.json();
    if (!response.ok) throw new Error('Decision status is unavailable.');
    if (
      ['approved', 'consumed'].includes(result.state) &&
      typeof result.credentialId === 'string' &&
      result.credentialId.length > 0
    ) {
      finishDecision(
        'approve',
        result.demoConsent?.human,
        result.demoConsent?.authentication?.method === 'webauthn',
      );
    } else if (result.state === 'denied') {
      finishDecision('deny');
    } else if (['failed', 'expired'].includes(result.state)) {
      showResult('Request unavailable', '!');
      status.dataset.state = 'error';
      status.textContent =
        'This request cannot be completed. Request fresh authorization from the agent.';
    } else if (result.state === 'pending') {
      requiresReconciliation = false;
      status.textContent =
        'No decision is recorded yet. You can approve or deny this request.';
    } else {
      throw new Error('Decision status is not final.');
    }
  } catch {
    status.dataset.state = 'error';
    status.textContent =
      'Your decision could not be confirmed. Check decision status before trying anything else.';
  }
}

async function confirmGrant(decisionFields) {
  const response = await fetch('/consent/webauthn/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(decisionFields),
  });
  const request = await response.json();
  if (!response.ok) throw new Error(request.message || request.error);
  const actualHuman = request.intent?.human;
  const reviewedHuman = bridge.human;
  if (
    Boolean(actualHuman) !== Boolean(reviewedHuman) ||
    (reviewedHuman &&
      ['accountRef', 'provider', 'issuer', 'identitySource'].some(
        (field) =>
          typeof reviewedHuman[field] !== 'string' ||
          actualHuman[field] !== reviewedHuman[field],
      ))
  ) {
    throw new Error(
      'The signed-in account changed. Reload this page to review the grant for the current account.',
    );
  }
  request.options.challenge = bytes(request.options.challenge);
  request.options.allowCredentials = request.options.allowCredentials.map(
    (credential) => ({ ...credential, id: bytes(credential.id) }),
  );
  const assertion = await navigator.credentials.get({
    publicKey: request.options,
  });
  if (!assertion) throw new Error('No assertion received.');
  return {
    human: actualHuman,
    fields: {
      webauthn_nonce: request.nonce,
      webauthn_response: JSON.stringify({
        id: assertion.id,
        rawId: b64u(assertion.rawId),
        type: assertion.type,
        clientExtensionResults: assertion.getClientExtensionResults(),
        response: {
          clientDataJSON: b64u(assertion.response.clientDataJSON),
          authenticatorData: b64u(assertion.response.authenticatorData),
          signature: b64u(assertion.response.signature),
          userHandle: assertion.response.userHandle
            ? b64u(assertion.response.userHandle)
            : null,
        },
      }),
    },
  };
}

async function decide(decision, selectedScopes) {
  if (busy || completed || requiresReconciliation) return;
  busy = true;
  updateControls();
  status.dataset.state = 'pending';
  status.textContent = '';
  let submitted = false;
  try {
    const decisionFields = {
      ...bridge.fields,
      ...(decision === 'approve' ? { selected_scopes: JSON.stringify(selectedScopes) } : {}),
    };
    const confirmation =
      decision === 'approve' && bridge.webauthnRequired
        ? await confirmGrant(decisionFields)
        : { fields: {} };
    const form = new FormData();
    for (const [name, value] of Object.entries({
      ...decisionFields,
      ...confirmation.fields,
    }))
      form.append(name, value);
    submitted = true;
    const response = await fetch(`/consent/${decision}`, {
      method: 'POST',
      body: form,
    });
    const result = await response.json();
    if (
      !response.ok ||
      result.success !== true ||
      (decision === 'approve' &&
        (typeof result.delegation_id !== 'string' || !result.delegation_id))
    )
      throw new Error(
        result.message || result.error || 'The decision could not be saved.',
      );
    finishDecision(decision, confirmation.human, bridge.webauthnRequired);
  } catch (error) {
    if (submitted) {
      await reconcileDecision();
    } else {
      status.dataset.state = 'error';
      status.textContent = ['AbortError', 'NotAllowedError'].includes(
        error.name,
      )
        ? 'Passkey confirmation did not complete. No grant was issued. Try again.'
        : error.message || 'Approval cancelled. You can try again.';
    }
  } finally {
    busy = false;
    updateControls();
  }
}

checkStatus.addEventListener('click', async () => {
  if (busy || completed || !requiresReconciliation) return;
  busy = true;
  updateControls();
  try {
    await reconcileDecision();
  } finally {
    busy = false;
    updateControls();
  }
});

consent.addEventListener('capabilities-allow', async (event) => {
  if (busy || completed || requiresReconciliation) return;
  const selected = event.detail?.selectedScopes;
  const expected = JSON.parse(bridge.fields.scopes);
  if (
    !Array.isArray(selected) ||
    selected.length === 0 ||
    new Set(selected).size !== selected.length ||
    !selected.every((scope) => typeof scope === 'string' && expected.includes(scope))
  ) {
    status.dataset.state = 'error';
    status.textContent = 'Select the order permission to approve this grant.';
    return;
  }
  if (bridge.needsRegistration) {
    status.textContent =
      'Register a passkey for this Google account, then reload this consent page.';
    return;
  }
  await decide('approve', [...selected]);
});
consent.addEventListener('capabilities-deny', () => decide('deny'));

document.querySelector('#close-consent-window').addEventListener('click', () => {
  window.close();
  // A normal tab may disallow script closing. Return it to the console instead.
  setTimeout(() => window.location.replace(document.querySelector('#return-to-demo').href), 150);
});
