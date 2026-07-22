const observedRoots = new WeakSet();
const handledSubmitEvents = new WeakSet();

function elementInComposedPath(event, selector) {
  return event.composedPath().find((entry) => entry instanceof Element && entry.matches(selector)) || null;
}

async function submitReplicaForm(event) {
  if (handledSubmitEvents.has(event)) return;
  handledSubmitEvents.add(event);
  event.preventDefault();
  const form = elementInComposedPath(event, 'form') || event.target;
  if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
  const payload = new FormData(form);
  payload.set('__replica_synthetic_canary', 'replica-synthetic-canary-v1');

  const response = await fetch('/api/applications', {
    method: 'POST',
    headers: {
      'x-idempotency-key': 'synthetic-browser-run',
      'x-replica-fixture': 'synthetic-browser-run-v1'
    },
    body: payload
  });
  const receipt = await response.json();
  form.dispatchEvent(new CustomEvent('replica:submitted', { detail: receipt }));
}

function handleReplicaClick(event) {
  const sourceLink = elementInComposedPath(event, '[data-replica-source-link]');
  if (sourceLink) {
    event.preventDefault();
    return;
  }
  const control = elementInComposedPath(event, 'button, input[type="button"], [role="button"]');
  if (!control || !/submit|apply|send|complete|continue/i.test(control.getAttribute('aria-label') || control.textContent || control.value || '')) return;
  const form = control.closest('form');
  if (!form || control.type === 'submit') return;
  event.preventDefault();
  form.requestSubmit();
}

function observeReplicaRoot(root) {
  if (!root || observedRoots.has(root)) return;
  observedRoots.add(root);
  root.addEventListener('submit', submitReplicaForm);
  for (const element of root.querySelectorAll('*')) {
    if (element.shadowRoot) observeReplicaRoot(element.shadowRoot);
  }
  new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (!(node instanceof Element)) continue;
        if (node.shadowRoot) observeReplicaRoot(node.shadowRoot);
        for (const element of node.querySelectorAll('*')) {
          if (element.shadowRoot) observeReplicaRoot(element.shadowRoot);
        }
      }
    }
  }).observe(root, { childList: true, subtree: true });
}

document.addEventListener('click', handleReplicaClick);
observeReplicaRoot(document);

const nativeAttachShadow = Element.prototype.attachShadow;
Object.defineProperty(Element.prototype, 'attachShadow', {
  configurable: true,
  writable: true,
  value(init) {
    const root = nativeAttachShadow.call(this, init);
    if (init?.mode === 'open') observeReplicaRoot(root);
    return root;
  }
});
