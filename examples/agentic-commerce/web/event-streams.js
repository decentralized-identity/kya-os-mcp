/* One EventSource per endpoint across all monitor tabs. HTTP/1.1 browsers
 * otherwise exhaust their per-origin connection pool after six open monitors. */
const feeds = new Map();
const memberships = new Map();
const INITIAL_RETRY_MS = 500;
const MAX_RETRY_MS = 10_000;

const active = feed => feeds.get(feed.url) === feed && feed.ports.size > 0;

function disconnect(port) {
  for (const url of memberships.get(port) || []) unsubscribe(port, url);
  memberships.delete(port);
  port.onmessage = null;
}

function send(port, message) {
  try { port.postMessage(message); }
  catch { disconnect(port); }
}

function broadcast(feed, type, data) {
  for (const port of feed.ports) send(port, { url: feed.url, type, data });
}

function retry(feed) {
  if (!active(feed) || feed.timer !== null) return;
  // Native EventSource owns transient reconnects. Only CLOSED is permanent.
  if (feed.source && feed.source.readyState !== EventSource.CLOSED) return;
  feed.timer = setTimeout(() => {
    feed.timer = null;
    if (active(feed) && (!feed.source || feed.source.readyState === EventSource.CLOSED)) connect(feed);
  }, feed.delay);
  feed.delay = Math.min(feed.delay * 2, MAX_RETRY_MS);
}

function connect(feed) {
  if (!active(feed)) return;
  const previous = feed.source;
  feed.source = null;
  feed.open = false;
  previous?.close();
  let source;
  try { source = new EventSource(feed.url); }
  catch { broadcast(feed, 'error'); retry(feed); return; }
  feed.source = source;
  // Queued callbacks from an old connection must not affect its replacement.
  const current = () => active(feed) && feed.source === source;
  source.onopen = () => {
    if (!current()) return;
    feed.open = true;
    feed.delay = INITIAL_RETRY_MS;
    if (feed.timer !== null) { clearTimeout(feed.timer); feed.timer = null; }
    broadcast(feed, 'open');
  };
  source.onerror = () => {
    if (!current()) return;
    feed.open = false;
    broadcast(feed, 'error');
    retry(feed);
  };
  source.onmessage = event => { if (current()) broadcast(feed, 'message', event.data); };
}

function unsubscribe(port, url) {
  memberships.get(port)?.delete(url);
  const feed = feeds.get(url);
  if (!feed) return;
  feed.ports.delete(port);
  if (!feed.ports.size) {
    feeds.delete(url);
    if (feed.timer !== null) clearTimeout(feed.timer);
    feed.source?.close();
  }
}

self.onconnect = ({ ports: [port] }) => {
  memberships.set(port, new Set());
  port.onmessage = ({ data }) => {
    if (!data || typeof data !== 'object' || !memberships.has(port)) return;
    if (data.type === 'disconnect') {
      disconnect(port);
      return;
    }
    const url = data.url;
    if (typeof url !== 'string') return;
    if (data.type === 'unsubscribe') { unsubscribe(port, url); return; }
    if (data.type !== 'subscribe') return;
    memberships.get(port)?.add(url);
    let feed = feeds.get(url);
    if (!feed) {
      feed = { url, source: null, ports: new Set([port]), open: false, timer: null, delay: INITIAL_RETRY_MS };
      feeds.set(url, feed);
      connect(feed);
      return;
    }
    feed.ports.add(port);
    if (feed.source?.readyState === EventSource.OPEN && feed.open) send(port, { url, type: 'open' });
    else {
      feed.open = false;
      // A new or repeated subscription can discover a missed fatal error.
      // Reuse an already scheduled retry so extra tabs cannot create a storm.
      retry(feed);
    }
  };
  port.start();
};
