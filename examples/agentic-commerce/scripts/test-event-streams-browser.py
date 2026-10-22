#!/usr/bin/env python3
"""Real SharedWorker/EventSource recovery against isolated, controllable HTTP SSE.

Requires Playwright and Chromium, like test-consent-webauthn.py. No demo state,
keys, accounts or live server are used. --worker-script can verify an old build.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
PAGE = b'''<!doctype html><meta charset="utf-8"><title>Shared stream recovery fixture</title>
<style>body{font:20px system-ui;background:#101310;color:#f1f4f1;padding:32px}pre{white-space:pre-wrap}h1{font-size:28px}</style>
<h1>Shared stream recovery fixture</h1><p>Actual Chromium SharedWorker and EventSource</p><pre id="events"></pre>
<script>
window.received=[];
const feed=new URL(location.href).searchParams.get('feed');
const url=new URL('/events?feed='+encodeURIComponent(feed),location.href).href;
const worker=new SharedWorker('/event-streams.js',{name:'isolated-merchant-monitor'});
worker.port.onmessage=({data})=>{received.push(data);document.querySelector('#events').textContent=JSON.stringify(received,null,2)};
worker.port.start();worker.port.postMessage({type:'subscribe',url});
addEventListener('pagehide',()=>{worker.port.postMessage({type:'disconnect'});worker.port.close()});
</script>'''


class Fixture:
    def __init__(self, worker):
        self.worker = worker
        self.lock = threading.Lock()
        self.feeds = {}

    def feed(self, name):
        return self.feeds.setdefault(name, {'mode': 'open', 'requests': 0, 'fatalResponses': 0, 'clients': set()})

    def snapshot(self, name):
        with self.lock:
            feed = self.feed(name)
            return {key: value for key, value in feed.items() if key != 'clients'} | {'active': len(feed['clients'])}

    def mode(self, name, mode, disconnect=False):
        with self.lock:
            feed = self.feed(name)
            feed['mode'] = mode
            if disconnect:
                for client in feed['clients']:
                    client.put(None)

    def send(self, name, value):
        with self.lock:
            for client in self.feed(name)['clients']:
                client.put(value)


def handler_for(fixture):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def body(self, status, content_type, body):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == '/':
                return self.body(200, 'text/html', PAGE)
            if url.path == '/event-streams.js':
                return self.body(200, 'text/javascript', fixture.worker)
            if url.path != '/events':
                return self.body(404, 'text/plain', b'Not found')
            name = parse_qs(url.query)['feed'][0]
            client = queue.Queue()
            with fixture.lock:
                feed = fixture.feed(name)
                feed['requests'] += 1
                mode = feed['mode']
                if mode != 'open':
                    feed['fatalResponses'] += 1
                else:
                    feed['clients'].add(client)
            if mode == '503':
                return self.body(503, 'text/plain', b'Simulated deploy unavailable')
            if mode == 'mime':
                return self.body(200, 'text/html', b'Simulated proxy error page')
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                self.wfile.write(b'retry: 100\n\n')
                self.wfile.flush()
                while True:
                    try:
                        value = client.get(timeout=.5)
                    except queue.Empty:
                        self.wfile.write(b': heartbeat\n\n')
                        self.wfile.flush()
                        continue
                    if value is None:
                        break
                    self.wfile.write(('data: ' + json.dumps(value) + '\n\n').encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with fixture.lock:
                    fixture.feed(name)['clients'].discard(client)
                self.close_connection = True
    return Handler


async def until(predicate, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await predicate():
            return True
        await asyncio.sleep(.05)
    return False


async def run(fixture, origin, output):
    report = {'ok': False, 'workerSha256': hashlib.sha256(fixture.worker).hexdigest(), 'scenarios': []}
    async with async_playwright() as playwright:
        executable = os.environ.get('CHROMIUM')
        browser = await playwright.chromium.launch(headless=True, **({'executable_path': executable} if executable else {}))
        report['browser'] = browser.version
        for name, failure, late_subscriber in [('transient', None, False), ('fatal-503', '503', False), ('fatal-mime-new-tab', 'mime', True)]:
            context = await browser.new_context(viewport={'width': 1000, 'height': 720})
            pages = [await context.new_page(), await context.new_page()]
            for page in pages:
                await page.goto(origin + '/?feed=' + name)
            async def all_open():
                return all(await asyncio.gather(*[page.evaluate("received.some(event=>event.type==='open')") for page in pages]))
            assert await until(all_open), f'{name}: initial SharedWorker connection did not open'
            initial = fixture.snapshot(name)
            assert initial['requests'] == 1, f'{name}: tabs did not share one EventSource: {initial}'
            fixture.send(name, {'phase': 'before'})
            async def all_received(phase):
                return all(await asyncio.gather(*[page.evaluate("phase=>received.some(event=>event.type==='message'&&JSON.parse(event.data).phase===phase)", phase) for page in pages]))
            assert await until(lambda: all_received('before')), f'{name}: initial broadcast lost'
            fixture.mode(name, failure or 'open', disconnect=True)
            if failure:
                async def fatal_seen():
                    return fixture.snapshot(name)['fatalResponses'] > 0
                assert await until(fatal_seen), f'{name}: fatal response was not delivered'
            else:
                async def reconnected():
                    return fixture.snapshot(name)['requests'] > 1 and fixture.snapshot(name)['active'] == 1
                assert await until(reconnected), 'Native transient retry did not reconnect'
            at_failure = fixture.snapshot(name)
            recovered_at = time.monotonic()
            fixture.mode(name, 'open')
            if late_subscriber:
                page = await context.new_page()
                pages.append(page)
                await page.goto(origin + '/?feed=' + name)
            async def delivered_after():
                fixture.send(name, {'phase': 'after'})
                return await all_received('after')
            recovered = await until(delivered_after)
            after = fixture.snapshot(name)
            for index, page in enumerate(pages):
                if index == 0:
                    await page.screenshot(path=str(output / (name + '.png')), full_page=True)
            scenario = {'name': name, 'recoveredWithoutReload': recovered, 'tabs': len(pages), 'initial': initial, 'atFailure': at_failure, 'after': after, 'recoveryMs': round((time.monotonic() - recovered_at) * 1000), 'tabEvents': [await page.evaluate('received') for page in pages]}
            report['scenarios'].append(scenario)
            await context.close()
        await browser.close()
    report['ok'] = all(scenario['recoveredWithoutReload'] and scenario['after']['active'] == 1 for scenario in report['scenarios'])
    (output / 'event-stream-browser-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    assert report['ok'], 'One or more real browser feeds failed to recover; see event-stream-browser-report.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-script', type=Path, default=ROOT / 'web/event-streams.js')
    parser.add_argument('--outdir', type=Path, required=True)
    args = parser.parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)
    fixture = Fixture(args.worker_script.read_bytes())
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(fixture))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        asyncio.run(run(fixture, f'http://127.0.0.1:{server.server_port}', args.outdir))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
