#!/usr/bin/env python3
"""Exercise real browser WebAuthn using a Chromium virtual FIDO2 authenticator.

The test starts isolated RP/merchant ports, creates temporary test keys, uses the
existing registration page and actual consent Approve grant button, then checks
MCP allow, software revoke, revoked denial and the witnessed audit bundle.
It never reads or changes the stage's credentials or running servers.
Requires Python playwright and Chromium; CHROMIUM may select an installed Chrome.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.request import urlopen
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect
from browser_consent import APPROVE, DENY, SCREEN, assert_capability_consent, assert_mobile_consent

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--outdir', default=None)
parser.add_argument('--passkey-revocation', action='store_true', help='Exercise passkey revocation, cancellation, replay rejection and lost-response recovery.')
parser.add_argument('--google-identity', action='store_true', help='Use a fictional signed Google ID-token fixture with real server cryptographic verification, then real browser WebAuthn.')
args = parser.parse_args()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


DECISION_HEIGHTS = {}


async def assert_console_layout(page, output=None, screenshot_name=None):
    """Exercise native and wider system-font metrics at every viewport/state."""
    for font in [None, 'Verdana, sans-serif']:
        if font:
            await page.locator('body').evaluate("(node, font) => node.style.setProperty('--sans', font)", font)
        try:
            name = f'{screenshot_name}-wide-font' if font and screenshot_name else screenshot_name
            await _assert_console_layout(page, output, name)
        finally:
            if font:
                await page.locator('body').evaluate("node => node.style.removeProperty('--sans')")


async def _assert_console_layout(page, output=None, screenshot_name=None):
    """Measure the actual rendered monitor, including every final decision state."""
    assert await page.locator('.controls button').evaluate_all('nodes => nodes.map(node => node.id)') == [
        'btn-discover', 'btn-order', 'btn-wrong', 'btn-overcap', 'btn-retry', 'btn-steal',
        'btn-revoke', 'btn-verify', 'btn-reset'], 'Fallback controls must follow their numbered sequence'
    assert await page.locator('.grant-panel .audit-actions button').evaluate_all('nodes => nodes.map(node => node.id)') == [
        'btn-audit', 'btn-tamper', 'btn-export'], 'Audit controls must put Show audit and Insider edit before Export bundle'
    controls = ['btn-order', 'btn-retry', 'btn-revoke', 'btn-wrong', 'btn-overcap',
                'btn-steal', 'btn-discover', 'btn-verify', 'btn-reset',
                'btn-audit', 'btn-tamper', 'btn-export']
    for width, height in [(1440, 900), (1280, 720), (1150, 900), (1024, 900), (901, 900), (820, 900), (640, 900)]:
        await page.set_viewport_size({'width': width, 'height': height})
        decision_box = await page.locator('.decision-panel').bounding_box()
        grant_box = await page.locator('.grant-panel').bounding_box()
        grant_body = await page.locator('.grant-panel .panel-body').bounding_box()
        audit_controls = await page.locator('.audit-controls').bounding_box()
        assert audit_controls['y'] >= grant_body['y'] + grant_body['height'], 'Audit controls overlap the credential viewport'
        if width >= 1280:
            show = await page.locator('#btn-audit').bounding_box()
            edit = await page.locator('#btn-tamper').bounding_box()
            export = await page.locator('#btn-export').bounding_box()
            assert abs(show['y'] - edit['y']) <= 1 and show['x'] + show['width'] < edit['x'], 'Show audit and Insider edit must share the top row'
            assert export['y'] >= max(show['y'] + show['height'], edit['y'] + edit['height']), 'Export bundle must sit below both audit actions'
            assert abs(export['x'] - show['x']) <= 1 and abs(export['x'] + export['width'] - edit['x'] - edit['width']) <= 1, 'Export bundle must span the full lower row'
        event_box = await page.locator('.event-panel').bounding_box()
        assert grant_box['x'] + grant_box['width'] < decision_box['x'], f'Delegation is not left of decision at {width}x{height}: {grant_box}, {decision_box}'
        assert grant_box['x'] + grant_box['width'] < event_box['x'], f'Delegation overlaps event feed at {width}x{height}: {grant_box}, {event_box}'
        assert abs(grant_box['y'] - decision_box['y']) <= 1, f'Delegation does not start beside decision at {width}x{height}'
        assert abs(grant_box['y'] + grant_box['height'] - event_box['y'] - event_box['height']) <= 1, f'Delegation does not span decision and logs at {width}x{height}'
        assert abs(decision_box['x'] - event_box['x']) <= 1 and abs(decision_box['width'] - event_box['width']) <= 1, f'Decision and logs do not share the right column at {width}x{height}'
        assert decision_box['y'] + decision_box['height'] < event_box['y'], f'Decision overlaps event feed at {width}x{height}'
        expected_height = DECISION_HEIGHTS.setdefault((width, height), decision_box['height'])
        assert abs(decision_box['height'] - expected_height) <= 1, f'Decision card shifted at {width}x{height}: {decision_box["height"]} vs {expected_height}'
        assert await page.locator('.decision-panel').evaluate('node => getComputedStyle(node).borderLeftWidth') == '0px', 'Decision card left border returned'
        displayed_code = (await page.locator('#verdict-code').inner_text()).strip()
        for control in controls + ['seal', 'log'] + (['verdict-code'] if displayed_code else []):
            element = page.locator('#' + control)
            await expect(element).to_be_visible()
            box = await element.bounding_box()
            assert box and box['x'] >= 0 and box['x'] + box['width'] <= width and box['y'] >= 0 and box['y'] + box['height'] <= height, f'{control} outside {width}x{height}: {box}'
            if control in controls:
                assert await element.evaluate("""element => {
                  const box = element.getBoundingClientRect();
                  const top = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
                  return top && (element === top || element.contains(top));
                }"""), f'{control} clipped or covered at {width}x{height}'
        assert await page.evaluate('document.documentElement.scrollHeight <= innerHeight'), f'Page scroll at {width}x{height}'
        icon_alignment = await page.evaluate("""() => {
          const icon = document.querySelector('#decision-symbol').getBoundingClientRect();
          const title = document.querySelector('.decision-heading').getBoundingClientRect();
          return Math.abs(icon.top + icon.height / 2 - title.top - title.height / 2);
        }""")
        assert icon_alignment < 1, f'Decision icon is not centered on the headline at {width}x{height}: {icon_alignment}px'
        aligned_heading = await page.evaluate("""() => {
          const rect = selector => document.querySelector(selector).getBoundingClientRect();
          const label = rect('.credential-frame legend span');
          const title = rect('.credential-type');
          const field = rect('.scope-actions .k');
          return Math.abs(label.left - field.left) < 1 && Math.abs(title.left - field.left) < 1
            && title.top >= label.bottom;
        }""")
        assert aligned_heading, f'Credential heading is misaligned at {width}x{height}'
        for selector in ['#seal', '#verdict-code']:
            text_fits = await page.locator(selector).evaluate("""element => {
              const panel = element.closest('.decision-panel').getBoundingClientRect();
              const text = document.createRange();
              text.selectNodeContents(element);
              return [...text.getClientRects()].every(box => box.left >= panel.left && box.right <= panel.right && box.top >= panel.top && box.bottom <= panel.bottom);
            }""")
            assert text_fits, f'{selector} text clipped outside decision at {width}x{height}'
        decision_collisions = await page.locator('.decision-panel').evaluate("""panel => {
          const groups = [...panel.querySelectorAll('#seal, #decision-summary, #verdict-code, #verdict-context, #verdict-note, #authorization-link, .g-name')]
            .filter(element => element.getClientRects().length && element.textContent.trim())
            .map(element => ({name: element.id || element.textContent.trim(), rects: [...element.getClientRects()]}));
          const overlaps = (a, b) => Math.min(a.right, b.right) - Math.max(a.left, b.left) > .5 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > .5;
          return groups.flatMap((group, index) => groups.slice(index + 1)
            .filter(other => group.rects.some(a => other.rects.some(b => overlaps(a, b))))
            .map(other => [group.name, other.name]));
        }""")
        if decision_collisions and (output or args.outdir):
            failure_output = output or Path(args.outdir)
            await page.screenshot(path=str(failure_output / f'console-overlap-{width}x{height}.png'), full_page=True)
        assert not decision_collisions, f'Decision text overlaps at {width}x{height}: {decision_collisions}'
        if width >= 1280 and (await page.locator('#c-cap').inner_text()).strip() != '—':
            for selector in ['.credential-frame', '.credential-frame legend', '#c-action-scopes', '#c-scope', '#c-cap', '#c-until', '#bit'] + (['#c-human'] if args.google_identity else []):
                element = page.locator(selector)
                await expect(element).to_be_visible()
                visible_in_panel = await element.evaluate("""element => {
                  const box = element.getBoundingClientRect();
                  const viewport = element.closest('.panel-body').getBoundingClientRect();
                  return box.left >= viewport.left && box.right <= viewport.right && box.top >= viewport.top && box.bottom <= viewport.bottom;
                }""")
                if not visible_in_panel and (output or args.outdir):
                    failure_output = output or Path(args.outdir)
                    await page.screenshot(path=str(failure_output / f'console-delegation-clipped-{width}x{height}.png'), full_page=True)
                    metrics = await page.locator('.grant-panel').evaluate("""panel => Object.fromEntries(['.panel-head', '.panel-body', '.human-grant', '.credential-frame', '.audit-controls'].map(selector => {
                      const node = panel.querySelector(selector), box = node.getBoundingClientRect();
                      return [selector, {top: box.top, bottom: box.bottom, height: box.height, scrollHeight: node.scrollHeight, font: getComputedStyle(node).fontFamily}];
                    }))""")
                    (failure_output / f'console-delegation-clipped-{width}x{height}.json').write_text(json.dumps(metrics, indent=2))
                assert visible_in_panel, f'Core delegation field {selector} requires scrolling at {width}x{height}'
        log_box = await page.locator('#log').bounding_box()
        assert log_box['height'] >= 180, f'Log too small at {width}x{height}: {log_box}'
        sizes = await page.evaluate("""() => ({
          action: parseFloat(getComputedStyle(document.querySelector('#btn-order')).fontSize),
          log: parseFloat(getComputedStyle(document.querySelector('#log')).fontSize),
          decision: parseFloat(getComputedStyle(document.querySelector('#seal')).fontSize),
          code: parseFloat(getComputedStyle(document.querySelector('#verdict-code')).fontSize)
        })""")
        assert sizes['action'] >= 16 and sizes['log'] >= 18, (width, height, sizes)
        assert sizes['decision'] >= (60 if width >= 1280 else 40), (width, height, sizes)
        assert sizes['code'] >= (24 if width >= 901 else 20), (width, height, sizes)
        contrast = await page.evaluate("""() => {
          const rgba = value => {
            const values = value.match(/[\\d.]+/g).map(Number);
            return [...values.slice(0, 3), values[3] ?? 1];
          };
          const over = (top, bottom) => [0, 1, 2].map(i => top[i] * top[3] + bottom[i] * (1 - top[3]));
          const background = element => {
            const ancestors = [];
            for (let node = element; node; node = node.parentElement) ancestors.push(node);
            return ancestors.reverse().reduce((paint, node) => over(rgba(getComputedStyle(node).backgroundColor), paint), [255, 255, 255]);
          };
          const luminance = rgb => rgb.map(value => value / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4)
            .reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
          const selectors = ['body', '#seal', '#verdict-code', '#log', '#log .log-message', '#log .log-message *'];
          return selectors.flatMap(selector => [...document.querySelectorAll(selector)].filter(element => element.getClientRects().length && element.textContent.trim()).map(element => {
            const back = background(element);
            const text = over(rgba(getComputedStyle(element).color), back);
            const light = [luminance(back), luminance(text)].sort((a, b) => a - b);
            return {selector, text: element.textContent.trim().slice(0, 90), ratio: (light[1] + .05) / (light[0] + .05)};
          }));
        }""")
        assert contrast and all(item['ratio'] >= 7 for item in contrast), {'viewport': [width, height], 'lowContrast': [item for item in contrast if item['ratio'] < 7]}
        if output and screenshot_name:
            await page.screenshot(path=str(output / f'{screenshot_name}-{width}x{height}.png'), full_page=True)
    log_icons = await page.locator('#log').evaluate("""node => ({
      rows: node.querySelectorAll('.log-line').length,
      icons: node.querySelectorAll('.log-line svg.log-icon[aria-hidden="true"]').length,
      emoji: /[\\p{Emoji_Presentation}\\uFE0F]/u.test(node.textContent)
    })""")
    assert log_icons['icons'] == log_icons['rows'] and not log_icons['emoji'], log_icons
    await page.set_viewport_size({'width': 390, 'height': 844})
    assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile horizontal overflow'
    code_size = await page.locator('#verdict-code').evaluate('node => parseFloat(getComputedStyle(node).fontSize)')
    assert code_size >= 18, f'Mobile decision code too small: {code_size}'
    await page.set_viewport_size({'width': 1440, 'height': 900})


async def assert_decision_motion(context, merchant, output):
    """Check actual decryption frames with controlled SSE; send no merchant action."""
    page = await context.new_page()
    await page.add_init_script("""(() => {
      window.SharedWorker = undefined;
      window.__motionStreams = {};
      window.__initialReadyDecode = false;
      new MutationObserver(() => {
        if (document.querySelector('#seal')?.textContent === 'READY' &&
            document.querySelector('.decision-heading')?.classList.contains('is-decoding') &&
            document.querySelector('#decision-decrypt .decrypt-letter')) window.__initialReadyDecode = true;
      }).observe(document, {subtree: true, childList: true, attributes: true});
      window.EventSource = class {
        constructor(url) { window.__motionStreams[url] = this; }
        close() {}
      };
      window.__motionEvent = event => window.__motionStreams['/api/events'].onmessage({data: JSON.stringify(event)});
      window.__decisionGeometry = () => Object.fromEntries(['#seal', '#decision-stage', '.decision-panel'].map(selector => {
        const box = document.querySelector(selector).getBoundingClientRect();
        return [selector, {x: box.x, y: box.y, width: box.width, height: box.height}];
      }));
    })()""")
    try:
        await page.goto(merchant + '/', wait_until='domcontentloaded')
        await page.wait_for_function("Object.keys(window.__motionStreams).length === 2")
        assert await page.evaluate('window.__initialReadyDecode'), 'Initial READY must receive the same decryption effect'
        await expect(page.locator('#decision-cursor')).to_have_text('_')
        await expect(page.locator('#decision-cursor')).to_have_attribute('aria-hidden', 'true')
        assert not await page.locator('#decision-cursor').evaluate('node => node.hidden'), 'READY cursor is missing'
        cursor_style = await page.locator('#decision-cursor').evaluate("""node => ({
          name: getComputedStyle(node).animationName,
          timing: getComputedStyle(node).animationTimingFunction,
          duration: getComputedStyle(node).animationDuration
        })""")
        assert cursor_style['name'] != 'none' and cursor_style['timing'] in ['step-end', 'steps(1)'] and cursor_style['duration'] == '1.2s', cursor_style
        request = {'type': 'request', 'product': 'risotto', 'quantity': 2}
        refusal = {'type': 'verdict', 'verdict': 'denied', 'code': 'PRODUCT_OUT_OF_SCOPE', 'body': {'detail': {}}}
        await page.evaluate('event => window.__motionEvent(event)', request)
        await expect(page.locator('#decision-stage')).to_have_attribute('aria-busy', 'true')
        await expect(page.locator('#seal')).to_have_text('VERIFYING')
        assert await page.locator('#decision-cursor').evaluate('node => node.hidden'), 'READY cursor must disappear during verification'
        animation = await page.locator('.processing-ring').evaluate("node => getComputedStyle(node).animationName")
        assert animation != 'none', 'The pending verification ring must animate'
        assert await page.locator('.processing-dot').count() == 3
        await assert_console_layout(page)
        await page.screenshot(path=str(output / 'console-processing.png'), full_page=True)
        # Even a request and result delivered in the same JS frame get the cue.
        result = await page.evaluate("""events => {
          for (const event of events) window.__motionEvent(event);
          window.__previousLetters = [...document.querySelectorAll('#decision-decrypt .decrypt-letter')];
          window.__decodingGeometry = window.__decisionGeometry();
          return {
            headline: document.querySelector('#seal').textContent,
            code: document.querySelector('#verdict-code').textContent,
            busy: document.querySelector('#decision-stage').getAttribute('aria-busy'),
            spinners: document.querySelectorAll('.processing-ring').length,
            cursorHidden: document.querySelector('#decision-cursor').hidden,
            letters: window.__previousLetters.length
          };
        }""", [request, refusal])
        assert result == {'headline': 'REFUSED', 'code': 'PRODUCT_OUT_OF_SCOPE', 'busy': 'false', 'spinners': 0, 'cursorHidden': True, 'letters': 7}, result
        await page.wait_for_timeout(160)
        visible = await page.evaluate("""() => {
          const overlay = document.querySelector('#decision-decrypt');
          const text = document.querySelector('#seal');
          return {
            decoding: text.parentElement.classList.contains('is-decoding'),
            hidden: overlay.hidden,
            ariaHidden: overlay.getAttribute('aria-hidden'),
            glyphs: overlay.textContent,
            glitchWidths: [...overlay.querySelectorAll('.glitching')].map(letter => {
              const range = document.createRange();
              range.selectNodeContents(letter);
              return {glyph: letter.textContent, text: range.getBoundingClientRect().width, box: letter.getBoundingClientRect().width};
            }),
            textOpacity: Number(getComputedStyle(text).opacity),
            verticalTransforms: ['#seal', '#decision-copy', '#decision-decrypt'].map(selector => getComputedStyle(document.querySelector(selector)).transform),
            geometry: window.__decisionGeometry(),
            originalGeometry: window.__decodingGeometry
          };
        }""")
        assert visible['decoding'] and not visible['hidden'] and visible['ariaHidden'] == 'true' and visible['glyphs'] != 'REFUSED', visible
        assert visible['textOpacity'] == 0 and all(transform == 'none' for transform in visible['verticalTransforms']), visible
        assert visible['geometry'] == visible['originalGeometry'], visible
        assert visible['glitchWidths'] and all(glyph['text'] <= glyph['box'] + 1 for glyph in visible['glitchWidths']), visible['glitchWidths']
        await page.screenshot(path=str(output / 'console-decrypting.png'), full_page=True)
        replay = await page.evaluate("""event => {
          window.__motionEvent(event);
          const letters = [...document.querySelectorAll('#decision-decrypt .decrypt-letter')];
          return {restarted: letters.length === 7 && letters.every(letter => !window.__previousLetters.includes(letter)),
            oldDetached: window.__previousLetters.every(letter => !letter.isConnected),
            headline: document.querySelector('#seal').textContent};
        }""", refusal)
        assert replay == {'restarted': True, 'oldDetached': True, 'headline': 'REFUSED'}, replay
        await page.wait_for_function("!document.querySelector('.decision-heading').classList.contains('is-decoding')", timeout=1500)
        settled = await page.evaluate("""() => ({
          headline: document.querySelector('#seal').textContent,
          overlayHidden: document.querySelector('#decision-decrypt').hidden,
          textOpacity: Number(getComputedStyle(document.querySelector('#seal')).opacity),
          geometry: window.__decisionGeometry(),
          originalGeometry: window.__decodingGeometry
        })""")
        assert settled['headline'] == 'REFUSED' and settled['overlayHidden'] and settled['textOpacity'] == 1, settled
        assert settled['geometry'] == settled['originalGeometry'], settled
        # Superseding decisions invalidate the previous character timers too.
        await page.evaluate("""events => {
          for (const event of events) window.__motionEvent(event);
        }""", [refusal, request, {'type': 'reset'}])
        await page.wait_for_timeout(1100)
        await expect(page.locator('#seal')).to_have_text('READY')
        assert not await page.locator('#decision-cursor').evaluate('node => node.hidden')
        assert await page.locator('#decision-decrypt').evaluate('node => node.hidden')
        # Glyph positions are measured for one layout; resizing restores real text.
        await page.evaluate('event => window.__motionEvent(event)', refusal)
        await page.set_viewport_size({'width': 1360, 'height': 900})
        await page.wait_for_function("document.querySelector('#decision-decrypt').hidden")
        await expect(page.locator('#seal')).to_have_text('REFUSED')
        assert await page.locator('#seal').evaluate('node => getComputedStyle(node).opacity') == '1'
        await page.set_viewport_size({'width': 1440, 'height': 900})
        # Changing the preference while decoding cancels JS timers immediately.
        await page.evaluate('event => window.__motionEvent(event)', request)
        await page.emulate_media(reduced_motion='reduce')
        await page.wait_for_function("document.querySelector('#decision-decrypt').hidden && !document.querySelector('.decision-heading').classList.contains('is-decoding')")
        assert await page.locator('.processing-ring').evaluate("node => getComputedStyle(node).animationName") == 'none'
        reduced = await page.evaluate("""event => {
          window.__motionEvent(event);
          return {headline: document.querySelector('#seal').textContent,
            busy: document.querySelector('#decision-stage').getAttribute('aria-busy'),
            overlayHidden: document.querySelector('#decision-decrypt').hidden,
            textOpacity: Number(getComputedStyle(document.querySelector('#seal')).opacity),
            animations: document.querySelector('.decision-panel').getAnimations({subtree: true}).length};
        }""", refusal)
        assert reduced == {'headline': 'REFUSED', 'busy': 'false', 'overlayHidden': True, 'textOpacity': 1, 'animations': 0}, reduced
        await page.evaluate('event => window.__motionEvent(event)', {'type': 'reset'})
        assert await page.locator('#decision-cursor').evaluate("node => getComputedStyle(node).animationName") == 'none'
        await assert_console_layout(page)
        # Payment protocols add distinct states without moving controls or
        # shrinking the merchant activity viewport. These are display events,
        # never payment requests against the running fixture.
        payment_states = [
            ('payment-required', {'type': 'verdict', 'verdict': 'denied', 'elapsedMs': 12,
                                  'body': {'error': 'PAYMENT_REQUIRED'}}),
            ('checkout-review', {'type': 'checkout.review', 'id': 'layout-checkout',
                                 'url': merchant + '/checkout/layout-checkout?token=layout-only',
                                 'expiresAt': '2099-01-01T00:00:00.000Z'}),
            ('settlement-pending', {'type': 'verdict', 'verdict': 'denied', 'elapsedMs': 12,
                                    'body': {'error': 'SETTLEMENT_PENDING'}}),
        ]
        for name, event in payment_states:
            await page.evaluate('event => window.__motionEvent(event)', event)
            await assert_console_layout(page, output, 'console-' + name)
    finally:
        await page.close()


async def assert_credential_details(page, credential, output):
    await expect(page.locator('.credential-frame legend')).to_contain_text('W3C Verifiable Credential')
    await expect(page.locator('.credential-frame .credential-type')).to_have_text('Delegation')
    await expect(page.locator('#c-action-scopes')).to_have_text(' · '.join(credential['credentialSubject']['delegation']['constraints']['scopes']))
    expected = {
        'c-rp': credential['issuer'] if isinstance(credential['issuer'], str) else credential['issuer']['id'],
        'c-agent': credential['credentialSubject']['id'],
        'c-aud': credential['credentialSubject']['delegation']['constraints']['audience'],
    }
    await page.locator('.grant-details').evaluate('node => { node.open = true; }')
    for width in [1440, 820, 640]:
        await page.set_viewport_size({'width': width, 'height': 900})
        for element_id, value in expected.items():
            element = page.locator('#' + element_id)
            await expect(element).to_have_text(value)
            assert '…' not in await element.inner_text()
            assert await element.evaluate("""node => {
              const rect = node.getBoundingClientRect(), panel = node.closest('.panel-body').getBoundingClientRect();
              return rect.left >= panel.left && rect.right <= panel.right;
            }"""), f'Full DID extends outside sidebar at {width}px'
        link_boxes = [await page.locator(selector).bounding_box() for selector in ['#list-url', '#rp-ledger-link', '#rp-bundle-link']]
        assert all(first['y'] + first['height'] < second['y'] for first, second in zip(link_boxes, link_boxes[1:])), 'Evidence links must have separate rows'
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await page.locator('#c-agent').scroll_into_view_if_needed()
        await page.screenshot(path=str(output / f'credential-identifiers-{width}.png'), full_page=True)
        await page.locator('.credential-evidence').scroll_into_view_if_needed()
        await page.screenshot(path=str(output / f'credential-evidence-{width}.png'), full_page=True)
    await page.locator('.grant-details').evaluate('node => { node.open = false; }')
    await page.locator('.grant-panel .panel-body').evaluate('node => { node.scrollTop = 0; }')
    await page.set_viewport_size({'width': 1440, 'height': 900})


async def assert_live_audit_editor(page, context, merchant, output, state, report):
    """Edit the last anchored entry through the UI, retaining real verification."""
    snapshot = await (await context.request.get(merchant + '/api/audit/ledger')).json()
    anchored = [entry for entry in snapshot['entries'] if entry['anchored']]
    assert anchored, 'The live editor needs an anchored entry to demonstrate tamper detection'
    target = anchored[-1]
    before = target['outcome']
    after = 'failed' if before != 'failed' else 'succeeded'
    action_requests = []
    def track_action(request):
        if request.method == 'POST' and request.url.startswith(merchant + '/api/act/'):
            action_requests.append({'url': request.url, 'body': request.post_data_json})
    page.on('request', track_action)
    release = asyncio.Event()
    response_ready = asyncio.get_running_loop().create_future()
    async def delay_edit_response(route):
        response = await route.fetch()
        response_ready.set_result((response.status, await response.json()))
        await release.wait()
        await route.fulfill(response=response)
    try:
        await expect(page.locator('#audit-edit')).to_be_visible()
        await expect(page.locator('#audit-edit')).to_be_enabled()
        started = time.monotonic()
        await page.keyboard.press('t')
        await expect(page.locator('#audit-editor')).to_be_visible(timeout=1000)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        assert not action_requests, 'Opening the cached editor must not wait for another checkpoint or submit a forgery'
        await page.locator('#audit-edit-entry').select_option(target['seq'])
        await expect(page.locator('#audit-edit-outcome')).to_have_value(before)
        await expect(page.locator('#audit-edit-before')).to_contain_text(before)
        await expect(page.locator('#audit-edit-done')).to_be_disabled()
        assert await page.locator('#audit-edit-entry option').evaluate_all('nodes => nodes.map(node => node.value)') == [entry['seq'] for entry in anchored], 'Only checkpointed entries may be selected'
        assert set(await page.locator('#audit-edit-outcome option').evaluate_all('nodes => nodes.map(node => node.value)')) == {'succeeded', 'failed', 'denied', 'challenged', 'unknown'}
        await page.locator('#audit-edit-outcome').focus()
        await page.keyboard.press('t')
        await page.keyboard.press('1')
        await page.evaluate('() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))')
        assert not action_requests, 'Typing in the outcome control fired a global demo shortcut'
        await expect(page.locator('#audit-editor')).to_be_visible()
        await page.locator('#audit-edit-outcome').select_option(after)
        await expect(page.locator('#audit-edit-done')).to_be_enabled()
        await page.locator('#audit-edit-cancel').click()
        await expect(page.locator('#audit-editor')).not_to_be_visible()
        assert not action_requests, 'Cancelling an edit submitted a mutation'
        await expect(page.locator('#audit-table tr.forged')).to_have_count(0)
        await page.locator('#audit-edit').click()
        await expect(page.locator('#audit-editor')).to_be_visible(timeout=1000)
        await page.locator('#audit-edit-entry').select_option(target['seq'])
        await page.locator('#audit-edit-outcome').select_option(after)
        for width, height in [(1440, 900), (1280, 720)]:
            await page.set_viewport_size({'width': width, 'height': height})
            for selector in ['#audit-edit-entry', '#audit-edit-outcome', '#audit-edit-done', '#audit-edit-cancel']:
                control = page.locator(selector)
                box = await control.bounding_box()
                assert box and box['x'] >= 0 and box['x'] + box['width'] <= width and box['y'] >= 0 and box['y'] + box['height'] <= height, f'Audit editor control {selector} is outside {width}x{height}: {box}'
                assert await control.evaluate('node => { const box = node.getBoundingClientRect(); const top = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2); return top === node || node.contains(top); }'), f'Audit editor control {selector} is covered at {width}x{height}'
            await page.screenshot(path=str(output / f'console-audit-editor-{width}x{height}.png'), full_page=True)
        await page.set_viewport_size({'width': 1440, 'height': 900})
        await page.screenshot(path=str(output / 'console-audit-editor.png'), full_page=True)
        await page.route(merchant + '/api/act/tamper', delay_edit_response, times=1)
        await page.locator('#audit-edit-done').click()
        try:
            await expect(page.locator('#audit-edit-done')).to_be_disabled()
            await expect(page.locator('#audit-edit-feedback')).to_be_visible(timeout=1000)
            assert (await page.locator('#audit-edit-feedback').inner_text()).strip(), 'A pending edit needs visible feedback'
            await expect(page.locator('#audit-table tr.forged')).to_have_count(0)
            await page.screenshot(path=str(output / 'console-audit-editor-verifying.png'), full_page=True)
            status, tamper = await asyncio.wait_for(response_ready, timeout=30)
            assert status == 200, tamper
            assert len(action_requests) == 1 and action_requests[0] == {
                'url': merchant + '/api/act/tamper',
                'body': {'sequence': target['seq'], 'outcome': after, 'checkpointDigest': snapshot['checkpoint']['checkpointDigest']},
            }, action_requests
            assert tamper['target']['seq'] == target['seq'] and tamper['target']['before'] == before and tamper['target']['after'] == after, tamper['target']
            assert tamper['chainBreaksAt'] is None, 'The final entry has no successor that can exhibit a predecessor mismatch'
            assert tamper['forgedReceiptVerifies'] is True and tamper['forgedInclusion'] is False and tamper['rootsMatch'] is False
            assert tamper['reports']['tampered']['chainIntegrity']['verdict'] == 'valid', tamper['reports']['tampered']['chainIntegrity']
            assert tamper['reports']['tampered']['checkpointIntegrity']['verdict'] == 'invalid', tamper['reports']['tampered']['checkpointIntegrity']
            # The real server has finished, but its response is deliberately withheld.
            # The table must not pretend verification completed before receiving it.
            await expect(page.locator('#audit-table tr.forged')).to_have_count(0)
        finally:
            release.set()
        await expect(page.locator('#audit-table tr.forged')).to_have_count(1)
        await expect(page.locator('#ledger-row-' + target['seq'] + ' .out s')).to_have_text(before)
        await expect(page.locator('#ledger-row-' + target['seq'] + ' .out')).to_contain_text(after)
        await expect(page.locator('#audit-chain-note')).not_to_contain_text('broken')
        await expect(page.locator('#audit-verdicts .verdict[title^="chainIntegrity:"]')).to_have_class('verdict valid')
        await expect(page.locator('#audit-verdicts .verdict[title^="checkpointIntegrity:"]')).to_have_class('verdict invalid')
        await expect(page.locator('#audit-tamper')).not_to_contain_text('PREDECESSOR_MISMATCH')
        await page.screenshot(path=str(output / 'console-audit-editor-detected.png'), full_page=True)
        (output / 'audit-live-edit-report.json').write_text(json.dumps({'editorOpenedMs': elapsed_ms, 'selection': action_requests[0]['body'], 'result': tamper}, indent=2))
        report['checks'].append(f'Cached audit editor opens with T in {elapsed_ms} ms without network work; native select typing does not fire demo shortcuts; Cancel leaves the ledger unchanged')
        report['checks'].append('Done sends the selected anchored sequence, outcome and checkpoint digest; delayed real verification keeps feedback visible and never paints a forged result early')
        report['checks'].append('Editing the final anchored entry shows the exact before/after outcome, valid signatures and chain, and invalid checkpoint proofs without claiming a nonexistent successor mismatch')
        response = await context.request.post(merchant + '/api/act/export', data={})
        assert response.ok, await response.text()
        honest = json.loads((state / 'var/audit/bundle.json').read_text())
        edited = json.loads((state / 'var/audit/bundle.tampered.json').read_text())
        entries = lambda bundle: next(component['content'] for component in bundle['components'] if component['path'] == 'entries.json')
        honest_entries, edited_entries = entries(honest), entries(edited)
        differences = [(original, forged) for original, forged in zip(honest_entries, edited_entries) if original != forged]
        assert len(honest_entries) == len(edited_entries) and len(differences) == 1, 'Export must contain exactly the demonstrated edit'
        original, forged = differences[0]
        assert original['core']['sequence'] == forged['core']['sequence'] == target['seq']
        assert original['core']['event']['outcome'] == before and forged['core']['event']['outcome'] == after, 'Export silently changed the presenter-selected outcome'
        current = await (await context.request.get(merchant + '/api/audit/ledger')).json()
        assert current['entries'] == snapshot['entries'], 'The isolated edited bundle must not rewrite the honest merchant ledger'
        report['checks'].append('Export preserves exactly the selected live edit while the honest merchant ledger and honest bundle retain the original event')
    finally:
        release.set()
        page.remove_listener('request', track_action)


async def browser_check(merchant, rp, output, state):
    errors = []
    report = {'ok': False, 'authenticator': 'Chromium virtual FIDO2', 'identity': 'Locally signed fictional Google token; Google certificate transport mocked' if args.google_identity else 'Local RP authority; no Google account', 'checks': [], 'browserErrors': errors}
    async with async_playwright() as playwright:
        executable = os.environ.get('CHROMIUM')
        browser = await playwright.chromium.launch(headless=True, **({'executable_path': executable} if executable else {}))
        context = await browser.new_context(no_viewport=True)
        if args.google_identity:
            redirected = await context.request.get(merchant + '/setup-key.html', max_redirects=0)
            assert redirected.status == 302 and redirected.headers['location'] == rp + '/setup-key.html'
            # No Google account is used by this test. The official ID-token verifier
            # runs on a locally signed fixture token; real GIS requires a client ID.
            await context.route('https://accounts.google.com/**', lambda route: route.abort())
        console_page = await context.new_page()
        await console_page.set_viewport_size({'width': 1440, 'height': 900})
        console_page.on('pageerror', lambda error: errors.append(str(error)))
        await console_page.goto(merchant + '/', wait_until='domcontentloaded')
        # Reproduce the audience's multiple-open-monitors scenario in the same
        # browser context. Eight tabs must not exhaust HTTP/1.1's six sockets.
        extra_monitors = []
        try:
            for _ in range(7):
                extra = await context.new_page()
                extra_monitors.append(extra)
                await extra.goto(merchant + '/', wait_until='domcontentloaded', timeout=5_000)
                await expect(extra.locator('#live-m')).to_have_class('live on', timeout=5_000)
                await expect(extra.locator('#live-rp')).to_have_class('live on', timeout=5_000)
            result = await extra_monitors[-1].evaluate("""async () => {
                const start = performance.now();
                const response = await fetch('/api/state', {signal: AbortSignal.timeout(2000)});
                return {status: response.status, elapsed: performance.now() - start};
            }""")
            assert result['status'] == 200 and result['elapsed'] < 2000, result
            report['checks'].append('Eight simultaneous monitor tabs share working merchant and RP feeds; browser API requests complete without connection starvation')
        finally:
            for extra in extra_monitors:
                await extra.close()
        await assert_decision_motion(context, merchant, output)
        report['checks'].append('Payment required, exact checkout review and unresolved settlement have distinct readable states; long codes wrap at underscores and all controls remain visible')
        report['checks'].append('Controlled SSE timing verifies initial and repeated decryption, a visible same-frame result cue, READY cursor, immediate semantic decisions, fixed text geometry, stale-timer cancellation, resize recovery and reduced-motion')
        await expect(console_page.locator('#btn-revoke')).to_be_disabled()
        await expect(console_page.locator('#seal')).to_have_text('READY')
        await expect(console_page.locator('#verdict-code')).to_have_text('NO_GRANT')
        await expect(console_page.locator('#verdict-context')).to_have_text('HUMAN CONSENT REQUIRED')
        await assert_console_layout(console_page)
        await console_page.screenshot(path=str(output / 'console-ready-desktop.png'), full_page=True)
        if args.passkey_revocation:
            blocked = await context.request.post(rp + '/api/rp/revoke', data={})
            assert blocked.status == 403, 'KEY_WEBAUTHN must not downgrade when no key is registered'
        await console_page.locator('#btn-order').click()
        await expect(console_page.locator('#authorization-link')).to_be_visible()
        await expect(console_page.locator('#seal')).to_have_text('CONSENT NEEDED')
        await expect(console_page.locator('#seal')).not_to_have_class('seal ok')
        await expect(console_page.locator('#verdict-code')).to_have_text('NEEDS_AUTHORIZATION')
        await expect(console_page.locator('#verdict-context')).to_have_text('NO ORDER PLACED')
        await assert_console_layout(console_page)
        await expect(console_page.locator('#log')).not_to_contain_text('hub state failed')
        # Reopening the merchant monitor must recover pending consent through the
        # RP's cross-origin read endpoint, without issuing another challenge.
        consent_url = await console_page.locator('#authorization-link').get_attribute('href')
        async with console_page.expect_response(lambda response: response.url.startswith(rp + '/consent/status?')) as pending_read:
            await console_page.reload(wait_until='domcontentloaded')
        assert (await pending_read.value).status == 200
        await expect(console_page.locator('#authorization-link')).to_have_attribute('href', consent_url)
        await expect(console_page.locator('#authorization-link')).to_be_visible()
        await expect(console_page.locator('#seal')).to_have_text('CONSENT NEEDED')
        await expect(console_page.locator('#log')).not_to_contain_text('hub state failed')
        report['checks'].append('A freshly reopened merchant monitor recovers the same pending consent through the RP cross-origin status endpoint, with no hub-state failure')
        await console_page.evaluate("window.__previousResponseLetters = [...document.querySelectorAll('#decision-decrypt .decrypt-letter')]")
        await console_page.locator('#btn-order').click()
        await expect(console_page.locator('#btn-order')).to_be_enabled()
        await expect(console_page.locator('#authorization-link')).to_have_attribute('href', consent_url)
        assert await console_page.evaluate("""() => {
          const next = [...document.querySelectorAll('#decision-decrypt .decrypt-letter')];
          return document.querySelector('.decision-heading').classList.contains('is-decoding') &&
            next.length && next.every(letter => !window.__previousResponseLetters.includes(letter));
        }"""), 'The same pending order must replay feedback even if the agent returns its cached challenge'
        report['checks'].append('Repeating the actual order button with the same pending consent challenge replays visible feedback without creating a different consent URL')
        await console_page.screenshot(path=str(output / 'console-consent-pending.png'), full_page=True)
        async with context.expect_page() as opened:
            await console_page.locator('#authorization-link').click()
        page = await opened.value
        page.on('pageerror', lambda error: errors.append(str(error)))
        await page.wait_for_url(rp + '/**', wait_until='networkidle')
        popup = await page.evaluate('({openerDetached:window.opener === null,name:window.name,width:window.innerWidth,height:window.innerHeight})')
        assert popup['openerDetached'], popup
        assert popup['width'] <= 680 and popup['height'] <= 900, popup
        assert console_page.url == merchant + '/'
        report['checks'].append('Open human consent launches a compact popup with its opener detached; the projector stays open')
        cdp = await context.new_cdp_session(page)
        await cdp.send('WebAuthn.enable')
        authenticator = await cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': False, 'hasUserVerification': False, 'isUserVerified': False, 'automaticPresenceSimulation': True}})
        if args.google_identity:
            await page.goto(rp + '/setup-key.html', wait_until='networkidle')
            await expect(page.locator('#go')).to_be_disabled()
            await expect(page.locator('#account-name')).to_contain_text('Sign in')
            await page.locator('#sign-in').click()
            await expect(page).to_have_url(rp + '/auth/login')
            signed_in = await page.evaluate('''async () => {
              const options = await (await fetch('/auth/google/options')).json();
              const token = await (await fetch('/test/google-token', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nonce:options.nonce})})).json();
              const response = await fetch('/auth/google/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(token)});
              return {status:response.status,body:await response.json()};
            }''')
            assert signed_in['status'] == 200, signed_in
            assert signed_in['body']['account']['displayName'] == 'Workshop Test Human'
            await page.goto(rp + signed_in['body']['returnTo'], wait_until='networkidle')
            await expect(page.locator('#account-name')).to_have_text('Workshop Test Human')
            await expect(page.locator('#go')).to_be_enabled()
            await page.screenshot(path=str(output / 'google-account-before-passkey.png'), full_page=True)
            report['checks'].append('Google account session created through real nonce, cookie and signature verification using a fictional local token; no live Google sign-in claimed')
        else:
            await page.goto(merchant + '/setup-key.html', wait_until='networkidle')
        await expect(page.locator('#registered')).to_contain_text('No passkey registered yet')
        await page.locator('#label').fill('Virtual workshop badge')
        await page.get_by_role('button', name='Register this passkey').click()
        await expect(page.locator('#out')).to_contain_text('registered ✓', timeout=15_000)
        report['checks'].append('Existing registration page verified a real browser FIDO2 attestation')
        if args.google_identity:
            authenticators = json.loads((state / 'data/authenticators.json').read_text())
            assert authenticators[-1]['accountId'] == signed_in['body']['account']['accountRef']
            report['checks'].append('Server-bound opaque Google account reference persisted on the verified passkey registration')
            await page.screenshot(path=str(output / 'google-account-passkey-registered.png'), full_page=True)

        async def order():
            response = await context.request.post(merchant + '/api/act/order', data={'product': 'risotto', 'quantity': 2})
            assert response.ok, await response.text()
            result = await response.json()
            return json.loads(result['result']['content'][0]['text'])

        challenge = await order()
        assert challenge['error'] == 'needs_authorization'
        await page.goto(challenge['authorizationUrl'], wait_until='networkidle')
        await assert_capability_consent(page)
        await page.locator(DENY).click()
        await expect(page.locator('#result-title')).to_have_text('Grant denied')
        await expect(page.locator('#consent-result #decision-status')).to_have_text('Grant denied. No credential was issued.')
        assert await page.locator('#decision-status').evaluate("node => !!node.closest('#consent-result')")
        await expect(page.locator('main > #decision-status')).to_have_count(0)
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        await page.screenshot(path=str(output / 'consent-popup-denied.png'), full_page=True)
        report['checks'].append('Denial stays inside the result card with no external banner and issues no credential')
        await context.request.post(merchant + '/api/act/reset', data={})
        challenge = await order()
        fields = {'tool': 'place_order', 'scopes': json.dumps(challenge['scopes']), 'selected_scopes': json.dumps(challenge['scopes']), 'agent_did': parse_qs(urlparse(challenge['authorizationUrl']).query)['agent_did'][0], 'session_id': challenge['resumeToken']}
        response = await context.request.post(rp + '/consent/approve', data=fields)
        assert response.status == 409, await response.text()
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        report['checks'].append('Registered authenticator flag rejects approval without an assertion')
        await context.request.post(merchant + '/api/act/reset', data={})
        challenge = await order()
        assert challenge['authorizationUrl'].startswith(rp + '/consent?')
        await page.goto(challenge['authorizationUrl'], wait_until='networkidle')
        pending = json.loads((state / 'var/rp/consent/flows.json').read_text())
        bindings = pending['flows'][challenge['resumeToken']]['bindings']
        await assert_capability_consent(page, bindings)
        await page.screenshot(path=str(output / 'consent-popup-ready.png'), full_page=True)
        await page.set_viewport_size({'width': 1920, 'height': 1080})
        await assert_capability_consent(page, bindings)
        report['checks'].append('Consent stays in one column at popup, desktop and mobile widths, capped at 640px with no external branding or callouts')
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        report['checks'].append('Actual capability component displays bound GS1 scope, agent, merchant, cap and expiry; deselection disables approval without issuing a VC')
        if args.google_identity:
            await expect(page.locator('#human-account-name')).to_have_text('Workshop Test Human')
        await page.screenshot(path=str(output / 'webauthn-ready.png'), full_page=True)
        await page.set_viewport_size({'width': 390, 'height': 844})
        await assert_mobile_consent(page)
        if args.google_identity:
            await page.screenshot(path=str(output / 'google-consent-ready-mobile.png'), full_page=True)
        await page.set_viewport_size({'width': 1440, 'height': 900})

        # Exercise cancellation of a real pending navigator.credentials.get call.
        # Only the user-presence simulation is paused; no fake assertion is returned.
        await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId': authenticator['authenticatorId'], 'enabled': False})
        await page.evaluate('''() => {
          const nativeGet = navigator.credentials.get.bind(navigator.credentials);
          navigator.credentials.get = options => {
            navigator.credentials.get = nativeGet;
            window.__cancelConsentPasskey = new AbortController();
            return nativeGet({...options, signal: window.__cancelConsentPasskey.signal});
          };
        }''')
        await page.locator(APPROVE).click()
        await page.wait_for_function('window.__cancelConsentPasskey !== undefined')
        await expect(page.locator(APPROVE)).to_be_disabled()
        await expect(page.locator(DENY)).to_be_disabled()
        await expect(page.locator(SCREEN).get_by_role('checkbox')).to_be_disabled()
        await expect(page.locator('.consent-feedback')).to_be_hidden()
        await page.evaluate('window.__cancelConsentPasskey.abort()')
        await expect(page.locator(APPROVE)).to_be_enabled()
        await expect(page.locator(DENY)).to_be_enabled()
        await expect(page.locator('#decision-status')).to_have_text('Passkey confirmation did not complete. No grant was issued. Try again.')
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        pending = json.loads((state / 'var/rp/consent/flows.json').read_text())
        assert pending['flows'][challenge['resumeToken']]['state'] == 'pending'
        report['checks'].append('Canceled real passkey request keeps the grant pending and issues no VC; controls unlock for a retry')
        await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId': authenticator['authenticatorId'], 'enabled': True})
        lost_response = {'committed': False}
        approval_posts = []
        if args.google_identity:
            page.on('request', lambda request: approval_posts.append(request.url)
                    if request.method == 'POST' and request.url == rp + '/consent/approve' else None)

            async def drop_committed_response(route):
                # Commit through the actual authenticated server and only then
                # simulate a connection failure on its way back to the browser.
                response = await route.fetch()
                assert response.ok, await response.text()
                lost_response['committed'] = True
                await route.abort('failed')

            await page.route(rp + '/consent/approve', drop_committed_response, times=1)
        # A slow merchant observer request must not delay the RP's grant panel.
        # Hold it through actual consent, with the popup still open and no retry.
        merchant_refresh_release = asyncio.Event()
        async def delay_merchant_state(route):
            response = await route.fetch()
            await merchant_refresh_release.wait()
            await route.fulfill(response=response)
        await console_page.route(merchant + '/api/state', delay_merchant_state)
        await page.locator(APPROVE).click()
        expected_decision = 'Grant issued. Workshop Test Human → passkey confirmed → signed grant → Acme Shopping Agent. Retry the same order in Claude.' if args.google_identity else 'Grant issued. Retry the same order in Claude.'
        await expect(page.locator('#decision-status')).to_have_text(expected_decision, timeout=20_000)
        if args.google_identity:
            assert lost_response['committed'] and len(approval_posts) == 1, 'Response loss must recover the committed grant without posting another approval'
            report['checks'].append('A deliberately dropped real approval response recovers the committed grant and account from read-only status, without submitting approval again')
        try:
            await expect(console_page.locator('#verdict-code')).to_have_text('HUMAN_APPROVED')
            await expect(console_page.locator('#grant-pill')).to_have_text('active', timeout=2000)
            await expect(console_page.locator('#c-cap-label')).to_have_text('Per-order limit')
            await expect(console_page.locator('#c-cap')).to_have_text('CHF 50.00')
            await expect(console_page.locator('#c-scope')).to_contain_text('09506000134352')
            if args.google_identity:
                await expect(console_page.locator('#c-human')).to_have_text('Workshop Test Human')
            report['checks'].append('Issued grant, scopes, spending cap and human appear behind the still-open consent popup before any agent retry, even with merchant state delayed')
        finally:
            merchant_refresh_release.set()
            await console_page.unroute(merchant + '/api/state', delay_merchant_state)
        await expect(page.locator('#consent-result #decision-status')).to_be_visible()
        await expect(page.locator('#close-consent-window')).to_be_visible()
        await page.screenshot(path=str(output / 'webauthn-grant-issued.png'), full_page=True)
        saved_keys = await cdp.send('WebAuthn.getCredentials', authenticator)
        async with page.expect_event('close'):
            await page.locator('#close-consent-window').click()
        page = console_page
        report['checks'].append('Approval feedback stays inside the result card and Back to demo returns to the still-open projector')
        await expect(page.locator('#seal')).to_have_text('GRANT APPROVED')
        await expect(page.locator('#seal')).not_to_have_class('seal ok')
        await expect(page.locator('#verdict-code')).to_have_text('HUMAN_APPROVED')
        await expect(page.locator('#verdict-context')).to_have_text('RETRY THE SAME ORDER')
        await assert_console_layout(page, output, 'console-approved-awaiting-agent')
        observed_grant = await (await context.request.get(rp + '/api/rp/delegation')).json()
        await assert_credential_details(page, observed_grant['credential'], output)
        report['checks'].append('Credential details show exact complete issuer, agent and audience identifiers, with separate evidence link rows and no horizontal overflow at desktop and split-screen widths')
        pending = json.loads((state / 'var/rp/consent/flows.json').read_text())
        hardware_events = [event for event in pending['events'] if event['type'] == 'consent.approved' and event['payload'].get('authentication', {}).get('method') == 'webauthn']
        assert hardware_events and hardware_events[-1]['payload']['authentication']['credentialId']
        assert hardware_events[-1]['payload']['authentication']['aaguid']
        assert not any(event['type'] == 'credential.verified' for event in pending['events']), 'Passkey proof must not be mislabeled as a credential verification'
        assert hardware_events[-1]['payload']['approvedScopes'] == challenge['scopes']
        if args.google_identity:
            assert hardware_events[-1]['payload']['authentication']['human']['accountRef'] == signed_in['body']['account']['accountRef']
            credentials = list((state / 'var').rglob('delegation-*.json'))
            if not credentials:
                credentials = list((state / 'data').rglob('delegation-*.json'))
            assert credentials, 'Issued VC missing from isolated state'
            vc = json.loads(credentials[-1].read_text())
            linked = vc['credentialSubject']['delegation']['metadata']['demoConsent']
            assert linked['human']['accountRef'] == signed_in['body']['account']['accountRef']
            assert linked['authentication']['method'] == 'webauthn'
            assert linked['consentRef'].startswith('sha256:')
            assert 'fixture-human-not-a-real-google-account' not in json.dumps(vc)
            assert 'fictional-human@example.test' not in json.dumps(vc)
            report['checks'].append('Issued signed VC metadata links the same provider account, verified passkey, consent reference and agent while omitting raw subject and email')
        report['checks'].append('Actual consent button completed navigator.credentials.get, bound assertion verification and VC issuance')
        report['checks'].append('Consent audit event commits authenticator credential ID, AAGUID and issuance-intent hash')
        allowed = await order()
        assert allowed.get('ok') is True, allowed
        await expect(page.locator('#seal')).to_have_text('AUTHORIZED')
        await expect(page.locator('#seal')).to_have_class('seal ok')
        await assert_console_layout(page, output, 'console-authorized')
        report['checks'].append('The monitor distinguishes no grant, consent needed, and approved grant awaiting an agent retry from the merchant authorizing an actual order')
        report['checks'].append('Same MCP order allowed with the new VC and fresh holder proof; the resume token is used only for RP consent and pickup')
        rp_ledger = await (await context.request.get(rp + '/api/rp/audit/ledger')).json()
        merchant_ledger = await (await context.request.get(merchant + '/api/audit/ledger')).json()
        consent_ref = hardware_events[-1]['payload']['consentRef']
        assert any(event['eventType'] == 'consent.approved' and event['correlationId'] == consent_ref for event in rp_ledger['entries'])
        assert not any(event['eventType'] in ['consent.approved', 'delegation.issued'] for event in merchant_ledger['entries'])
        assert any(event['eventType'] == 'credential.verified' and event['correlationId'] == consent_ref for event in merchant_ledger['entries'])
        assert rp_ledger['recorder']['did'] != merchant_ledger['recorder']['did']
        report['checks'].append('RP consent approval and merchant attestation verification have separate ledger signers and the same signed consent reference')
        if args.google_identity:
            await page.goto(merchant + '/', wait_until='domcontentloaded')
            await expect(page.locator('#c-human')).to_contain_text('Workshop Test Human')
            await expect(page.locator('#verdict-code')).to_have_text('GRANT_ACTIVE')
            await expect(page.locator('#verdict-context')).to_have_text('READY TO ORDER')
            await assert_console_layout(page)
            await page.screenshot(path=str(output / 'console-grant-desktop.png'), full_page=True)
            await page.locator('#btn-order').click()
            await expect(page.locator('#seal')).to_have_text('AUTHORIZED')
            await assert_console_layout(page)
            await page.screenshot(path=str(output / 'console-authorized.png'), full_page=True)
            for control, gate, decision, code in [
                ('btn-wrong', 'Product class', 'REFUSED', 'PRODUCT_OUT_OF_SCOPE'),
                ('btn-overcap', 'Spend cap', 'REFUSED', 'SPEND_CAP_EXCEEDED'),
                ('btn-steal', 'Holder key', 'DENIED', 'HOLDER_BINDING_FAILED'),
            ]:
                await page.locator('#' + control).click()
                # Await this request's reason as well as the label: the previous
                # REFUSED must not satisfy a later action before its SSE arrives.
                await expect(page.locator('#verdict-code')).to_have_text(code)
                await expect(page.locator('#seal')).to_have_text(decision)
                await expect(page.locator('.gate.fail').filter(has_text=gate)).to_be_visible()
                if control == 'btn-wrong':
                    await assert_console_layout(page, output, 'console-product-out-of-scope')
                elif control == 'btn-overcap':
                    await assert_console_layout(page, output, 'console-refused')
                    await page.screenshot(path=str(output / 'console-refused.png'), full_page=True)
                elif control == 'btn-steal':
                    await assert_console_layout(page, output, 'console-holder-key-denied')
            # Restore the authorized view for the presenter screenshots.
            await page.locator('#btn-retry').click()
            await expect(page.locator('#seal')).to_have_text('AUTHORIZED')
            await page.keyboard.press('p')
            await page.screenshot(path=str(output / 'google-human-to-agent-projector.png'), full_page=True)
            await page.set_viewport_size({'width': 390, 'height': 844})
            await page.screenshot(path=str(output / 'google-human-to-agent-projector-mobile.png'), full_page=True)
            await page.set_viewport_size({'width': 1440, 'height': 900})
            report['checks'].append('Projector renders the account to passkey to consent to signed agent grant relationship')
            await page.keyboard.press('p')  # Restore the visible operator controls.
        before_revoke = await (await context.request.get(rp + '/api/rp/state')).json()
        assert before_revoke['keyRequired'] == args.passkey_revocation
        await expect(page.locator('#btn-revoke')).to_be_enabled()
        if args.passkey_revocation:
            blocked = await context.request.post(rp + '/api/rp/revoke', data={})
            assert blocked.status == 403, 'Software endpoint must not bypass the passkey'
            console_cdp = await context.new_cdp_session(page)
            await console_cdp.send('WebAuthn.enable')
            console_auth = await console_cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': False, 'hasUserVerification': False, 'isUserVerified': False, 'automaticPresenceSimulation': False}})
            for credential in saved_keys['credentials']:
                await console_cdp.send('WebAuthn.addCredential', {**console_auth, 'credential': credential})
            executions = []
            page.on('request', lambda request: executions.append(request.post_data_json) if request.method == 'POST' and request.url == rp + '/api/rp/revoke/execute' else None)
            await page.locator('#btn-revoke').click()
            await expect(page.locator('#key-overlay')).to_have_class('key-overlay on')
            await page.locator('#key-cancel').click()
            await expect(page.locator('#verdict-code')).to_have_text('REVOCATION_CANCELLED')
            assert not executions, 'Cancelling the native prompt must not submit a revocation'
            after_cancel = await (await context.request.get(rp + '/api/rp/state')).json()
            assert after_cancel['statusList']['version'] == before_revoke['statusList']['version'] and after_cancel['revoked'] is False
            await console_cdp.send('WebAuthn.setAutomaticPresenceSimulation', {**console_auth, 'enabled': True})
            await page.locator('#btn-revoke').click()
            await expect(page.locator('#verdict-code')).to_have_text('GRANT_REVOKED', timeout=20_000)
            await expect(page.locator('#seal')).to_have_text('REVOKED')
            await assert_console_layout(page, output, 'console-grant-revoked')
            assert len(executions) == 1
            replay = await context.request.post(rp + '/api/rp/revoke/execute', data=executions[0])
            assert replay.status == 400, await replay.text()
            report['checks'].append('Passkey required without silent software fallback; Cancel aborts the native prompt without publication; a real assertion revokes and replay is rejected')
            # Lose a real completion response after the status list is published.
            async def drop_revoke_response(route):
                committed = await route.fetch()
                assert committed.ok, await committed.text()
                await route.abort('failed')
            await page.route(rp + '/api/rp/revoke/execute', drop_revoke_response, times=1)
            await page.locator('#btn-revoke').click()
            await expect(page.locator('#verdict-code')).to_have_text('GRANT_REVOKED', timeout=20_000)
            await expect(page.locator('#verdict-context')).to_have_text('AUDIT STATUS UNKNOWN', timeout=20_000)
            await expect(page.locator('#seal')).to_have_text('REVOKED')
            report['checks'].append('A lost revocation response resolves through status readback and never leaves VERIFYING stuck')
        else:
            await page.locator('#btn-revoke').click()
            await expect(page.locator('#verdict-code')).to_have_text('GRANT_REVOKED', timeout=20_000)
            await assert_console_layout(page, output, 'console-grant-revoked')
            report['checks'].append('KEY_WEBAUTHN=0 keeps revocation software-only despite the registered issuance key')
        denied = await order()
        assert 'revoked' in json.dumps(denied).lower(), denied
        await expect(page.locator('#seal')).to_have_text('DENIED')
        await expect(page.locator('#seal')).to_have_class('seal denied')
        report['checks'].append('Next MCP order denied after the RP status-list bit flipped')
        await assert_console_layout(page, output, 'console-denied')
        await page.screenshot(path=str(output / 'console-revoked.png'), full_page=True)
        report['checks'].append('Full-height delegation stays left of aligned decision and logs at 1440x900, 1280x720, 1150x900, 1024x900, 901x900, 820x900 and 640x900; core grant fields remain visible without scrolling on desktop')
        report['checks'].append('All 12 controls, unclipped and non-overlapping decision text, and live log remain in the viewport at seven desktop and split-screen sizes through pending, authorized, refused and revoked states')
        report['checks'].append('Decision labels are at least 60px on desktop and 40px in split-screen widths; body and log text contrast is at least 7:1; log rows use decorative SVG icons without emoji')
        report['checks'].append('Decision codes use consistent uppercase underscore tokens with separate audit caveats; codes are at least 24px on desktop, 20px in split-screen widths and 18px on mobile, with at least 7:1 contrast')
        report['checks'].append('Decision card height is identical across natural consent, approval, verification and refusal states at every desktop and split-screen viewport; left accent border is absent')
        audit_release = asyncio.Event()
        async def delay_audit_response(route):
            response = await route.fetch()
            await audit_release.wait()
            await route.fulfill(response=response)
        await page.route(merchant + '/api/act/audit', delay_audit_response, times=1)
        await page.locator('#btn-audit').click()
        try:
            await expect(page.locator('#audit-overlay')).to_be_visible(timeout=1000)
            await expect(page.locator('#audit-status')).to_contain_text('Creating the signed checkpoint')
            await expect(page.locator('#audit-overlay')).to_have_attribute('aria-busy', 'true')
            await page.screenshot(path=str(output / 'console-audit-loading.png'), full_page=True)
            await page.locator('#audit-close').click()
            await expect(page.locator('#audit-overlay')).not_to_be_visible()
        finally:
            audit_release.set()
        await expect(page.locator('#btn-audit')).to_be_enabled()
        await expect(page.locator('#audit-overlay')).not_to_be_visible()
        await page.locator('#btn-audit').click()
        await expect(page.locator('#audit-body')).to_be_visible()
        await expect(page.locator('#audit-status')).not_to_be_visible()
        await expect(page.locator('#audit-overlay')).to_have_attribute('aria-busy', 'false')
        await page.screenshot(path=str(output / 'console-audit-ready.png'), full_page=True)
        await assert_live_audit_editor(page, context, merchant, output, state, report)
        await page.locator('#audit-close').click()
        report['checks'].append('Show audit opens immediately while a real checkpoint response is delayed; closing it stays closed when the response arrives, and reopening displays the verified report')
        for filename, code in [('bundle.json', 0), ('bundle.tampered.json', 1)]:
            result = subprocess.run(['python3', str(ROOT / 'scripts/verify-ledger.py'), str(state / 'var/audit' / filename), '--keys', str(state / 'var/audit/keys.json'), '--quiet'], capture_output=True, text=True)
            assert result.returncode == code, result.stdout + result.stderr
        report['checks'].append('Honest witnessed bundle verified and tampered bundle rejected')
        # Start over archives the merchant run; it never erases the RP history.
        # Exercise the real button after the finale, including a freshly opened audit.
        before_reset = await (await context.request.get(merchant + '/api/audit/ledger')).json()
        rp_before_reset = await (await context.request.get(rp + '/api/rp/audit/ledger')).json()
        rp_visible_history = await page.locator('#rp-log').inner_text()
        async with page.expect_response(lambda response: response.url == merchant + '/api/act/reset') as resetting:
            await page.locator('#btn-reset').click()
        reset_response = await resetting.value
        reset_result = await reset_response.json()
        assert reset_response.ok and reset_result['success'] is True, reset_result
        assert reset_result['auditRunId'] != before_reset['ledger']['ledgerEpochId']
        assert reset_result['archivedAudit']['ledgerEpochId'] == before_reset['ledger']['ledgerEpochId']
        await expect(page.locator('#verdict-code')).to_have_text('NO_GRANT')
        await expect(page.locator('#audit-overlay')).not_to_be_visible()
        await expect(page.locator('#audit-table')).to_be_empty()
        await expect(page.locator('#audit-export')).to_be_empty()
        await expect(page.locator('#audit-root')).to_be_empty()
        await expect(page.locator('#audit-n')).to_have_text('0 ENTRIES')
        await expect(page.locator('#receipt')).to_have_text('Every allowed response is signed by the merchant’s key. Its receipt can be verified by any party.')
        await expect(page.locator('#log')).to_contain_text('Previous merchant run archived')
        await expect(page.locator('#log .log-line')).to_have_count(1)
        assert rp_visible_history in await page.locator('#rp-log').inner_text(), 'Start over erased visible RP history'
        after_reset = await (await context.request.get(merchant + '/api/audit/ledger')).json()
        assert after_reset['entries'] == [] and after_reset['ledger']['ledgerEpochId'] == reset_result['auditRunId']
        rp_after_reset = await (await context.request.get(rp + '/api/rp/audit/ledger')).json()
        assert rp_after_reset['entries'][:len(rp_before_reset['entries'])] == rp_before_reset['entries'], 'Start over altered recorded RP evidence'
        await page.wait_for_function("!document.querySelector('.decision-heading').classList.contains('is-decoding')")
        await page.screenshot(path=str(output / 'console-start-over-fresh.png'), full_page=True)
        await page.locator('#btn-audit').click()
        await expect(page.locator('#audit-status')).not_to_be_visible()
        await expect(page.locator('#audit-overlay')).to_have_attribute('aria-busy', 'false')
        await expect(page.locator('#audit-chain-note')).to_have_text('0 entries · fresh run')
        await expect(page.locator('#audit-table')).to_contain_text('No merchant decisions')
        await expect(page.locator('#audit-cp')).to_contain_text('No checkpoint yet')
        await expect(page.locator('#audit-tree-root')).to_be_empty()
        await expect(page.locator('#audit-export')).to_be_empty()
        await expect(page.locator('#audit-edit')).to_be_disabled()
        await page.screenshot(path=str(output / 'console-start-over-empty-audit.png'), full_page=True)
        (output / 'audit-run-reset-report.json').write_text(json.dumps({'reset': reset_result, 'merchantEntries': len(after_reset['entries']), 'rpEntriesBefore': len(rp_before_reset['entries']), 'rpEntriesAfter': len(rp_after_reset['entries'])}, indent=2))
        report['checks'].append('Start over archives the previous merchant epoch and clears audit, receipt and activity only after confirmation; signed RP history remains intact and Show audit opens an honest empty run')
        assert not errors, errors
        report['ok'] = True
        (output / ('google-identity-browser-report.json' if args.google_identity else 'webauthn-browser-report.json')).write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        await browser.close()


def main():
    output = Path(args.outdir or tempfile.mkdtemp(prefix='kya-webauthn-evidence-')).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='kya-webauthn-state-') as directory:
        state = Path(directory)
        rp_port, merchant_port = free_port(), free_port()
        while merchant_port == rp_port:
            merchant_port = free_port()
        env = {**os.environ, 'DEMO_VAR_DIR': str(state / 'var'), 'DEMO_DATA_DIR': str(state / 'data'), 'RP_PORT': str(rp_port), 'MERCHANT_PORT': str(merchant_port), 'DEMO_GOOGLE_IDENTITY_TEST': '1' if args.google_identity else '0', 'DEMO_PASSKEY_REVOCATION_TEST': '1' if args.passkey_revocation else '0'}
        log = (output / 'fixture.log').open('w')
        process = subprocess.Popen(['node', '--import', 'tsx', 'scripts/consent-browser-fixture.ts'], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        merchant, rp = f'http://localhost:{merchant_port}', f'http://localhost:{rp_port}'
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    with urlopen(merchant + '/api/state', timeout=1) as response:
                        assert response.status == 200
                    break
                except Exception:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError((output / 'fixture.log').read_text())
                    time.sleep(.2)
            asyncio.run(browser_check(merchant, rp, output, state))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
    print(f'Virtual WebAuthn evidence: {output}')


if __name__ == '__main__':
    main()
