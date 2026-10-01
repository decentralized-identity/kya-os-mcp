#!/usr/bin/env python3
"""Verify the human-grant journey in Chromium and capture projector evidence.

Install once: python3 -m pip install playwright && python3 -m playwright install chromium
Run: python3 scripts/screenshot-run.py docs/screenshots --presenter
Backup: python3 scripts/screenshot-run.py docs/screenshots --presenter --record-video --duration 90

Uses the actual @kya-os/consent component's Deny and Approve grant buttons.
No credential is fabricated and no approval endpoint is called directly.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, urlparse

from playwright.async_api import async_playwright, expect
from browser_consent import APPROVE, DENY, assert_capability_consent, assert_mobile_consent

expect.set_options(timeout=20_000)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('outdir', nargs='?', default='docs/screenshots')
parser.add_argument('--presenter', action='store_true')
parser.add_argument('--headed', action='store_true')
parser.add_argument('--record-video', action='store_true')
parser.add_argument('--check-variants', action='store_true', help='Also verify real no-JS forms and the mobile layout')
parser.add_argument('--duration', type=float, default=90, help='Minimum backup video duration in seconds')
parser.add_argument('--origin', default=os.environ.get('MERCHANT_ORIGIN', 'http://localhost:4949'))
args = parser.parse_args()
output = Path(args.outdir).resolve()
output.mkdir(parents=True, exist_ok=True)


async def main():
    errors = []
    shots = []
    report = {'ok': False, 'screenshots': shots, 'errors': errors, 'checks': []}
    async with async_playwright() as playwright:
        executable = os.environ.get('CHROMIUM')
        browser = await playwright.chromium.launch(
            headless=not args.headed,
            **({'executable_path': executable} if executable else {}),
        )
        viewport = {'width': int(os.environ.get('W', '1440')), 'height': int(os.environ.get('H', '900'))}
        context = await browser.new_context(
            viewport=viewport,
            **({'record_video_dir': str(output / 'video'), 'record_video_size': viewport} if args.record_video else {}),
        )
        page = await context.new_page()
        page.set_default_timeout(20_000)
        video = page.video
        started = time.monotonic()
        page.on('pageerror', lambda error: errors.append(str(error)))

        async def shot(name, full=True):
            file = output / f'consent-{name}.png'
            await page.screenshot(path=str(file), full_page=full)
            shots.append(str(file))
            print(f'saved {file}', flush=True)
            if args.record_video:
                await page.wait_for_timeout(5000)

        async def console():
            await page.goto(args.origin + '/', wait_until='domcontentloaded')
            await expect(page.locator('#live-m')).to_have_class('live on')
            await expect(page.locator('#live-rp')).to_have_class('live on')
            if args.presenter:
                await page.keyboard.press('p')

        async def act(key):
            button = {
                'r': 'reset', '0': 'discover', '1': 'order', '4': 'retry',
                'v': 'verify', '2': 'wrong', '3': 'overcap', 'k': 'revoke',
                'a': 'audit', 't': 'tamper', 'e': 'export',
            }[key]
            control = page.locator('#btn-' + button)
            await expect(control).to_be_enabled()
            await page.keyboard.press(key)
            await expect(control).to_be_enabled()

        async def request_consent():
            await act('1')
            await expect(page.locator('#seal')).to_have_text('CONSENT NEEDED')
            await expect(page.locator('#authorization-panel')).to_be_visible()
            authorization_url = await page.locator('#authorization-link').get_attribute('href')
            assert authorization_url and '/consent?' in authorization_url, 'Missing real consent URL'
            return authorization_url

        async def consent_page(url):
            await page.goto(url, wait_until='networkidle')
            await assert_capability_consent(page)

        async def fresh_challenge(test_context):
            reset = await test_context.request.post(args.origin + '/api/act/reset', data={})
            assert reset.ok, 'Variant reset failed'
            response = await test_context.request.post(args.origin + '/api/act/order', data={'product': 'risotto', 'quantity': 2})
            payload = await response.json()
            challenge = json.loads(payload['result']['content'][0]['text'])
            assert challenge['error'] == 'needs_authorization'
            return challenge

        async def variants():
            checks = []
            nojs = await browser.new_context(java_script_enabled=False, viewport=viewport)
            nojs_page = await nojs.new_page()
            for choice in ['Deny', 'Approve grant']:
                challenge = await fresh_challenge(nojs)
                await nojs_page.goto(challenge['authorizationUrl'], wait_until='networkidle')
                form = nojs_page.locator('.fallback-form')
                summary = nojs_page.locator('.native-summary')
                await expect(form).to_be_visible()
                await expect(summary).to_be_visible()
                # Playwright's text matcher skips NOSCRIPT even when Chromium
                # paints its native fallback. inner_text reads the rendered text.
                summary_text = await summary.inner_text()
                for expected in ['09506000134352', 'https://id.gs1.org/01/09506000134352', 'CHF 50.00']:
                    assert expected in summary_text, f'No-JS summary omits {expected}'
                hub = challenge['authorizationUrl'].split('/consent?', 1)[0]
                query = parse_qs(urlparse(challenge['authorizationUrl']).query)
                assert (await form.get_attribute('method')).upper() == 'POST'
                assert await form.get_attribute('action') == hub + '/consent/approve'
                for name, value in {'tool': 'place_order', 'agent_did': query['agent_did'][0], 'session_id': challenge['resumeToken']}.items():
                    assert await form.locator(f'input[type="hidden"][name="{name}"]').input_value() == value, f'No-JS form has an unbound {name}'
                scopes = await form.locator('input[type="hidden"][name="scopes"]').input_value()
                assert json.loads(scopes) == challenge['scopes'], 'No-JS form has unbound scopes'
                selection = form.locator('input[type="checkbox"][name="selected_scopes"]')
                await expect(selection).to_be_checked()
                assert json.loads(await selection.input_value()) == challenge['scopes'], 'Native selection has unbound scopes'
                submitted_approvals = []
                def observe_native_request(request):
                    if request.method == 'POST' and request.url == hub + '/consent/approve':
                        submitted_approvals.append(request.url)
                nojs_page.on('request', observe_native_request)
                await selection.uncheck()
                await form.get_by_role('button', name='Approve grant', exact=True).click()
                assert await selection.evaluate('(input) => input.validity.valueMissing'), 'Unchecked scope must block native approval'
                assert not submitted_approvals, 'Unchecked native scope submitted an approval request'
                before_grant = await nojs.request.get(hub + '/api/rp/delegation')
                assert not (await before_grant.json()).get('credential'), 'Unchecked native scope minted a credential'
                nojs_page.remove_listener('request', observe_native_request)
                if choice == 'Approve grant':
                    await selection.check()
                file = output / ('consent-nojs-' + ('deny' if choice == 'Deny' else 'approve') + '.png')
                await nojs_page.screenshot(path=str(file), full_page=True)
                shots.append(str(file))
                await nojs_page.get_by_role('button', name=choice, exact=True).click()
                await expect(nojs_page.locator('body')).to_contain_text(re.compile('denied' if choice == 'Deny' else 'approved|grant issued', re.I))
                response = await nojs.request.get(hub + '/api/rp/delegation')
                grant = await response.json()
                assert bool(grant.get('credential')) == (choice == 'Approve grant'), f'No-JS {choice}: wrong credential state'
                checks.append('no-JS ' + choice)
            await nojs.close()
            mobile = await browser.new_context(viewport={'width': 390, 'height': 844})
            mobile_page = await mobile.new_page()
            challenge = await fresh_challenge(mobile)
            await mobile_page.goto(challenge['authorizationUrl'], wait_until='networkidle')
            await assert_mobile_consent(mobile_page)
            file = output / 'consent-mobile.png'
            await mobile_page.screenshot(path=str(file), full_page=True)
            shots.append(str(file))
            checks.append('390px mobile layout')
            await mobile.close()
            return checks

        try:
            await console()
            await act('r')
            await expect(page.locator('#grant-pill')).to_have_text('no grant')
            await shot('00-no-grant')
            await act('0')
            await expect(page.locator('#disc-pill')).to_have_text('read · accepted')
            url = await request_consent()
            await shot('01-challenge')

            # A real human denial must not create an active credential.
            await consent_page(url)
            report['checks'].append('Actual capability screen displays exact GS1 scope and grant bounds, and deselection disables approval')
            await page.locator(DENY).click()
            await expect(page.locator('body')).to_contain_text('denied', ignore_case=True)
            await shot('02-denied-by-human')
            await console()
            await expect(page.locator('#grant-pill')).to_have_text('no grant')
            await act('r')
            await expect(page.locator('#verdict-code')).to_have_text('NO_GRANT')
            await expect(page.locator('#verdict-context')).to_have_text('HUMAN CONSENT REQUIRED')
            url = await request_consent()
            await consent_page(url)
            await shot('03-approve-grant', full=False)
            await page.locator(APPROVE).click()
            await expect(page.locator('#consent-result')).to_contain_text('Grant issued')
            await shot('04-approved')

            await console()
            await expect(page.locator('#grant-pill')).to_have_text('active')
            await act('4')
            await expect(page.locator('#seal')).to_have_text('AUTHORIZED')
            await expect(page.locator('#receipt')).to_contain_text('39.80')
            await shot('05-authorized')
            await act('v')
            await expect(page.locator('#crosscheck')).to_have_class('crosscheck ok')
            await shot('06-receipt-verified')

            await act('2')
            await expect(page.locator('#verdict-code')).to_have_text('PRODUCT_OUT_OF_SCOPE')
            await shot('07-wrong-product')
            await act('3')
            await expect(page.locator('#verdict-code')).to_have_text('SPEND_CAP_EXCEEDED')
            await shot('08-over-cap')
            await act('k')
            await expect(page.locator('#seal')).to_have_text('REVOKED')
            await act('4')
            await expect(page.locator('#seal')).to_have_text('DENIED')
            await expect(page.locator('#verdict-code')).to_contain_text('CREDENTIAL_REVOKED')
            await shot('09-revoked-denial')

            await act('a')
            await expect(page.locator('#audit-overlay')).to_have_class('audit-overlay on')
            for event in ['consent.requested', 'credential.verified', 'authorization.approved', 'authorization.denied']:
                await expect(page.locator('#audit-table')).to_contain_text(event)
            await shot('10-ledger', full=False)
            await act('t')
            await expect(page.locator('#audit-verdicts')).to_contain_text('INVALID')
            await shot('11-tamper-rejected', full=False)
            await act('e')
            await expect(page.locator('#audit-export')).to_contain_text('bundle.json')
            await shot('12-exported', full=False)

            if args.record_video:
                remaining = args.duration - (time.monotonic() - started)
                if remaining > 0:
                    await page.wait_for_timeout(remaining * 1000)
            assert not errors, f'Browser errors: {errors}'
            if args.check_variants:
                report['variants'] = await variants()
            report.update(ok=True, audit=await page.locator('#audit-verdicts').inner_text())
        except Exception as error:
            report['failure'] = str(error)
            raise
        finally:
            report['elapsedSeconds'] = round(time.monotonic() - started, 1)
            await context.close()
            if video:
                destination = output / 'consent-demo-backup.webm'
                await video.save_as(str(destination))
                report['video'] = str(destination)
            await browser.close()
            (output / 'consent-browser-report.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2), flush=True)


asyncio.run(main())
