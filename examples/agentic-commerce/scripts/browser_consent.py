"""Shared assertions for the actual package capability screen in browser demos."""
import re

from playwright.async_api import expect

GS1_SCOPE = 'https://id.gs1.org/01/09506000134352'
SCREEN = 'consent-capabilities-screen'
APPROVE = SCREEN + ' consent-action-bar button.primary'
DENY = SCREEN + ' consent-action-bar button.secondary'


async def rendered_text(page):
    """Read visible light and shadow DOM, excluding script and hidden fallback copy."""
    return await page.evaluate('''() => {
      const read = (node) => {
        if (!node) return '';
        if (node.nodeType === Node.TEXT_NODE) return node.textContent;
        if (!(node instanceof Element || node instanceof ShadowRoot)) return '';
        if (node instanceof Element) {
          if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.tagName)) return '';
          const style = getComputedStyle(node);
          if (style.display === 'none' || style.visibility === 'hidden') return '';
          if (node.tagName === 'DETAILS' && !node.open)
            return read(node.querySelector(':scope > summary'));
          if (node.tagName === 'SLOT') {
            const assigned = node.assignedNodes({flatten: true});
            return [...(assigned.length ? assigned : node.childNodes)].map(read).join(' ');
          }
          if (node.shadowRoot) return read(node.shadowRoot);
        }
        return [...node.childNodes].map(read).join(' ');
      };
      return read(document.body).replace(/\\s+/g, ' ').trim();
    }''')


async def assert_capability_consent(page, expected_bindings=None):
    screen = page.locator(SCREEN)
    await expect(screen).to_be_visible()
    await expect(page.locator('mcp-consent')).to_have_count(0)
    await expect(page.locator(APPROVE)).to_be_visible()
    await expect(page.locator(APPROVE)).to_have_accessible_name(re.compile(r'^Approve grant(?: with passkey)?$'))
    await expect(page.locator(DENY)).to_have_text('Deny')
    cards = screen.locator('consent-capability-card')
    await expect(cards).to_have_count(1)
    await expect(cards.get_by_text(GS1_SCOPE, exact=True)).to_be_visible()
    text = await rendered_text(page)
    for expected in ['09506000134352', GS1_SCOPE, 'CHF 50.00', 'place_order']:
        assert expected in text, f'Capability consent omits {expected}'
    for unsupported in [r'90\s+days', r'days of inactivity', r'Cedar policy',
                        r'Use your saved payment methods', r'Ship to (?:your saved|new) addresses']:
        assert not re.search(unsupported, text, re.I), f'Unsupported demo consent claim: {unsupported}'
    await expect(screen.get_by_role('button', name='View policy', exact=True)).to_have_count(0)
    await expect(page.locator('.grant-notice')).to_have_count(0)
    for removed in ['Your Google account identifies you.', 'You can revoke this grant from the demo console',
                    'Confirm with the passkey linked to this Google account']:
        assert removed not in text, f'Removed notice copy is still visible: {removed}'
    expiry = page.locator('#grant-expiry')
    await expect(expiry).to_be_visible()
    hours = await expiry.get_attribute('data-valid-hours')
    assert hours and float(hours) > 0, 'Consent must expose its actual grant validity'
    await expect(expiry).to_contain_text(hours + ' hours from approval')
    if expected_bindings:
        assert float(hours) == expected_bindings['validHours']
        for key in ['audience', 'productClass']:
            assert expected_bindings[key] in text, f'Consent omits bound {key}'
        details = screen.locator('summary').filter(has_text='View grant details')
        await details.click()
        await expect(screen.get_by_text(expected_bindings['agentDid'], exact=True)).to_be_visible()
        await details.click()

    # Selection must change the actual package action, not an imitation wrapper.
    checkbox = screen.get_by_role('checkbox')
    await expect(checkbox).to_be_checked()
    await checkbox.click()
    await expect(checkbox).not_to_be_checked()
    await expect(page.locator(APPROVE)).to_be_disabled()
    await expect(page.locator(DENY)).to_be_enabled()
    await checkbox.click()
    await expect(checkbox).to_be_checked()
    await expect(page.locator(APPROVE)).to_be_enabled()
    assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Consent layout overflows its viewport'
    await page.evaluate('window.scrollTo(0, 0)')
    await assert_single_column_consent(page)


async def assert_single_column_consent(page):
    screen = page.locator(SCREEN)
    card = await screen.locator('[part="card"]').bounding_box()
    assert card and card['width'] <= 640, f'Consent card must stay at most 640px wide: {card}'
    regions = [screen.locator('[slot="identity"]'), screen.locator('[part="agent"]'),
               screen.locator('[part="permissions"]'), screen.locator('[slot="details"]'),
               screen.locator('[slot="notice"]'), screen.locator('[part="actions"]')]
    bounds = [await region.bounding_box() for region in regions if await region.is_visible()]
    for previous, current in zip(bounds, bounds[1:]):
        assert previous and current and current['y'] >= previous['y'] + previous['height'] - 1, 'Consent sections must follow one vertical column'
    await expect(page.locator('.masthead')).to_have_count(0)
    await expect(page.locator('main > .provenance')).to_have_count(0)
    assert await page.locator('#decision-status').evaluate("node => !!node.closest('consent-capabilities-screen')"), 'Decision feedback must be inside the card'


async def assert_mobile_consent(page):
    await expect(page.locator(APPROVE)).to_be_visible()
    await expect(page.locator(SCREEN).locator('consent-capability-card').get_by_text(GS1_SCOPE, exact=True)).to_be_visible()
    assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Consent page overflows a 390px mobile viewport'
    await assert_single_column_consent(page)
