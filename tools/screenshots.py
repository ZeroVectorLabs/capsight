"""Retake the README screenshots and the start-page app images from dist/capsight.html.

Usage: python3 tools/screenshots.py   (needs Python Playwright with Chromium, and Pillow)
Writes docs/screenshots/*.png and assets/shot-{dark,light}.webp. Run `npm run build` again
afterwards so the new start-page images are embedded in the bundle.
"""
import asyncio, io, os, pathlib
from PIL import Image
from playwright.async_api import async_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / 'docs' / 'screenshots'


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=os.environ.get('CHROME_PATH') or None)
        page = await browser.new_page(viewport={'width': 1440, 'height': 900})

        async def shot(name):
            await page.wait_for_timeout(700)
            await page.screenshot(path=str(OUT / f'{name}.png'))

        async def theme(t):
            await page.evaluate(f"document.documentElement.dataset.theme = '{t}'; window.dispatchEvent(new Event('resize'))")
            await page.wait_for_timeout(900)

        async def tab(v):
            await page.click(f'.tab[data-view={v}]')
            await page.evaluate('window.scrollTo(0, 0)')
            await page.wait_for_timeout(900)

        await page.goto((ROOT / 'dist' / 'capsight.html').as_uri())
        await theme('dark')
        await shot('landing')
        await page.click('#demoBtn')
        await page.wait_for_selector('#view-overview.on', timeout=20000)
        await page.wait_for_timeout(1200)
        for t in ('light', 'dark'):
            await theme(t)
            await shot('overview' if t == 'dark' else 'overview-light')
            png = await page.screenshot()
            Image.open(io.BytesIO(png)).convert('RGB').resize((1200, 750), Image.LANCZOS) \
                .save(ROOT / 'assets' / f'shot-{t}.webp', quality=80, method=6)

        await tab('threats')
        await shot('threats')
        await page.evaluate("const c = document.querySelector('#seq').closest('.card'); window.scrollTo(0, c.getBoundingClientRect().top + window.scrollY - 150)")
        await shot('attack-flow')

        await tab('conversations')
        await page.wait_for_timeout(1500)
        await shot('network-map')

        await tab('packets')
        await page.fill('#fin', 'ip:10.0.0.20 port:4444')
        await page.wait_for_timeout(600)
        await page.locator('#pbody').get_by_text('1998', exact=True).first.click()
        await shot('packets')
        await page.fill('#fin', '')

        await tab('artifacts')
        await shot('artifacts-files')
        await page.click('.seg [data-v=gallery]')
        await page.wait_for_timeout(400)
        await page.locator('.gcard img[alt="team-offsite.jpg"]').click()
        await shot('artifacts-gallery')
        for sub, name in (('creds', 'credentials'), ('iocs', 'indicators'), ('hosts', 'hosts')):
            await page.click(f'.subnav [data-sub={sub}]')
            await page.evaluate('window.scrollTo(0, 0)')
            await shot('artifacts-' + name)
        await browser.close()
    print('screenshots updated')

asyncio.run(main())
