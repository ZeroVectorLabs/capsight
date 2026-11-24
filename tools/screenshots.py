"""Retake the README screenshots and the start-page app images from dist/capsight.html.

Usage: python3 tools/screenshots.py   (needs Python Playwright with Chromium, and Pillow)
Writes docs/screenshots/*.png and the start-page images assets/shot-*.webp and assets/tile-*.webp. Run `npm run build` again
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
        await page.close()

        # start-page images, at 1.5x for sharp edges: the laptop screen and three feature tiles
        page = await browser.new_page(viewport={'width': 1440, 'height': 900}, device_scale_factor=1.5)
        await page.goto((ROOT / 'dist' / 'capsight.html').as_uri())
        await page.click('#demoBtn')
        await page.wait_for_selector('#view-overview.on', timeout=20000)

        async def save(name, box=None, size=None):
            await page.wait_for_timeout(800)
            im = Image.open(io.BytesIO(await page.screenshot())).convert('RGB')
            if box:
                im = im.crop(tuple(int(v * 1.5) for v in box))
            if size:
                im = im.resize(size, Image.LANCZOS)
            im.save(ROOT / 'assets' / f'{name}.webp', quality=76, method=6)

        for t in ('dark', 'light'):
            await theme(t)
            await tab('overview')
            await save(f'shot-{t}', size=(1800, 1125))
            await tab('threats')
            await page.evaluate("const c = document.querySelector('#seq').closest('.card'); window.scrollTo(0, c.getBoundingClientRect().top + window.scrollY - 150)")
            await save(f'tile-flow-{t}', (0, 0, 1100, 640))
            await tab('conversations')
            await page.wait_for_timeout(1200)
            await save(f'tile-map-{t}', (14, 176, 1114, 776))
            await tab('artifacts')
            await save(f'tile-files-{t}', (0, 52, 1100, 652))
        await browser.close()
    print('screenshots updated')

asyncio.run(main())
