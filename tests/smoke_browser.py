"""Browser smoke test: opens dist/capsight.html, loads the sample, visits every view and downloads reports.

Needs Python Playwright and a Chromium/Chrome build:  pip install playwright && playwright install chromium
Run:  python3 tests/smoke_browser.py   (exits non-zero on any page error; set CHROME_PATH to use an installed Chrome)
"""
import asyncio, os, pathlib, sys
from playwright.async_api import async_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
VIEWS = ['overview', 'threats', 'conversations', 'packets', 'artifacts', 'insights']

async def main():
    errors = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=os.environ.get('CHROME_PATH') or None)
        context = await browser.new_context(viewport={'width': 1440, 'height': 900}, accept_downloads=True)
        page = await context.new_page()
        page.on('pageerror', lambda e: errors.append(str(e)))
        # the Capture dialog looks for the helper on 127.0.0.1:47115; a refused connection there is expected
        page.on('console', lambda m: errors.append(m.text) if m.type == 'error' and 'ERR_CONNECTION_REFUSED' not in m.text and '47115' not in m.text else None)
        await page.goto((ROOT / 'dist' / 'capsight.html').as_uri())
        # Capture live traffic: the dialog opens and offers the helper download when it isn't running
        await page.click('.lcta [data-capture] >> nth=0')
        await page.wait_for_selector('#capture-page.on a[href$="capsight-capture.zip"]', timeout=8000)
        await page.click('#backBtn')
        await page.wait_for_selector('#landing.on', timeout=5000)
        await page.click('#demoBtn')
        await page.wait_for_selector('#view-overview.on', timeout=20000)
        for v in VIEWS:
            await page.click(f'.tab[data-view={v}]')
            await page.wait_for_timeout(700)
        await page.click('.tab[data-view=artifacts]')
        await page.wait_for_selector('#dlEverything', timeout=10000)
        async with page.expect_download() as dl:
            await page.click('#dlEverything')
        if not (await dl.value).suggested_filename.endswith('_artifacts.zip'):
            errors.append('artifact zip download has an unexpected name')
        # findings report: Markdown and Word downloads, passwords masked by default
        await page.click('#reportBtn')
        async with page.expect_download() as dl:
            await page.click('.rpt-opt[data-fmt=md]')
        md_path = await (await dl.value).path()
        md = open(md_path, encoding='utf-8').read()
        if '25 security detections' not in md or 'Summer2026!' in md:
            errors.append('report is missing detections or shows a password it should mask')
        async with page.expect_download() as dl:
            await page.click('.rpt-opt[data-fmt=docx]')
        if not (await dl.value).suggested_filename.endswith('_report.docx'):
            errors.append('Word report has an unexpected name')
        await page.click('#mclose')
        await page.click('.tab[data-view=packets]')
        await page.fill('#fin', 'ip:10.0.0.20 port:4444')
        await page.wait_for_timeout(500)
        count = await page.inner_text('#fcount')
        # Clear filter removes the text and every chip, then hides itself
        await page.click('#clearAll')
        await page.wait_for_timeout(400)
        if await page.input_value('#fin') or 'of' in await page.inner_text('#fcount') or await page.is_visible('#clearAll'):
            errors.append('Clear filter did not reset the filter')
        # Back button returns to the start page; browser Forward reopens the capture; browser Back returns again
        await page.click('#backBtn')
        await page.wait_for_selector('#landing.on', timeout=5000)
        if await page.is_visible('#tabs') or await page.is_visible('#backBtn'):
            errors.append('capture UI still visible on the start page')
        await page.go_forward()
        await page.wait_for_selector('#view-packets.on', timeout=5000)
        await page.go_back()
        await page.wait_for_selector('#landing.on', timeout=5000)
        await page.click('#demoBtn')
        await page.wait_for_selector('#view-overview.on', timeout=20000)
        await page.click('#backBtn')
        await page.wait_for_selector('#landing.on', timeout=5000)
        await browser.close()
    if '27 of' not in count:
        errors.append('filter returned unexpected count: ' + count)
    for e in errors:
        print('ERROR', e)
    print('smoke test', 'failed' if errors else 'passed')
    sys.exit(1 if errors else 0)

asyncio.run(main())
