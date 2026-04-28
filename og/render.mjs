/*
 * Headless screenshot of the live dashboard for og:image / twitter:image.
 *
 * Runs from the dht44-og.service systemd unit on a daily timer. Output goes
 * straight to the path nginx serves at /og.png — the file inode must already
 * exist with r2d2 as owner (the timer doesn't have write on the directory):
 *
 *   sudo install -m 0644 -o r2d2 -g www-data /dev/null /var/www/dht44.com/og.png
 *
 * Subsequent runs overwrite the file in place via puppeteer's screenshot,
 * which open(O_WRONLY|O_TRUNC)s — directory write is not required.
 *
 * Env overrides:
 *   OG_URL    - page to capture (default https://dht44.com/dashboard/graph)
 *   OG_OUT    - output path     (default /var/www/dht44.com/og.png)
 *   OG_WAIT_MS - extra settle time after networkidle (default 8000)
 */

import puppeteer from 'puppeteer';

const URL    = process.env.OG_URL    || 'https://dht44.com/dashboard/graph';
const OUT    = process.env.OG_OUT    || '/var/www/dht44.com/og.png';
const WAITMS = parseInt(process.env.OG_WAIT_MS || '8000', 10);
const WIDTH  = 1200;
const HEIGHT = 630;

const t0 = Date.now();
const log = (...a) => console.log('[og]', ...a);

/* `headless: 'shell'` uses chrome-headless-shell (already downloaded into
 * ~/.cache/puppeteer/chrome-headless-shell/). It's the headless-only fork
 * and does not bundle crashpad — which avoids "chrome_crashpad_handler:
 * --database is required" when running under systemd PrivateTmp. */
const browser = await puppeteer.launch({
  headless: 'shell',
  args: [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-breakpad',
    '--disable-crash-reporter',
    '--hide-scrollbars',
  ],
  defaultViewport: { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1 },
});

try {
  const page = await browser.newPage();
  page.on('pageerror', e => log('pageerror', e.message));
  log('goto', URL);
  await page.goto(URL, { waitUntil: 'networkidle2', timeout: 30000 });

  /* The 3D graph + WS-driven panels need a moment after networkidle to
   * receive their first /stream batch and lay out. Plain setTimeout —
   * page.waitForTimeout was removed in puppeteer v22. */
  await new Promise(r => setTimeout(r, WAITMS));

  log('screenshot', OUT);
  await page.screenshot({
    path: OUT,
    type: 'png',
    clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT },
  });
  log('done in', Date.now() - t0, 'ms');
} finally {
  await browser.close();
}
