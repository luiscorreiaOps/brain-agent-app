// Captures real, current screenshots of the plugin for the README /
// plugin.json's info.screenshots -- run against a real local Grafana
// instance with the plugin installed. Update BASE/credentials below to
// match your environment.
const puppeteer = require('puppeteer');
const path = require('path');

const BASE = process.env.SCREENSHOT_BASE_URL || 'http://localhost:3000';
const USER = process.env.SCREENSHOT_USER || 'admin';
const PASSWORD = process.env.SCREENSHOT_PASSWORD || 'admin';
const DIR = path.join(__dirname, '..', 'src', 'img', 'screenshots');

async function login(page) {
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle2' });
  await page.type('input[name="user"]', USER);
  await page.type('input[name="password"]', PASSWORD);
  await Promise.all([
    page.click('button[type="submit"]'),
    page.waitForResponse((r) => r.url().includes('/api/login') && r.status() === 200).catch(() => {}),
  ]);
  await new Promise((r) => setTimeout(r, 1500));
}

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 1000 });
  await login(page);

  console.log('1. Brain Hub...');
  await page.goto(`${BASE}/a/brain-agent/hub`, { waitUntil: 'networkidle2' });
  await new Promise((r) => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(DIR, 'brain-hub.png'), fullPage: true });

  console.log('2. Configuration page...');
  await page.goto(`${BASE}/plugins/brain-agent?page=configuration`, { waitUntil: 'networkidle2' });
  await new Promise((r) => setTimeout(r, 1500));
  await page.screenshot({ path: path.join(DIR, 'configuration-page.png'), fullPage: true });

  await browser.close();
  console.log('\nDone. Screenshots saved to', DIR);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
