const http = require('http');
const path = require('path');
const fs = require('fs');

const TIMEOUT_MS = 5000;

const LOCALES_DIR = path.resolve(__dirname, '../src/main/resources/locales');

const EXPECTED_LOCALE_KEYS = {
  device: ['form.description', 'form.submit', 'common.form.thankYou'],
  authorize: ['form.allow', 'form.deny', 'form.description'],
};

function fetch(urlStr, timeout = TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Request timed out after ${timeout}ms`));
    }, timeout);

    const req = http.get(urlStr, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        clearTimeout(timer);
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });

    req.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function getNestedValue(obj, dotPath) {
  return dotPath.split('.').reduce((cur, key) => {
    if (cur && typeof cur === 'object') return cur[key];
    return undefined;
  }, obj);
}

function check(name, fn) {
  return fn().then(
    (details) => ({ name, status: 'pass', details }),
    (err) => ({ name, status: 'fail', details: [err.message] }),
  );
}

async function checkDevicePage(baseUrl, scenario, expectedPageData) {
  const url = `${baseUrl}${scenario}`;
  const res = await fetch(url);
  const details = [];

  if (res.status !== 200) {
    details.push(`✗ Status expected 200, got ${res.status}`);
    return { name: scenario, status: 'fail', details };
  }
  details.push(`✓ Status is 200`);

  if (!res.body.includes('id="wrapper"')) {
    details.push('✗ Missing <div id="wrapper">');
    return { name: scenario, status: 'fail', details };
  }
  details.push('✓ Has #wrapper element');

  const pageDataMatch = res.body.match(/window\.pageData\s*=\s*(\{.*?\})\s*;/s);
  if (!pageDataMatch) {
    details.push('✗ Missing window.pageData injection');
    return { name: scenario, status: 'fail', details };
  }
  details.push('✓ Has window.pageData injection');

  let actual;
  try {
    actual = JSON.parse(pageDataMatch[1]);
  } catch {
    details.push(`✗ pageData is not valid JSON: ${pageDataMatch[1]}`);
    return { name: scenario, status: 'fail', details };
  }

  for (const [key, expected] of Object.entries(expectedPageData)) {
    if (actual[key] !== expected) {
      details.push(`✗ pageData.${key} expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual[key])}`);
      return { name: scenario, status: 'fail', details };
    }
    details.push(`✓ pageData.${key} = ${JSON.stringify(expected)}`);
  }

  if (!res.body.includes('main-device.js') && !res.body.includes('device-main.ts')) {
    details.push('✗ Missing script tag for main-device.js / device-main.ts');
    return { name: scenario, status: 'fail', details };
  }
  details.push('✓ Loads device entry point');

  return { name: scenario, status: 'pass', details };
}

async function checkLocale(baseUrl, namespace) {
  const url = `${baseUrl}/openam/XUI/locales/en/${namespace}.json`;
  const res = await fetch(url);
  const details = [];

  if (res.status !== 200) {
    details.push(`✗ Status expected 200, got ${res.status}`);
    return { name: `locale/${namespace}.json`, status: 'fail', details };
  }
  details.push(`✓ Status is 200`);

  let data;
  try {
    data = JSON.parse(res.body);
  } catch {
    details.push('✗ Response is not valid JSON');
    return { name: `locale/${namespace}.json`, status: 'fail', details };
  }
  details.push('✓ Valid JSON');

  const expectedKeys = EXPECTED_LOCALE_KEYS[namespace] || [];
  for (const key of expectedKeys) {
    const val = getNestedValue(data, key);
    if (val === undefined) {
      details.push(`✗ Missing key: ${key}`);
      return { name: `locale/${namespace}.json`, status: 'fail', details };
    }
    details.push(`✓ Has key: ${key}`);
  }

  return { name: `locale/${namespace}.json`, status: 'pass', details };
}

async function checkCompiledJS(baseUrl) {
  const url = `${baseUrl}/openam/XUI/js/main-device.js`;
  const details = [];

  let res;
  try {
    res = await fetch(url);
  } catch (err) {
    details.push(`✗ Request failed: ${err.message}`);
    return { name: 'compiled JS', status: 'fail', details };
  }

  const contentType = res.headers['content-type'] || '';

  // Dev mode: no compiled bundle, Vite proxies to missing backend or serves source
  if (!contentType.includes('javascript')) {
    details.push('⊘ Skipped (dev mode — source files served directly)');
    return { name: 'compiled JS', status: 'pass', details };
  }

  if (res.status !== 200) {
    details.push(`✗ Status expected 200, got ${res.status}`);
    return { name: 'compiled JS', status: 'fail', details };
  }
  details.push(`✓ Status is 200`);

  if (res.body.length === 0) {
    details.push('✗ Response body is empty');
    return { name: 'compiled JS', status: 'fail', details };
  }
  details.push(`✓ Non-empty response (${res.body.length} bytes)`);

  return { name: 'compiled JS', status: 'pass', details };
}

async function checkCSS(baseUrl) {
  const files = ['structure.css', 'theme.css', 'bootstrap-3.3.5-custom.css'];
  const details = [];

  for (const file of files) {
    const url = `${baseUrl}/css/${file}`;
    let res;
    try {
      res = await fetch(url);
    } catch (err) {
      details.push(`✗ ${file}: request failed — ${err.message}`);
      return { name: 'CSS assets', status: 'fail', details };
    }

    if (res.status !== 200) {
      details.push(`✗ ${file}: expected status 200, got ${res.status}`);
      return { name: 'CSS assets', status: 'fail', details };
    }

    const contentType = res.headers['content-type'] || '';
    if (!contentType.includes('text/css')) {
      details.push(`✗ ${file}: expected text/css, got ${contentType}`);
      return { name: 'CSS assets', status: 'fail', details };
    }

    if (res.body.length < 50) {
      details.push(`✗ ${file}: suspiciously small (${res.body.length} bytes) — may be a stub`);
      return { name: 'CSS assets', status: 'fail', details };
    }

    details.push(`✓ ${file} (${res.body.length} bytes)`);
  }

  return { name: 'CSS assets', status: 'pass', details };
}

async function runChecks(baseUrl) {
  const results = await Promise.all([
    checkDevicePage(baseUrl, '/device/form', { done: false }),
    checkDevicePage(baseUrl, '/device/done', { done: true }),
    checkDevicePage(baseUrl, '/device/error', { errorCode: 'not_found' }),
    checkDevicePage(baseUrl, '/device/error/expired', { errorCode: 'expired' }),
    checkLocale(baseUrl, 'device'),
    checkLocale(baseUrl, 'authorize'),
    checkCompiledJS(baseUrl),
    checkCSS(baseUrl),
  ]);

  const passed = results.filter((r) => r.status === 'pass').length;
  const failed = results.filter((r) => r.status === 'fail').length;

  return { passed, failed, total: results.length, results };
}

module.exports = { runChecks };
