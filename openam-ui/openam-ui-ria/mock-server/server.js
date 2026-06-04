const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const COMPILED_GRUNT_DIR = path.join(ROOT_DIR, 'target', 'compiled');
const LOCALES_DIR = path.join(ROOT_DIR, 'src', 'main', 'resources', 'locales');
const STUB_DIR = path.join(__dirname, 'stub-assets');
const VUE_DIR = path.join(ROOT_DIR, 'src', 'main', 'vue');

const PORT = parseInt(process.env.PORT, 10) || 3001;
const reset = '\x1b[0m';

function getDevicePageData(pathname) {
  const parts = pathname.split('/').filter(Boolean);
  const scenario = parts[1];
  if (scenario === 'form') return { realm: '/', locale: 'en', baseUrl: '/openam/XUI', done: false };
  if (scenario === 'done') return { realm: '/', locale: 'en', baseUrl: '/openam/XUI', done: true };
  if (scenario === 'error') return { realm: '/', locale: 'en', baseUrl: '/openam/XUI', errorCode: parts[2] || 'not_found' };
  return null;
}

function getAuthorizePageData(pathname) {
  const parts = pathname.split('/').filter(Boolean);
  const scenario = parts[1];
  if (scenario === 'consent') {
    return {
      realm: '/',
      locale: 'en',
      baseUrl: '/openam/XUI',
      oauth2Data: {
        displayName: 'Test Application',
        displayDescription: 'This app wants to access your profile',
        displayScopes: [
          { name: 'read your profile', values: { email: 'user@example.com', name: 'John Doe' } },
          { name: 'read your emails', values: 'Access to all emails' },
          { name: 'no details scope' },
        ],
        displayClaims: [
          { name: 'email claim', values: 'user@example.com' },
          { name: 'empty claim' },
        ],
        formTarget: '/authorize/consent',
        userName: 'john.doe',
        responseType: 'code',
        clientId: 'test-client',
        csrf: 'mock-csrf-token',
        isSaveConsentEnabled: true,
      },
    };
  }
  if (scenario === 'consent-no-details') {
    return {
      realm: '/',
      locale: 'en',
      baseUrl: '/openam/XUI',
      oauth2Data: {
        displayName: 'Simple App',
        displayScopes: [],
        displayClaims: [],
        formTarget: '/authorize/consent-no-details',
        responseType: 'code',
        clientId: 'simple-client',
        csrf: 'mock-csrf-token',
      },
      noScopes: true,
    };
  }
  if (scenario === 'error') {
    return {
      realm: '/',
      locale: 'en',
      baseUrl: '/openam/XUI',
      error: {
        message: 'Access denied',
        description: 'The resource owner denied the request.',
      },
    };
  }
  if (scenario === 'error-with-uri') {
    return {
      realm: '/',
      locale: 'en',
      baseUrl: '/openam/XUI',
      error: {
        uri: 'https://example.com/help',
        message: 'Something went wrong',
        description: 'Please contact your administrator.',
      },
    };
  }
  return null;
}

function buildDeviceHtml(pageData) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OpenAM — Device</title>
</head>
<body style="display:none">
  <div id="wrapper"></div>
  <script type="module">
    window.pageData = ${JSON.stringify(pageData)};
  </script>
  <script type="module" src="/device-main.ts"></script>
</body>
</html>`;
}

function buildAuthorizeHtml(pageData) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OpenAM — Authorize</title>
</head>
<body style="display:none">
  <div id="wrapper"></div>
  <script type="module">
    window.pageData = ${JSON.stringify(pageData)};
  </script>
  <script type="module" src="/authorize-main.ts"></script>
</body>
</html>`;
}

function buildLandingHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OpenAM Vue Mock Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }
    h1 { border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; }
    a { color: #3498db; text-decoration: none; }
    a:hover { text-decoration: underline; }
    li { margin: 6px 0; }
    .status { padding: 10px; border-radius: 5px; background: #2ecc71; color: #fff; margin: 15px 0; }
    .note { color: #888; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>OpenAM Vue Mock Server</h1>
  <div class="status">Vite dev server — source maps active, HMR enabled</div>

  <h2>Device Flow Scenarios</h2>
  <ul>
    <li><a href="/device/form">/device/form</a> — Code entry form (pending state)</li>
    <li><a href="/device/done">/device/done</a> — Success / completion page</li>
    <li><a href="/device/error">/device/error</a> — Error: not_found</li>
    <li><a href="/device/error/expired">/device/error/expired</a> — Error: expired</li>
  </ul>

  <h2>Authorize Flow Scenarios</h2>
  <ul>
    <li><a href="/authorize/consent">/authorize/consent</a> — Consent page with scopes and claims</li>
    <li><a href="/authorize/consent-no-details">/authorize/consent-no-details</a> — Consent page (no scopes/claims)</li>
    <li><a href="/authorize/error">/authorize/error</a> — Error: access denied</li>
    <li><a href="/authorize/error-with-uri">/authorize/error-with-uri</a> — Error with help link</li>
  </ul>

  <h2>Login Flow Scenarios</h2>
  <ul>
    <li><a href="/#/login">/#/login</a> — Login form (mock DataStore1 stage)</li>
    <li><a href="/#/loggedOut">/#/loggedOut</a> — Logged out page</li>
    <li><a href="/#/failedLogin">/#/failedLogin</a> — Login failure page</li>
    <li><a href="/#/sessionExpired">/#/sessionExpired</a> — Session expired page</li>
  </ul>

  <h2>Diagnostics</h2>
  <ul>
    <li><a href="/test">/test</a> — Run test suite (JSON report)</li>
  </ul>

  <h2>Assets</h2>
  <ul>
    <li><a href="/openam/XUI/locales/en/device.json">locales/en/device.json</a></li>
    <li><a href="/openam/XUI/locales/en/authorize.json">locales/en/authorize.json</a></li>
    <li><a href="/css/structure.css">css/structure.css</a></li>
    <li><a href="/css/theme.css">css/theme.css</a></li>
  </ul>

  <p class="note">Open DevTools Sources tab — set breakpoints in original .vue and .ts files.</p>
</body>
</html>`;
}

function getContentType(filePath) {
  const ext = path.extname(filePath);
  const types = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.svg': 'image/svg+xml',
  };
  return types[ext] || 'application/octet-stream';
}

function serveStaticFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': getContentType(filePath) });
    res.end(data);
  });
}

function logReq(method, pathname, status, ms) {
  const color = status >= 400 ? '\x1b[31m' : '\x1b[32m';
  console.log(`${color}${status}${reset} ${method} ${pathname} (${ms}ms)`);
}

const MOCK_API_RESPONSES = {
  '/openam/json/authenticate': {
    success: true,
    token: { tokenId: 'mock-token-abc123' },
    callbacks: [],
  },
};

const MOCK_AUTH_STATE = {
  authId: null,
  stage: 0,
};

function buildMockAuthenticateResponse(body) {
  const authId = MOCK_AUTH_STATE.authId;

  if (authId && body && body.authId === authId) {
    MOCK_AUTH_STATE.authId = null;
    MOCK_AUTH_STATE.stage = 0;
    return {
      tokenId: 'mock-session-token-' + Date.now(),
      realm: '/',
      successUrl: '/openam/console',
    };
  }

  if (!authId) {
    MOCK_AUTH_STATE.authId = 'mock-auth-id-' + Date.now();
    MOCK_AUTH_STATE.stage = 1;
    return {
      authId: MOCK_AUTH_STATE.authId,
      realm: '/',
      stage: 'DataStore1',
      callbacks: [
        {
          type: 'TextInputCallback',
          output: [{ name: 'prompt', value: 'User Name' }],
          input: [{ name: 'input', value: '' }],
        },
        {
          type: 'PasswordCallback',
          output: [{ name: 'prompt', value: 'Password' }],
          input: [{ name: 'password', value: '' }],
        },
        {
          type: 'ConfirmationCallback',
          output: [
            { name: 'prompt', value: '' },
            { name: 'options', value: ['Login'] },
            { name: 'optionType', value: 0 },
            { name: 'defaultOption', value: 0 },
            { name: 'value', value: false },
          ],
          input: [{ name: 'loginButton', value: 0 }],
        },
      ],
    };
  }

  return {
    authId: MOCK_AUTH_STATE.authId,
    realm: '/',
    stage: 'DataStore1',
    callbacks: [
      {
        type: 'TextInputCallback',
        output: [{ name: 'prompt', value: 'User Name' }],
        input: [{ name: 'input', value: '' }],
      },
      {
        type: 'PasswordCallback',
        output: [{ name: 'prompt', value: 'Password' }],
        input: [{ name: 'password', value: '' }],
      },
      {
        type: 'ConfirmationCallback',
        output: [
          { name: 'prompt', value: '' },
          { name: 'options', value: ['Login'] },
          { name: 'optionType', value: 0 },
          { name: 'defaultOption', value: 0 },
          { name: 'value', value: false },
        ],
        input: [{ name: 'loginButton', value: 0 }],
      },
    ],
  };
}

function buildMockServerInfoResponse() {
  return {
    cookieName: 'iPlanetDirectoryPro',
    cookieDomains: ['localhost'],
    cookieSameSite: 'none',
    secureCookie: false,
    zeroPageLogin: { enabled: false, allowedWithoutReferer: false, refererWhitelist: [] },
    forgotPassword: 'true',
    forgotUsername: 'true',
    selfRegistration: 'true',
    socialImplementations: [],
  };
}

function buildMockSessionInfoResponse() {
  return {
    username: 'demo',
    realm: '/',
    sessionHandle: 'mock-handle',
  };
}

// Vite plugin that injects mock middleware BEFORE Vite's internal middleware
function mockDataPlugin() {
  return {
    name: 'openam-mock-data',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const parsed = new URL(req.url, `http://localhost:${PORT}`);
        const pathname = parsed.pathname;
        const method = req.method;
        const start = Date.now();

        // Landing page
        if (pathname === '/' && method === 'GET') {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(buildLandingHtml());
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Theme CSS — must come before device page handler so /device/error/css/... is served correctly
        const cssMatch = pathname.match(/^(.*)\/css\/(.+)$/);
        if (cssMatch && method === 'GET') {
          const file = cssMatch[2];
          const compiledPath = path.join(COMPILED_GRUNT_DIR, 'css', file);
          const stubPath = path.join(STUB_DIR, 'css', file);
          const filePath = fs.existsSync(compiledPath) ? compiledPath : stubPath;
          serveStaticFile(res, filePath);
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Images — must come before device page handler so /device/error/images/... is served correctly
        const imageMatch = pathname.match(/^(.*)\/images\/(.+)$/);
        if (imageMatch && method === 'GET') {
          const file = imageMatch[2];
          const compiledPath = path.join(COMPILED_GRUNT_DIR, 'images', file);
          const stubPath = path.join(STUB_DIR, 'images', file);
          const filePath = fs.existsSync(compiledPath) ? compiledPath : stubPath;
          serveStaticFile(res, filePath);
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Favicon
        if (pathname === '/favicon.ico' && method === 'GET') {
          const compiledPath = path.join(COMPILED_GRUNT_DIR, 'favicon.ico');
          const stubPath = path.join(STUB_DIR, 'favicon.ico');
          serveStaticFile(res, fs.existsSync(compiledPath) ? compiledPath : stubPath);
          return;
        }

        // Locale files
        const localeMatch = pathname.match(/^\/openam\/XUI\/locales\/([^/]+)\/([^/]+)\.json$/);
        if (localeMatch && method === 'GET') {
          const [, locale, namespace] = localeMatch;
          const filePath = path.join(LOCALES_DIR, locale, `${namespace}.json`);
          if (fs.existsSync(filePath)) {
            serveStaticFile(res, filePath);
          } else {
            res.writeHead(404);
            res.end('Not Found');
          }
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Device flow pages
        if (/^\/device\/(form|done|error)/.test(pathname) && method === 'GET') {
          const pageData = getDevicePageData(pathname);
          if (!pageData) {
            res.writeHead(404);
            res.end('Unknown scenario');
            return;
          }
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(buildDeviceHtml(pageData));
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Authorize flow pages
        if (/^\/authorize\/(consent|error)/.test(pathname) && method === 'GET') {
          const pageData = getAuthorizePageData(pathname);
          if (!pageData) {
            res.writeHead(404);
            res.end('Unknown scenario');
            return;
          }
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(buildAuthorizeHtml(pageData));
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Test endpoint
        if (pathname === '/test' && method === 'GET') {
          const { runChecks } = require('./checks');
          runChecks(`http://localhost:${PORT}`).then((report) => {
            const body = JSON.stringify(report);
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(body);
            logReq(method, pathname, 200, Date.now() - start);
          });
          return;
        }

        // Mock REST API
        if (pathname.startsWith('/openam/json/') && (method === 'GET' || method === 'POST')) {
          let mockData = MOCK_API_RESPONSES[pathname] || {};

          if (pathname === '/openam/json/authenticate' && method === 'POST') {
            let body = '';
            req.on('data', (chunk) => { body += chunk; });
            req.on('end', () => {
              try {
                const parsed = body ? JSON.parse(body) : {};
                mockData = buildMockAuthenticateResponse(parsed);
              } catch {
                mockData = buildMockAuthenticateResponse(null);
              }
              const responseBody = JSON.stringify(mockData);
              res.setHeader('Content-Type', 'application/json; charset=utf-8');
              res.end(responseBody);
              logReq(method, pathname, 200, Date.now() - start);
            });
            return;
          }

          if (pathname === '/openam/json/serverinfo/*' && method === 'GET') {
            mockData = buildMockServerInfoResponse();
            const responseBody = JSON.stringify(mockData);
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(responseBody);
            logReq(method, pathname, 200, Date.now() - start);
            return;
          }

          if (pathname === '/openam/json/sessions' && method === 'POST') {
            mockData = buildMockSessionInfoResponse();
            const responseBody = JSON.stringify(mockData);
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(responseBody);
            logReq(method, pathname, 200, Date.now() - start);
            return;
          }

          if (pathname.startsWith('/openam/json/users') && method === 'POST') {
            mockData = {
              username: 'demo',
              realm: '/',
              roles: ['ui-user'],
              uiroles: ['ui-user'],
            };
            const responseBody = JSON.stringify(mockData);
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(responseBody);
            logReq(method, pathname, 200, Date.now() - start);
            return;
          }

          const body = JSON.stringify(mockData);
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.end(body);
          logReq(method, pathname, 200, Date.now() - start);
          return;
        }

        // Not handled — fall through to Vite
        next();
      });
    },
  };
}

async function createViteServer(port) {
  const { createServer } = require('vite');
  const vue = require('@vitejs/plugin-vue').default;
  const listenPort = port || PORT;

  const vite = await createServer({
    root: VUE_DIR,
    configFile: false,
    plugins: [vue(), mockDataPlugin()],
    resolve: {
      alias: {
        '@': VUE_DIR,
      },
    },
    server: {
      port: listenPort,
      strictPort: true,
      proxy: {},
    },
  });

  await vite.listen();

  console.log('');
  console.log('  OpenAM Vue Mock Server (dev mode)');
  console.log('  ================================');
  console.log(`  http://localhost:${listenPort}/`);
  console.log(`  http://localhost:${listenPort}/device/form`);
  console.log(`  http://localhost:${listenPort}/device/done`);
  console.log(`  http://localhost:${listenPort}/device/error`);
  console.log(`  http://localhost:${listenPort}/authorize/consent`);
  console.log(`  http://localhost:${listenPort}/authorize/error`);
  console.log(`  http://localhost:${listenPort}/#/login`);
  console.log(`  http://localhost:${listenPort}/test`);
  console.log('');
  console.log('  Source maps active — DevTools shows original .vue/.ts files');
  console.log('');

  return vite;
}

if (require.main === module) {
  createViteServer();
}

module.exports = { createViteServer };
