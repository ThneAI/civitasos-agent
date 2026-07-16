#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const AGENT = path.resolve(__dirname, '..');
const WORKSPACE = path.resolve(AGENT, '..');
const { chromium } = require(path.join(
  WORKSPACE,
  'civitasos-frontend',
  'node_modules',
  '@playwright',
  'test',
));

const parseArguments = () => {
  const values = {};
  for (let index = 2; index < process.argv.length; index += 2) {
    const key = process.argv[index];
    const value = process.argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error('arguments require --name value');
    values[key.slice(2)] = value;
  }
  if (!values.targets || !values.output) throw new Error('--targets and --output are required');
  return values;
};

const requestJson = (target, method, requestPath, body, token) => new Promise((resolve, reject) => {
  const encoded = body === undefined ? null : Buffer.from(JSON.stringify(body));
  const headers = { Host: `${target.hostname}:${target.frontend_port}`, Accept: 'application/json' };
  if (encoded) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = encoded.length;
  }
  if (token) headers.Authorization = `Bearer ${token}`;
  const request = https.request({
    hostname: target.ip,
    port: target.frontend_port,
    path: requestPath,
    method,
    headers,
    rejectUnauthorized: false,
  }, response => {
    const chunks = [];
    response.on('data', chunk => chunks.push(chunk));
    response.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      let parsed = {};
      if (text) {
        try { parsed = JSON.parse(text); } catch { parsed = { text }; }
      }
      resolve({ status: response.statusCode, body: parsed });
    });
  });
  request.once('error', reject);
  if (encoded) request.write(encoded);
  request.end();
});

const main = async () => {
  const args = parseArguments();
  const targets = JSON.parse(fs.readFileSync(args.targets, 'utf8'));
  if (!Array.isArray(targets) || targets.length !== 3) throw new Error('targets must contain exactly three nodes');
  const hostRules = targets.map(target => `MAP ${target.hostname} ${target.ip}`).join(', ');
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome',
    args: [`--host-resolver-rules=${hostRules}`],
  });
  const observations = [];
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'civitasos-p4ef-browser-'));
  try {
    for (const target of targets) {
      const serviceSecret = fs.readFileSync(target.service_secret_file, 'utf8').trim();
      const service = await requestJson(target, 'POST', '/api/v1/auth/service-token', {
        service_id: `p4ef-browser-${target.node_id}`,
        secret: serviceSecret,
        scopes: ['agents:write', 'pool:read'],
      });
      if (service.status !== 200 || !service.body.data?.token) {
        throw new Error(`${target.node_id} service bootstrap failed`);
      }
      const serviceToken = service.body.data.token;
      const keyPair = crypto.generateKeyPairSync('ed25519');
      const seedHex = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex');
      const publicKeyHex = keyPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
      const identitySuffix = crypto.randomBytes(6).toString('hex');
      const quickstart = await requestJson(target, 'POST', '/api/v1/a2a/quickstart', {
        public_key: publicKeyHex,
        alias: `p4ef-browser-${target.node_id}-${identitySuffix}`,
        name: `P4-EF Browser ${target.node_id}`,
        endpoint: '',
      }, serviceToken);
      const agentId = quickstart.body.agent?.did || quickstart.body.data?.agent?.did;
      if (![200, 201].includes(quickstart.status) || !agentId) {
        const detail = quickstart.body.error || quickstart.body.hint || 'missing agent DID';
        throw new Error(`${target.node_id} DID quickstart failed (${quickstart.status}): ${detail}`);
      }
      const identityPath = path.join(tempRoot, `${target.node_id}-identity.json`);
      fs.writeFileSync(identityPath, JSON.stringify({
        agent_id: agentId,
        public_key_hex: publicKeyHex,
        seed_hex: seedHex,
      }), { mode: 0o600 });

      const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'zh-CN' });
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          ctap2Version: 'ctap2_1',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      const origin = `https://${target.hostname}:${target.frontend_port}`;
      await page.goto(origin);
      if (!await page.evaluate(() => globalThis.isSecureContext)) {
        throw new Error(`${target.node_id} browser context is not secure`);
      }
      await page.getByRole('button', { name: '登录', exact: true }).click();
      await page.locator('input[type="file"]').setInputFiles(identityPath);
      await page.getByRole('button', { name: '签名登录', exact: true }).click();
      await page.locator('.header-agent').waitFor();
      await page.getByRole('button', { name: '凭据', exact: true }).click();
      await page.getByRole('button', { name: '登记当前设备', exact: true }).click();
      await page.getByText('通行密钥已登记，可在下次登录时使用').waitFor();
      const credentialId = await page.evaluate(() =>
        localStorage.getItem('civitasos.webauthn.credential_id'));
      if (!credentialId) throw new Error(`${target.node_id} browser registration did not persist credential ID`);

      await page.getByRole('button', { name: '退出', exact: true }).click();
      await page.reload();
      await page.getByRole('button', { name: '登录', exact: true }).click();
      await page.getByRole('button', { name: '通行密钥', exact: true }).click();
      await page.getByLabel('WebAuthn credential ID').fill(credentialId);
      await page.getByRole('button', { name: '使用通行密钥', exact: true }).click();
      await page.locator('.header-agent').waitFor();
      const webauthnToken = await page.evaluate(() => sessionStorage.getItem('civitasos_token'));
      const protectedBefore = await requestJson(
        target, 'GET', '/api/v1/a2a/pool/tasks', undefined, webauthnToken);
      if (protectedBefore.status !== 200) throw new Error(`${target.node_id} WebAuthn token was rejected`);

      page.once('dialog', dialog => dialog.accept());
      await page.getByRole('button', { name: '凭据', exact: true }).click();
      await page.getByRole('button', { name: '撤销已保存通行密钥', exact: true }).click();
      await page.getByText('通行密钥已从后端认证存储中撤销').waitFor();
      const protectedAfter = await requestJson(
        target, 'GET', '/api/v1/a2a/pool/tasks', undefined, webauthnToken);
      if (protectedAfter.status !== 401) throw new Error(`${target.node_id} revoked token remained valid`);
      observations.push({
        node_id: target.node_id,
        hostname: target.hostname,
        did_challenge_login: true,
        secure_context: true,
        credential_sha256: crypto.createHash('sha256').update(credentialId).digest('hex'),
        protected_before_revoke_status: protectedBefore.status,
        protected_after_revoke_status: protectedAfter.status,
        passed: true,
      });
      await context.close();
      fs.rmSync(identityPath, { force: true });
    }
  } finally {
    await browser.close();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
  const report = {
    schema_version: 'civitasos-p4ef-multivm-browser-webauthn:v1',
    passed: observations.length === 3 && observations.every(item => item.passed),
    node_count: observations.length,
    observations,
    boundaries: {
      public_ingress_opened: false,
      production_data_used: false,
      virtual_authenticator_proves_hardware_provenance: false,
      service_token_bootstrap_is_production_identity: false,
    },
  };
  const output = path.resolve(args.output);
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
};

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
