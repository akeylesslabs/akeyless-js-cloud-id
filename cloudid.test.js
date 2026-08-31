'use strict';

/**
 * Hermetic unit tests for the akeyless-cloud-id SDK (cloudid.js).
 *
 * These tests run fully offline. Before requiring the SDK (and, transitively,
 * @aws-sdk/credential-providers / google-auth-library / @azure/identity) we:
 *   - point HOME and the AWS credential/config files at an empty temp dir so no
 *     ambient ~/.aws credentials or profiles can leak in,
 *   - disable the EC2 instance-metadata provider,
 *   - clear any AWS_* credential env vars,
 *   - install a network guard that throws if any TCP socket connect is attempted.
 *
 * The AWS cloud-id path is pure crypto (aws4 SigV4 signing) once credentials are
 * resolved from the environment, so it produces a deterministic token with no
 * network access.
 */

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

// ---------------------------------------------------------------------------
// Hermetic isolation — MUST happen before requiring the SDK / provider libs.
// ---------------------------------------------------------------------------
const isoHome = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudid-test-home-'));
const isoCreds = path.join(isoHome, 'credentials');
const isoConfig = path.join(isoHome, 'config');
// Empty (but existing) files: no profiles/keys inside, so nothing leaks in, yet
// the credential provider can still stat/read them without raising ENOENT.
fs.writeFileSync(isoCreds, '');
fs.writeFileSync(isoConfig, '');
process.env.HOME = isoHome;
process.env.USERPROFILE = isoHome; // Windows equivalent
process.env.AWS_SHARED_CREDENTIALS_FILE = isoCreds;
process.env.AWS_CONFIG_FILE = isoConfig;
process.env.AWS_EC2_METADATA_DISABLED = 'true';
delete process.env.AWS_SDK_LOAD_CONFIG;
delete process.env.AWS_ACCESS_KEY_ID;
delete process.env.AWS_SECRET_ACCESS_KEY;
delete process.env.AWS_SESSION_TOKEN;
delete process.env.AWS_PROFILE;

// Network guard: any attempt to open a real TCP socket during the guarded
// window throws, proving the code path did not touch the network.
const realConnect = net.Socket.prototype.connect;
let networkBlocked = false;
net.Socket.prototype.connect = function guardedConnect(...args) {
  if (networkBlocked) {
    const err = new Error('NETGUARD: TCP socket connect attempted during hermetic test');
    err.netguard = true;
    throw err;
  }
  return realConnect.apply(this, args);
};

const cloudid = require('./cloudid');

// Well-formed but fake credentials (AWS docs example key id + secret).
const FAKE_ACCESS_KEY = 'AKIDEXAMPLE';
const FAKE_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const FAKE_SESSION_TOKEN = 'FQoGZXIvYXdzEXAMPLESESSIONTOKEN//////////fake';

/**
 * Sets fake AWS credential env vars for hermetic unit tests.
 * @param {{session?: boolean}} [opts] When session is true, also sets AWS_SESSION_TOKEN
 */
function setEnvCreds({ session } = {}) {
  process.env.AWS_ACCESS_KEY_ID = FAKE_ACCESS_KEY;
  process.env.AWS_SECRET_ACCESS_KEY = FAKE_SECRET_KEY;
  if (session) {
    process.env.AWS_SESSION_TOKEN = FAKE_SESSION_TOKEN;
  } else {
    delete process.env.AWS_SESSION_TOKEN;
  }
}

/** Clears AWS credential env vars used by hermetic unit tests. */
function clearEnvCreds() {
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
}

// Decode the base64(JSON) cloud-id token into its outer object and the inner
// (also base64-encoded) STS request headers.
function decodeToken(token) {
  assert.strictEqual(typeof token, 'string', 'token should be a string');
  const outer = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
  const headers = JSON.parse(
    Buffer.from(outer.sts_request_headers, 'base64').toString('utf8')
  );
  return { outer, headers };
}

after(() => {
  net.Socket.prototype.connect = realConnect;
  try { fs.rmSync(isoHome, { recursive: true, force: true }); } catch (_) {}
});

// ---------------------------------------------------------------------------
describe('module loads and exports are intact', () => {
  test('exports the documented public API as functions', () => {
    for (const name of ['getCloudId', 'getAWsCloudId', 'getAzureCloudID', 'getGcpCloudID', 'getAlibabaCloudId']) {
      assert.strictEqual(typeof cloudid[name], 'function', `${name} should be a function`);
    }
  });

  test('does not export unexpected extra symbols', () => {
    assert.deepStrictEqual(
      Object.keys(cloudid).sort(),
      ['getAWsCloudId', 'getAlibabaCloudId', 'getAzureCloudID', 'getCloudId', 'getGcpCloudID']
    );
  });
});

// ---------------------------------------------------------------------------
describe('getCloudId provider dispatch', () => {
  beforeEach(() => clearEnvCreds());

  test('access_key type resolves to an empty string (no cloud-id needed)', async () => {
    const result = await cloudid.getCloudId('access_key');
    assert.strictEqual(result, '');
  });

  test('unknown access type rejects with "Invalid access type"', async () => {
    await assert.rejects(
      () => cloudid.getCloudId('not_a_real_type'),
      /Invalid access type/
    );
  });

  test('undefined access type rejects with "Invalid access type"', async () => {
    await assert.rejects(
      () => cloudid.getCloudId(),
      /Invalid access type/
    );
  });

  test('aws_iam type dispatches to the AWS path and yields a valid STS token', async () => {
    setEnvCreds({ session: true });
    networkBlocked = true;
    try {
      const token = await cloudid.getCloudId('aws_iam');
      const { outer } = decodeToken(token);
      assert.strictEqual(
        Buffer.from(outer.sts_request_url, 'base64').toString('utf8'),
        'https://sts.amazonaws.com/'
      );
    } finally {
      networkBlocked = false;
    }
  });

  test('azure_ad type dispatches to the Azure provider (not the invalid-type branch)', async () => {
    // Offline: DefaultAzureCredential reports "credential unavailable" without
    // any network. We only assert that dispatch entered the Azure branch, i.e.
    // it did NOT fall through to the generic "Invalid access type" error.
    networkBlocked = true;
    try {
      await assert.rejects(
        () => cloudid.getCloudId('azure_ad', 'object-id'),
        (err) => {
          assert.doesNotMatch(err.message, /Invalid access type/);
          return true;
        }
      );
    } finally {
      networkBlocked = false;
    }
  });

  test('gcp type dispatches to the GCP provider (not the invalid-type branch)', async () => {
    // Offline: with the network guard armed, the GCP metadata lookup is blocked
    // and the client rejects with a credentials error. We assert only that
    // dispatch entered the GCP branch, never that a live token was produced.
    networkBlocked = true;
    try {
      await assert.rejects(
        () => cloudid.getCloudId('gcp', 'akeyless.io'),
        (err) => {
          assert.doesNotMatch(err.message, /Invalid access type/);
          return true;
        }
      );
    } finally {
      networkBlocked = false;
    }
  });

  test('ali_cloud type dispatches to the Alibaba provider (not the invalid-type branch)', async () => {
    // Offline: without env credentials the Alibaba path tries ECS metadata,
    // which the network guard blocks. We assert only that dispatch entered
    // the Alibaba branch, never that a live token was produced.
    networkBlocked = true;
    try {
      await assert.rejects(
        () => cloudid.getCloudId('ali_cloud'),
        (err) => {
          assert.doesNotMatch(err.message, /Invalid access type/);
          return true;
        }
      );
    } finally {
      networkBlocked = false;
    }
  });
});

// ---------------------------------------------------------------------------
describe('AWS cloud-id token construction (offline SigV4)', () => {
  beforeEach(() => clearEnvCreds());

  test('produces a base64(JSON) token wrapping a signed STS GetCallerIdentity request', async () => {
    setEnvCreds({ session: true });
    networkBlocked = true;
    let token;
    try {
      token = await cloudid.getAWsCloudId();
    } finally {
      networkBlocked = false;
    }
    const { outer, headers } = decodeToken(token);

    // Outer envelope shape.
    assert.deepStrictEqual(
      Object.keys(outer).sort(),
      ['sts_request_body', 'sts_request_headers', 'sts_request_method', 'sts_request_url']
    );
    assert.strictEqual(outer.sts_request_method, 'POST');
    assert.strictEqual(
      Buffer.from(outer.sts_request_url, 'base64').toString('utf8'),
      'https://sts.amazonaws.com/'
    );
    assert.strictEqual(
      Buffer.from(outer.sts_request_body, 'base64').toString('utf8'),
      'Action=GetCallerIdentity&Version=2011-06-15'
    );
  });

  test('signs the request with SigV4 (Authorization: AWS4-HMAC-SHA256) and X-Amz-Date', async () => {
    setEnvCreds({ session: true });
    networkBlocked = true;
    let token;
    try {
      token = await cloudid.getAWsCloudId();
    } finally {
      networkBlocked = false;
    }
    const { headers } = decodeToken(token);

    assert.ok(Array.isArray(headers.Authorization), 'Authorization header should be an array');
    const authz = headers.Authorization[0];
    assert.match(authz, /^AWS4-HMAC-SHA256 /);
    assert.match(authz, new RegExp(`Credential=${FAKE_ACCESS_KEY}/\\d{8}/us-east-1/sts/aws4_request`));
    assert.match(authz, /SignedHeaders=[^,]*x-amz-date/);
    assert.match(authz, /Signature=[0-9a-f]{64}/);

    assert.ok(Array.isArray(headers['X-Amz-Date']));
    assert.match(headers['X-Amz-Date'][0], /^\d{8}T\d{6}Z$/);

    // Host targets the global STS endpoint.
    assert.strictEqual(headers.Host[0], 'sts.amazonaws.com');
    assert.match(headers['Content-Type'][0], /application\/x-www-form-urlencoded/);
  });

  test('includes X-Amz-Security-Token when a session token is present', async () => {
    setEnvCreds({ session: true });
    networkBlocked = true;
    let token;
    try {
      token = await cloudid.getAWsCloudId();
    } finally {
      networkBlocked = false;
    }
    const { headers } = decodeToken(token);
    assert.ok(Array.isArray(headers['X-Amz-Security-Token']), 'security token header present');
    assert.strictEqual(headers['X-Amz-Security-Token'][0], FAKE_SESSION_TOKEN);
    // The session token is also folded into the SigV4 SignedHeaders list.
    assert.match(headers.Authorization[0], /SignedHeaders=[^,]*x-amz-security-token/);
  });

  test('omits X-Amz-Security-Token for static (long-term) credentials', async () => {
    setEnvCreds({ session: false });
    networkBlocked = true;
    let token;
    try {
      token = await cloudid.getAWsCloudId();
    } finally {
      networkBlocked = false;
    }
    const { headers } = decodeToken(token);
    assert.strictEqual(headers['X-Amz-Security-Token'], undefined);
    // Still a valid SigV4 signature, just without the session-token signed header.
    assert.match(headers.Authorization[0], /^AWS4-HMAC-SHA256 /);
    assert.doesNotMatch(headers.Authorization[0], /x-amz-security-token/);
  });

  test('rejects when no credentials can be resolved from any provider', async () => {
    clearEnvCreds();
    networkBlocked = true;
    try {
      await assert.rejects(
        () => cloudid.getAWsCloudId(),
        (err) => {
          // AWS SDK v3 raises CredentialsProviderError; must not be our net guard firing.
          assert.ok(!err.netguard, 'no network should be attempted while resolving creds');
          assert.match(String(err.code || err.name || err.message), /Credentials/i);
          return true;
        }
      );
    } finally {
      networkBlocked = false;
    }
  });

  test('two invocations with the same credentials are deterministic in shape', async () => {
    setEnvCreds({ session: true });
    networkBlocked = true;
    try {
      const a = decodeToken(await cloudid.getAWsCloudId());
      const b = decodeToken(await cloudid.getAWsCloudId());
      assert.deepStrictEqual(Object.keys(a.outer).sort(), Object.keys(b.outer).sort());
      assert.strictEqual(a.outer.sts_request_url, b.outer.sts_request_url);
      assert.strictEqual(a.outer.sts_request_body, b.outer.sts_request_body);
    } finally {
      networkBlocked = false;
    }
  });
});
