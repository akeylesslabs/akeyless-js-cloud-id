'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const alibaba = require('./alibaba');

const TEST_TIMESTAMP = '2026-05-11T10:00:00Z';
const TEST_NONCE = 'fixed-nonce';

function decode(cloudId) {
  const root = JSON.parse(Buffer.from(cloudId, 'base64').toString());
  return {
    method: root.sts_request_method,
    url: Buffer.from(root.sts_request_url, 'base64').toString(),
    body: Buffer.from(root.sts_request_body, 'base64').toString(),
    headers: JSON.parse(Buffer.from(root.sts_request_headers, 'base64').toString()),
  };
}

function query(url) {
  return Object.fromEntries(new URL(url).searchParams.entries());
}

function signed(region, securityToken) {
  return decode(alibaba.buildAlibabaCloudId(
    { accessKeyId: 'AKID', accessKeySecret: 'SECRET', securityToken: securityToken || '' },
    region,
    TEST_TIMESTAMP,
    TEST_NONCE
  ));
}

test('default region uses hangzhou and the global STS endpoint', () => {
  const token = signed('');
  assert.strictEqual(token.method, 'POST');
  assert.ok(token.url.startsWith('https://sts.aliyuncs.com/?'));
  assert.strictEqual(token.body, '');
  assert.strictEqual(query(token.url).RegionId, alibaba.ALIBABA_DEFAULT_REGION);
  assert.strictEqual(query(token.url).Action, alibaba.ALIBABA_STS_API_ACTION);
  assert.ok(query(token.url).Signature);
});

test('configured region is signed into the request', () => {
  assert.strictEqual(query(signed('cn-beijing').url).RegionId, 'cn-beijing');
});

test('includes SecurityToken for temporary credentials', () => {
  assert.strictEqual(query(signed('cn-hangzhou', 'SESSION').url).SecurityToken, 'SESSION');
});

test('payload headers stay compatible with the Akeyless contract', () => {
  const token = signed('cn-hangzhou');
  assert.strictEqual(token.headers['Content-Type'][0], 'application/x-www-form-urlencoded');
  assert.strictEqual(token.headers['X-Acs-Action'][0], alibaba.ALIBABA_STS_API_ACTION);
  assert.strictEqual(token.headers['X-Acs-Version'][0], alibaba.ALIBABA_STS_API_VERSION);
});

test('RPC string-to-sign is deterministic', () => {
  const queryParams = {
    AccessKeyId: 'AKID',
    Action: alibaba.ALIBABA_STS_API_ACTION,
    Format: alibaba.ALIBABA_STS_API_FORMAT,
    RegionId: alibaba.ALIBABA_DEFAULT_REGION,
    SignatureMethod: alibaba.ALIBABA_SIGNATURE_METHOD,
    SignatureNonce: TEST_NONCE,
    SignatureType: '',
    SignatureVersion: '1.0',
    Timestamp: TEST_TIMESTAMP,
    Version: alibaba.ALIBABA_STS_API_VERSION,
  };
  const stringToSign = alibaba.buildAlibabaRpcStringToSign('POST', queryParams);
  const signature = alibaba.alibabaShaHmac1(stringToSign, 'SECRET&');
  assert.strictEqual(
    stringToSign,
    'POST&%2F&AccessKeyId%3DAKID%26Action%3DGetCallerIdentity%26Format%3DJSON%26RegionId%3Dcn-hangzhou%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3Dfixed-nonce%26SignatureType%3D%26SignatureVersion%3D1.0%26Timestamp%3D2026-05-11T10%253A00%253A00Z%26Version%3D2015-04-01'
  );
  assert.strictEqual(signature, 'dSCqL2sSKYDmcOcAj2Grhpar/wE=');
});

function mockMetadata(responses) {
  const original = http.request;
  const calls = [];
  http.request = (url, options, cb) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => {
      const next = responses.shift() || { statusCode: 500, body: '' };
      calls.push({
        url: String(url),
        method: (options && options.method) || 'GET',
        headers: (options && options.headers) || {},
      });
      const res = new EventEmitter();
      res.statusCode = next.statusCode == null ? 200 : next.statusCode;
      queueMicrotask(() => {
        if (next.error) {
          req.emit('error', next.error);
          return;
        }
        cb(res);
        if (next.body) res.emit('data', next.body);
        res.emit('end');
      });
    };
    return req;
  };
  return {
    calls,
    restore() { http.request = original; },
  };
}

const ROLE_CREDS = JSON.stringify({
  AccessKeyId: 'AK-FROM-IMDS',
  AccessKeySecret: 'SK-FROM-IMDS',
  SecurityToken: 'ST-FROM-IMDS',
});

test('ECS RAM role credentials send IMDSv2 token on both metadata GETs', async () => {
  const mock = mockMetadata([
    { statusCode: 200, body: 'imds-token' },
    { statusCode: 200, body: 'my-role' },
    { statusCode: 200, body: ROLE_CREDS },
  ]);
  try {
    const creds = await alibaba.resolveAlibabaEcsRamRoleCredentials();
    assert.deepStrictEqual(creds, {
      accessKeyId: 'AK-FROM-IMDS',
      accessKeySecret: 'SK-FROM-IMDS',
      securityToken: 'ST-FROM-IMDS',
    });
    assert.strictEqual(mock.calls.length, 3);
    assert.strictEqual(mock.calls[0].method, 'PUT');
    assert.strictEqual(mock.calls[0].url, 'http://100.100.100.200/latest/api/token');
    assert.strictEqual(mock.calls[0].headers['X-aliyun-ecs-metadata-token-ttl-seconds'], '60');
    assert.strictEqual(mock.calls[1].url, 'http://100.100.100.200/latest/meta-data/ram/security-credentials/');
    assert.strictEqual(mock.calls[1].headers['X-aliyun-ecs-metadata-token'], 'imds-token');
    assert.strictEqual(mock.calls[2].url, 'http://100.100.100.200/latest/meta-data/ram/security-credentials/my-role');
    assert.strictEqual(mock.calls[2].headers['X-aliyun-ecs-metadata-token'], 'imds-token');
  } finally {
    mock.restore();
  }
});

test('ECS RAM role credentials fall back to IMDSv1 when the token request fails', async () => {
  const mock = mockMetadata([
    { error: new Error('imdSv2 unavailable') },
    { statusCode: 200, body: 'legacy-role' },
    { statusCode: 200, body: ROLE_CREDS },
  ]);
  try {
    const creds = await alibaba.resolveAlibabaEcsRamRoleCredentials();
    assert.strictEqual(creds.accessKeyId, 'AK-FROM-IMDS');
    assert.strictEqual(mock.calls[0].method, 'PUT');
    assert.strictEqual(mock.calls[1].headers['X-aliyun-ecs-metadata-token'], undefined);
    assert.strictEqual(mock.calls[2].headers['X-aliyun-ecs-metadata-token'], undefined);
    assert.strictEqual(
      mock.calls[2].url,
      'http://100.100.100.200/latest/meta-data/ram/security-credentials/legacy-role'
    );
  } finally {
    mock.restore();
  }
});
