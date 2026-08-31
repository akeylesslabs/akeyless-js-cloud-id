'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
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
