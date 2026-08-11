'use strict';

/**
 * Credentials-gated LIVE end-to-end test.
 *
 * This test talks to a real cloud provider and is therefore SKIPPED by default
 * so CI never fails when no secrets are configured. To run it, export:
 *
 *   AKEYLESS_CLOUD_ID_E2E=1
 *   AKEYLESS_CLOUD_ID_E2E_TYPE=aws_iam|azure_ad|gcp   (default: aws_iam)
 *   AKEYLESS_CLOUD_ID_E2E_PARAM=<object-id | audience> (optional, provider-specific)
 *
 * plus whatever ambient credentials that provider needs (e.g. AWS_* env vars /
 * instance role, GOOGLE_APPLICATION_CREDENTIALS, Azure managed identity, ...).
 */

const { test } = require('node:test');
const assert = require('node:assert');
const { getCloudId } = require('./cloudid');

const enabled = process.env.AKEYLESS_CLOUD_ID_E2E === '1';
const type = process.env.AKEYLESS_CLOUD_ID_E2E_TYPE || 'aws_iam';
const param = process.env.AKEYLESS_CLOUD_ID_E2E_PARAM;

test(
  `live e2e: getCloudId('${type}') returns a non-empty token`,
  { skip: enabled ? false : 'set AKEYLESS_CLOUD_ID_E2E=1 (and provider credentials) to run' },
  async () => {
    const token = await getCloudId(type, param);
    assert.strictEqual(typeof token, 'string', 'token should be a string');
    assert.ok(token.length > 0, 'token should be non-empty');
  }
);
