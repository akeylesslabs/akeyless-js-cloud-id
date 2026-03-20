#!/usr/bin/env node
/**
 * Test script for GCP IAM authentication.
 *
 * Tests getCloudId('gcp', audience) with:
 * - Service account JSON (via GOOGLE_APPLICATION_CREDENTIALS)
 * - GCE metadata server (when running on GCE instance)
 * - Application Default Credentials
 *
 * Usage:
 *   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
 *   node test_gcp_auth.js
 *
 *   # Or on GCE instance (no env var needed):
 *   node test_gcp_auth.js
 */

const { getCloudId } = require('./cloudid');

async function testGcpAuthentication() {
  try {
    const token = await getCloudId('gcp', 'akeyless.io');
    if (!token || token.length === 0) throw new Error('Expected non-empty token');
    console.log('All GCP auth tests passed');
    return true;
  } catch (err) {
    console.error(`Error: ${err.message}`);
    console.error('Troubleshooting: Set GOOGLE_APPLICATION_CREDENTIALS or run on GCE');
    return false;
  }
}

testGcpAuthentication().then((success) => {
  process.exit(success ? 0 : 1);
});
