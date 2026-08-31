const crypto = require('crypto')
const http = require('http')

const ALIBABA_DEFAULT_REGION = 'cn-hangzhou'
const ALIBABA_STS_DOMAIN = 'sts.aliyuncs.com'
const ALIBABA_STS_API_VERSION = '2015-04-01'
const ALIBABA_STS_API_ACTION = 'GetCallerIdentity'
const ALIBABA_STS_API_FORMAT = 'JSON'
const ALIBABA_SIGNATURE_METHOD = 'HMAC-SHA1'
const ALIBABA_METADATA_HOST = '100.100.100.200'
const ALIBABA_METADATA_BASE = `http://${ALIBABA_METADATA_HOST}/latest/`
const ALIBABA_METADATA_TOKEN_URL = `${ALIBABA_METADATA_BASE}api/token`
const ALIBABA_METADATA_ROLE_URL = `${ALIBABA_METADATA_BASE}meta-data/ram/security-credentials/`
const ALIBABA_METADATA_TIMEOUT_MS = 2000
const ALIBABA_IMDS_TOKEN_TTL_SECONDS = '60'

async function getAlibabaCloudId() {
    const creds = await resolveAlibabaCredentials()
    const region = resolveAlibabaRegion() || ALIBABA_DEFAULT_REGION
    return buildAlibabaCloudId(creds, region, formatAlibabaTimestamp(new Date()), randomAlibabaNonce())
}

function buildAlibabaCloudId(creds, region, timestamp, nonce) {
    if (!creds.accessKeyId || !creds.accessKeySecret) {
        throw new Error('alibaba credentials are missing access key id or secret')
    }
    const queryParams = {
        AccessKeyId: creds.accessKeyId,
        Action: ALIBABA_STS_API_ACTION,
        Format: ALIBABA_STS_API_FORMAT,
        RegionId: region || ALIBABA_DEFAULT_REGION,
        SignatureMethod: ALIBABA_SIGNATURE_METHOD,
        SignatureNonce: nonce,
        SignatureType: '',
        SignatureVersion: '1.0',
        Timestamp: timestamp,
        Version: ALIBABA_STS_API_VERSION,
    }
    if (creds.securityToken) {
        queryParams.SecurityToken = creds.securityToken
    }

    const stringToSign = buildAlibabaRpcStringToSign('POST', queryParams)
    queryParams.Signature = alibabaShaHmac1(stringToSign, creds.accessKeySecret + '&')

    const requestUrl = `https://${ALIBABA_STS_DOMAIN}/?${encodeAlibabaQueryParams(queryParams)}`
    const headers = {
        'Content-Type': ['application/x-www-form-urlencoded'],
        'X-Acs-Action': [ALIBABA_STS_API_ACTION],
        'X-Acs-Version': [ALIBABA_STS_API_VERSION],
    }
    const obj = {
        sts_request_method: 'POST',
        sts_request_url: Buffer.from(requestUrl).toString('base64'),
        sts_request_body: Buffer.from('').toString('base64'),
        sts_request_headers: Buffer.from(JSON.stringify(headers)).toString('base64'),
    }
    return Buffer.from(JSON.stringify(obj)).toString('base64')
}

function buildAlibabaRpcStringToSign(method, queryParams) {
    let encoded = encodeAlibabaQueryParams(queryParams)
    encoded = encoded.replace(/\+/g, '%20').replace(/\*/g, '%2A').replace(/%7E/g, '~')
    return method + '&%2F&' + alibabaQueryEscape(encoded)
}

function encodeAlibabaQueryParams(params) {
    return Object.keys(params).sort().map((key) => {
        return alibabaQueryEscape(key) + '=' + alibabaQueryEscape(params[key] == null ? '' : String(params[key]))
    }).join('&')
}

function alibabaQueryEscape(value) {
    return encodeURIComponent(value).replace(/%20/g, '+').replace(/%7E/g, '~')
}

function alibabaShaHmac1(source, secret) {
    return crypto.createHmac('sha1', secret).update(source).digest('base64')
}

function resolveAlibabaRegion() {
    return (process.env.ALIBABA_CLOUD_REGION_ID || process.env.ALIBABA_CLOUD_REGION || process.env.REGION_ID || '').trim()
}

async function resolveAlibabaCredentials() {
    const accessKeyId = (process.env.ALIBABA_CLOUD_ACCESS_KEY_ID || process.env.ALICLOUD_ACCESS_KEY || '').trim()
    const accessKeySecret = (process.env.ALIBABA_CLOUD_ACCESS_KEY_SECRET || process.env.ALICLOUD_SECRET_KEY || '').trim()
    const securityToken = (process.env.ALIBABA_CLOUD_SECURITY_TOKEN || process.env.ALICLOUD_SECURITY_TOKEN || '').trim()
    if (accessKeyId && accessKeySecret) {
        return { accessKeyId, accessKeySecret, securityToken }
    }
    return resolveAlibabaEcsRamRoleCredentials()
}

/**
 * Resolves RAM-role credentials from ECS instance metadata.
 * Prefers IMDSv2 (security-hardening mode): PUT /latest/api/token, then send
 * X-aliyun-ecs-metadata-token on both credential GETs. Falls back to IMDSv1
 * only if the token request fails (older instances still in normal mode).
 * @returns {Promise<{accessKeyId: string, accessKeySecret: string, securityToken: string}>}
 */
async function resolveAlibabaEcsRamRoleCredentials() {
    const token = await fetchAlibabaImdsV2Token()
    const headers = {}
    if (token) {
        headers['X-aliyun-ecs-metadata-token'] = token
    }
    const roleName = (await metadataRequest(ALIBABA_METADATA_ROLE_URL, { headers })).trim()
    if (!roleName || roleName.includes('/') || roleName.includes('\\')) {
        throw new Error('alibaba credentials are missing access key id or secret')
    }
    const body = await metadataRequest(ALIBABA_METADATA_ROLE_URL + roleName, { headers })
    const json = JSON.parse(body)
    return {
        accessKeyId: json.AccessKeyId,
        accessKeySecret: json.AccessKeySecret,
        securityToken: json.SecurityToken || '',
    }
}

/**
 * Fetches an ECS IMDSv2 session token. Returns empty string if the instance
 * does not support security-hardening mode, so callers can fall back to IMDSv1.
 * @returns {Promise<string>}
 */
async function fetchAlibabaImdsV2Token() {
    try {
        return (await metadataRequest(ALIBABA_METADATA_TOKEN_URL, {
            method: 'PUT',
            headers: { 'X-aliyun-ecs-metadata-token-ttl-seconds': ALIBABA_IMDS_TOKEN_TTL_SECONDS },
        })).trim()
    } catch (_) {
        return ''
    }
}

/**
 * Issues an HTTP request to the Alibaba ECS metadata service only.
 * @param {string} url Absolute metadata URL (must stay on 100.100.100.200)
 * @param {{method?: string, headers?: Record<string, string>}} [opts]
 * @returns {Promise<string>} Response body
 */
function metadataRequest(url, { method = 'GET', headers = {} } = {}) {
    if (!url.startsWith(ALIBABA_METADATA_BASE)) {
        return Promise.reject(new Error('alibaba metadata request has invalid url'))
    }
    return new Promise((resolve, reject) => {
        const req = http.request(url, { method, headers, timeout: ALIBABA_METADATA_TIMEOUT_MS }, (res) => {
            let data = ''
            res.on('data', (chunk) => { data += chunk })
            res.on('end', () => {
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    reject(new Error(`alibaba metadata request failed with status ${res.statusCode}`))
                    return
                }
                resolve(data)
            })
        })
        req.on('error', reject)
        req.on('timeout', () => {
            req.destroy()
            reject(new Error('alibaba metadata request timed out'))
        })
        req.end()
    })
}

function formatAlibabaTimestamp(date) {
    return date.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function randomAlibabaNonce() {
    return crypto.randomBytes(16).toString('hex')
}

module.exports = {
    getAlibabaCloudId,
    buildAlibabaCloudId,
    buildAlibabaRpcStringToSign,
    alibabaShaHmac1,
    resolveAlibabaEcsRamRoleCredentials,
    ALIBABA_DEFAULT_REGION,
    ALIBABA_STS_API_ACTION,
    ALIBABA_STS_API_VERSION,
    ALIBABA_STS_API_FORMAT,
    ALIBABA_SIGNATURE_METHOD,
}
