
const AWS = require('aws-sdk')
const aws4 = require('aws4')
const fs = require('fs')
const path = require('path')
const { GoogleAuth } = require('google-auth-library');
const { DefaultAzureCredential } = require("@azure/identity");

async function getCloudId(acc_type, param) {
    if (acc_type === "aws_iam") {
        return getAWsCloudId()
    } else if (acc_type === "azure_ad") {
        return getAzureCloudID(param)
    } else if (acc_type === "gcp") {
        return getGcpCloudID(param)
    } else if (acc_type === "access_key") {
        return ""
    } else {
        throw new Error("Invalid access type")
    }
}

async function getAzureCloudID(object_id) {
 
    const credential = new DefaultAzureCredential();
    
    const scope = "https://management.azure.com/.default";
    const token = await credential.getToken(scope);

    return Buffer.from(token.token).toString('base64')
}


async function getGcpCloudID(audience) {
    if (!audience) {
        audience = "akeyless.io"
    }

    const googleAuth = new GoogleAuth();
    try {
        // Use getIdTokenClient for SA key, GCE metadata.
        // For ExternalAccountClient (WIF), both fetchIdToken and getIdTokenClient
        // throw "Cannot fetch ID token in this environment..." - fall back to IAM Credentials.
        const idTokenClient = await googleAuth.getIdTokenClient(audience);
        const headers = await idTokenClient.getRequestHeaders();
        const token = headers.Authorization.replace('Bearer ', '');
        return Buffer.from(token).toString('base64');
    } catch (err) {
        const msg = err?.message || '';
        if (!/cannot fetch id token/i.test(msg)) {
            throw err;
        }
        // WIF fallback: use IAM Credentials API generateIdToken.
        // Requires GOOGLE_APPLICATION_CREDENTIALS pointing to WIF config with
        // service_account_impersonation_url.
        return getGcpCloudIDViaIamCredentials(audience);
    }
}

function extractServiceAccountFromCredFile(credPath) {
    const json = JSON.parse(fs.readFileSync(credPath, 'utf8'));
    const url = json.service_account_impersonation_url ||
        json.service_account_impersonation?.url ||
        json.service_account_impersonation?.token_url ||
        '';
    // URL format: .../projects/-/serviceAccounts/EMAIL@project.iam.gserviceaccount.com:generateAccessToken
    const m = url.match(/\/serviceAccounts\/([^:]+)/);
    return m ? `projects/-/serviceAccounts/${m[1]}` : null;
}

async function getGcpCloudIDViaIamCredentials(audience) {
    const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    if (!credPath || !fs.existsSync(credPath)) {
        throw new Error('GOOGLE_APPLICATION_CREDENTIALS not set or file missing; cannot use IAM Credentials fallback');
    }
    const name = extractServiceAccountFromCredFile(credPath);
    if (!name) {
        throw new Error('Could not extract service account from credential file (no service_account_impersonation_url)');
    }
    const { IAMCredentialsClient } = require('@google-cloud/iam-credentials').v1;
    const client = new IAMCredentialsClient();
    const [response] = await client.generateIdToken({ name, audience, includeEmail: true });
    const token = response.token;
    if (!token) {
        throw new Error('IAM Credentials generateIdToken returned empty token');
    }
    return Buffer.from(token).toString('base64');
}

function getAWsCloudId() {
    return new Promise((resolve, reject) => {
        AWS.config.getCredentials(function (err) {
            if (err) {
                reject(err)
            } else {
                const result = stsGetCallerIdentity(AWS.config.credentials)
                resolve(result)
            }
        })    
    })
}

function stsGetCallerIdentity(creds) {

    const opts3 = { method: 'POST', service: 'sts', body: 'Action=GetCallerIdentity&Version=2011-06-15', region: 'us-east-1' }
    opts3.headers = {
        "Content-Length": opts3.body.length,
        "Content-Type": 'application/x-www-form-urlencoded; charset=utf-8',
    }
    aws4.sign(opts3, creds)

    const h = {
        'Authorization': [opts3.headers['Authorization']],
        'Content-Length': [opts3.body.length.toString()],
        'Host': [opts3.headers['Host']],
        'Content-Type': [opts3.headers['Content-Type']],
        'X-Amz-Date': [opts3.headers['X-Amz-Date']],
    }
    if (creds.sessionToken) {
        h['X-Amz-Security-Token'] = [creds.sessionToken];
    }
    const myheaders = JSON.stringify(h);

    const obj = {
        'sts_request_method': 'POST',
        'sts_request_url': Buffer.from('https://sts.amazonaws.com/').toString('base64'),
        'sts_request_body': Buffer.from('Action=GetCallerIdentity&Version=2011-06-15').toString('base64'),
        'sts_request_headers': Buffer.from(myheaders).toString('base64')
    };
    const awsData = JSON.stringify(obj)
    return Buffer.from(awsData).toString('base64')
}


module.exports = {
    getAWsCloudId: getAWsCloudId,
    getAzureCloudID: getAzureCloudID,
    getGcpCloudID: getGcpCloudID,
    getCloudId: getCloudId,
}
