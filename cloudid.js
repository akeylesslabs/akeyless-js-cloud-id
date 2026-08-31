
const AWS = require('aws-sdk')
const aws4 = require('aws4')
const { GoogleAuth } = require('google-auth-library');
const { DefaultAzureCredential } = require("@azure/identity");
const { IAMCredentialsClient } = require('@google-cloud/iam-credentials')
const { getAlibabaCloudId } = require('./alibaba')

async function getCloudId(acc_type, param) {
    if (acc_type === "aws_iam") {
        return getAWsCloudId()
    } else if (acc_type === "azure_ad") {
        return getAzureCloudID(param)
    } else if (acc_type === "gcp") {
        return getGcpCloudID(param)
    } else if (acc_type === "ali_cloud") {
        return getAlibabaCloudId()
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
    const client = await googleAuth.getClient();
    let token;

    if (typeof client.fetchIdToken === 'function') {
        token = await client.fetchIdToken(audience);
    } else if (client.serviceAccountImpersonationUrl) {
        // WIF: get ID token via IAM Credentials API.
        // URL format: https://iamcredentials.googleapis.com/v1/{name=projects/*/serviceAccounts/*}:generateAccessToken
        const url = client.serviceAccountImpersonationUrl;
        const name = url.match(/projects\/[^:]+/)?.[0];
        if (!name) throw new Error('Invalid serviceAccountImpersonationUrl format');
        const [resp] = await new IAMCredentialsClient().generateIdToken({
            name,
            audience,
            includeEmail: true
        });
        token = resp.token;
    } else {
        // Get ID token via getIdTokenClient (for google-auth-library clients types: JWT, GCE, Impersonated).
        const idTokenClient = await googleAuth.getIdTokenClient(audience);
        const headers = await idTokenClient.getRequestHeaders();
        token = headers.Authorization.replace('Bearer ', '');
    }
    return Buffer.from(token).toString('base64')
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
    getAlibabaCloudId: getAlibabaCloudId,
    getCloudId: getCloudId,
}
