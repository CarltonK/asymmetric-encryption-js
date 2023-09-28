const jose = require('node-jose');
const fs = require('fs');

// Private Key
// Generated on Linux via Openssl -> openssl genrsa -out private.pem 2048
const privateKeyFromFile = fs.readFileSync('private.pem');

// Public key, derived from the private key
// Generated on Linux via Openssl -> openssl rsa -in private.pem -pubout -out public.pem
const publicKeyFromFile = fs.readFileSync('public.pem');

const publicKeyBuffer = Buffer.from(publicKeyFromFile, 'base64');
const privateKeyBuffer = Buffer.from(privateKeyFromFile, 'base64');

const payload = Buffer.from('123456');

// Payload Encryption Process
const getKeyStore = async (payload, key) => {
    const keyStore = await jose.JWK.asKey(key, 'pem');
    const result = await jose.JWE.createEncrypt({ format: 'compact', contentAlg: 'A256GCM' }, keyStore)
        .update(payload)
        .final();
    console.log(`Encrpted ${payload} to ${result}`);
    return result;
}

const decrypt = async (encryptedData, privateKey) => {
    const privateKeyStore = await jose.JWK.asKey(privateKey, 'pem');
    const opts = { algorithms: ['RSA-OAEP', 'RSA-OAEP-256', 'A128GCM', 'A256GCM'] };
    const decrypted = await jose.JWE.createDecrypt(privateKeyStore, opts).decrypt(encryptedData);
    const result = decrypted.plaintext.toString().split('\'').join('');
    console.log(`The decrypted payload is ${result}`);
}

// Encrypt Payload
getKeyStore(payload, publicKeyBuffer)
    .then((val) => {
        // Confirm by testing the decyption
        decrypt(val, privateKeyBuffer);
    });