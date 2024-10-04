const fs = require('fs');
const crypto = require('crypto');

const message = fs.readFileSync('../assets/message.txt', 'utf8');
const [encryptedPassphraseB64, encryptedPayloadB64] = message.split('.');

const encryptedPassphrase = Buffer.from(encryptedPassphraseB64, 'base64');
const encryptedPayload = Buffer.from(encryptedPayloadB64, 'base64');

const privateKey = fs.readFileSync('../assets/Private.pem', 'utf8');
const passphrase = crypto.privateDecrypt(
  {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  },
  encryptedPassphrase
);

const salt = encryptedPayload.slice(8, 16);
const payloadData = encryptedPayload.slice(16);

const keyiv = crypto.pbkdf2Sync(
  passphrase,
  salt,
  10000,
  48,
  'sha256'
);

const key = keyiv.slice(0, 32);
const iv = keyiv.slice(32, 48);

const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
let decrypted = decipher.update(payloadData);
decrypted = Buffer.concat([decrypted, decipher.final()]);

console.log("Passphrase:", decrypted.toString());
