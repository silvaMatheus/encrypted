const fs = require("fs");

const message = fs.readFileSync("../assets/message.txt", "utf8");
const [encryptedPassphrase, encryptedPayload, signature] = message.split(".");

console.log("Encrypted Passphrase:", encryptedPassphrase);
console.log();

console.log("Encrypted Payload:", encryptedPayload);
console.log();

console.log("Signature:", signature);
console.log();

console.log("Encrypted Passphrase length:", Buffer.from(encryptedPassphrase, "base64").length);
