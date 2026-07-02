#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, '../certs');
fs.mkdirSync(certsDir, { recursive: true });

console.log('Generating RSA 2048 key pair...');
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

fs.writeFileSync(path.join(certsDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(certsDir, 'public.pem'), publicKey);

console.log('Keys written to certs/private.pem and certs/public.pem');
