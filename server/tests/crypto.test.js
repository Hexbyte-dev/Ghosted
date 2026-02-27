const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { encrypt, decrypt } = require('../services/crypto');

describe('crypto service', () => {
  before(() => {
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
  });

  it('encrypts and decrypts a string', () => {
    const original = 'my-secret-refresh-token-12345';
    const encrypted = encrypt(original);
    assert.notStrictEqual(encrypted, original);
    const decrypted = decrypt(encrypted);
    assert.strictEqual(decrypted, original);
  });

  it('produces different ciphertext each time (random IV)', () => {
    const original = 'same-input';
    const a = encrypt(original);
    const b = encrypt(original);
    assert.notStrictEqual(a, b);
  });
});
