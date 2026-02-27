const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret';
const requireAuth = require('../middleware/requireAuth');

describe('requireAuth middleware', () => {
  let mockReq, mockRes, nextCalled;

  beforeEach(() => {
    nextCalled = false;
    mockRes = {
      statusCode: null,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(data) { this.body = data; },
    };
  });

  it('rejects requests with no token', () => {
    mockReq = { headers: {} };
    requireAuth(mockReq, mockRes, () => { nextCalled = true; });
    assert.strictEqual(mockRes.statusCode, 401);
    assert.strictEqual(nextCalled, false);
  });

  it('rejects requests with invalid token', () => {
    mockReq = { headers: { authorization: 'Bearer bad-token' } };
    requireAuth(mockReq, mockRes, () => { nextCalled = true; });
    assert.strictEqual(mockRes.statusCode, 401);
    assert.strictEqual(nextCalled, false);
  });

  it('passes valid tokens and sets req.user', () => {
    const token = jwt.sign({ userId: 1, email: 'test@test.com' }, 'test-secret');
    mockReq = { headers: { authorization: `Bearer ${token}` } };
    requireAuth(mockReq, mockRes, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
    assert.strictEqual(mockReq.user.userId, 1);
  });
});
