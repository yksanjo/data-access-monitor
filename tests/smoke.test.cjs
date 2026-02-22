const test = require('node:test');
const assert = require('node:assert/strict');
const { DataAccessMonitor } = require('../dist/index.js');

test('data access monitor enforces sensitive write restrictions', () => {
  const monitor = new DataAccessMonitor();
  const allowedRead = monitor.checkAccess('read', 'user_data_profile', 'u1', { approved: true });
  const blockedWrite = monitor.checkAccess('write', 'api_key_store', 'u1', { approved: true });

  assert.equal(allowedRead.allowed, true);
  assert.equal(blockedWrite.allowed, false);
});
