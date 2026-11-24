'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createMutex } = require('../electron/lock');

test('a concurrent operation is rejected while the first one is running', async () => {
  const mutex = createMutex();
  let releaseFirst;
  const first = mutex.runExclusive(
    () =>
      new Promise((resolve) => {
        releaseFirst = resolve;
      }),
  );

  const second = await mutex.runExclusive(() => 'should-not-run');
  assert.deepEqual(second, { locked: true });

  releaseFirst('done');
  assert.deepEqual(await first, { locked: false, value: 'done' });
});

test('the lock is released after a failed operation', async () => {
  const mutex = createMutex();

  await assert.rejects(
    mutex.runExclusive(async () => {
      throw new Error('failure');
    }),
    /failure/,
  );

  assert.deepEqual(await mutex.runExclusive(() => 'recovered'), { locked: false, value: 'recovered' });
});
