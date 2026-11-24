'use strict';

function createMutex() {
  let locked = false;

  return {
    async runExclusive(task) {
      if (locked) return { locked: true };
      locked = true;
      try {
        return { locked: false, value: await task() };
      } finally {
        locked = false;
      }
    },
  };
}

module.exports = { createMutex };
