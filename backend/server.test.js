const assert = require("assert");
const {
  hashPassword,
  isStrongPassword,
  normalizeEmail,
  verifyPassword,
} = require("./server");

assert.strictEqual(normalizeEmail("  USER@Example.COM "), "user@example.com");
assert.strictEqual(isStrongPassword("short"), false);
assert.strictEqual(isStrongPassword("MoneySim123!"), true);

const user = hashPassword("MoneySim123!");
assert.strictEqual(verifyPassword("MoneySim123!", user), true);
assert.strictEqual(verifyPassword("wrong-password", user), false);

console.log("backend unit tests passed");
