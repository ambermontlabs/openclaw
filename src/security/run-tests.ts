/**
 * Test runner for security modules.
 */

import { runSecurityTestSuite, printTestResults } from "./testing.js";

// Run the complete security test suite
const results = runSecurityTestSuite();

// Print results
printTestResults(results);

// Exit with error code if any tests failed
const totalFailed =
  results.injection.failed +
  results.validation.failed +
  results.secrets.failed +
  results.rateLimiting.failed;

if (totalFailed > 0) {
  console.error(`\n❌ ${totalFailed} test(s) failed`);
  process.exit(1);
}

console.log("\n✅ All security tests passed!");
process.exit(0);
