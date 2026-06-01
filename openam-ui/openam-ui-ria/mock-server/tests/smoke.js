const { createViteServer } = require('../server');
const { runChecks } = require('../checks');

const PORT = 3001;
const BASE_URL = `http://localhost:${PORT}`;

const PASS = '\x1b[32m✓\x1b[0m';
const FAIL = '\x1b[31m✗\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';

function printTable(results) {
  const header = `  ${BOLD}#  Scenario${' '.repeat(25)}Status   Checks${RESET}`;
  const separator = `  ${'─'.repeat(55)}`;

  console.log(header);
  console.log(separator);

  results.forEach((r, i) => {
    const num = String(i + 1).padStart(2);
    const name = r.name.padEnd(28);
    const status =
      r.status === 'pass'
        ? `${GREEN}PASS${RESET}`
        : `${RED}FAIL${RESET}`;
    const totalChecks = r.details.length;
    const passedChecks = r.details.filter((d) => d.startsWith('✓')).length;
    const checks = `${passedChecks}/${totalChecks}`.padStart(7);

    console.log(`  ${num}  ${name}${status}   ${checks}`);
  });
}

function printFailures(results) {
  const failures = results.filter((r) => r.status === 'fail');
  if (failures.length === 0) return;

  console.log(`\n${BOLD}${RED}Failures:${RESET}`);
  for (const r of failures) {
    console.log(`\n  ${BOLD}${r.name}${RESET}`);
    for (const detail of r.details) {
      const icon = detail.startsWith('✓') ? `${GREEN}${detail}${RESET}` : `${RED}${detail}${RESET}`;
      console.log(`    ${icon}`);
    }
  }
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  // Check if port is in use
  const net = require('net');
  const portInUse = await new Promise((resolve) => {
    const tester = net.createServer()
      .once('error', () => resolve(true))
      .once('listening', () => { tester.close(); resolve(false); })
      .listen(PORT);
  });

  if (portInUse) {
    console.error(`${RED}ERROR:${RESET} Port ${PORT} is already in use.`);
    console.error(`Stop the running mock server first, or use a different port.\n`);
    process.exit(1);
  }

  console.log(`\n  ${BOLD}OpenAM Mock Server — Diagnostic Test Runner${RESET}\n`);

  const vite = await createViteServer(PORT);

  // Wait for server to be ready
  await wait(300);

  console.log(`  Running checks against ${BASE_URL}...\n`);

  try {
    const report = await runChecks(BASE_URL);

    printTable(report.results);
    printFailures(report.results);

    const totalChecks = report.results.reduce((sum, r) => sum + r.details.length, 0);
    console.log('');

    if (report.failed === 0) {
      console.log(`  ${GREEN}${report.passed} passed${RESET}, ${report.failed} failed ${DIM}(${totalChecks} checks total)${RESET}\n`);
    } else {
      console.log(`  ${RED}${report.failed} failed${RESET}, ${report.passed} passed ${DIM}(${totalChecks} checks total)${RESET}\n`);
    }

    vite.close();
    process.exit(report.failed === 0 ? 0 : 1);
  } catch (err) {
    console.error(`\n  ${RED}Unexpected error:${RESET} ${err.message}\n`);
    vite.close();
    process.exit(1);
  }
}

main();
