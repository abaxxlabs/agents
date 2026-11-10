import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { evidenceFailures } from './evidence.mjs';

export const PREFIX = 'SQLITE_RUNTIME_PROOF ';

export function parseRecords(output) {
  return output.split('\n').filter((line) => line.startsWith(PREFIX)).map((line) => JSON.parse(line.slice(PREFIX.length)));
}

export function requireResult(output, exitCode, expected) {
  const results = parseRecords(output).filter((record) => record.type === 'result');
  const result = results.at(-1);
  if (results.length !== 1 || !result || !['PASS', 'FAIL'].includes(result.status)
    || !Array.isArray(result.checks) || !result.checks.length
    || result.checks.some((check) => !['PASS', 'FAIL'].includes(check.status))) {
    throw new Error('missing-or-invalid-worker-result');
  }
  if (exitCode !== 0 || result.checks.some((check) => check.status !== 'PASS')) result.status = 'FAIL';
  if (result.status === 'PASS') {
    const failures = evidenceFailures(result, expected);
    result.checks.push({ name: 'host-worker-evidence-contract', status: failures.length ? 'FAIL' : 'PASS', failures });
    if (failures.length) result.status = 'FAIL';
  }
  return result;
}

export function finalizeReport(report) {
  const passed = (name) => report.phases[name]?.status === 'PASS';
  report.acceptance = [
    { criterion: 1, status: passed('run') ? 'PASS' : 'NOT_PROVEN', evidence: 'Final Node image opens real SDK SQLite stores; environment and image identity recorded.' },
    { criterion: 2, status: passed('run') ? 'PASS' : 'NOT_PROVEN', evidence: 'Real credential/query/revocation/audit and independent-store checks.' },
    { criterion: 3, status: passed('run') ? 'PASS' : 'NOT_PROVEN', evidence: 'Explicit SQLite disposal, B-after-A operation, caller buffers, retained-handle characterization.' },
    { criterion: 4, status: passed('run') && passed('kill') && passed('restart') ? 'PASS' : 'NOT_PROVEN', evidence: 'Fixed recorded cycles, resource observations, externally observed SIGKILL and fresh-store restart.' },
    { criterion: 5, status: passed('fixture') && passed('cleanup') ? 'PASS' : 'NOT_PROVEN', evidence: 'Reproducible command, fixture, outcomes and limitations; incomplete scenarios cannot approve migration.' },
  ];
  const complete = ['fixture', 'run', 'kill', 'restart', 'postgres', 'cleanup'].every(passed);
  report.status = complete && report.acceptance.every((entry) => entry.status === 'PASS')
    && !report.failure && Object.values(report.phases).every((phase) => phase.status === 'PASS') ? 'PASS' : 'FAIL';
  report.recommendation = report.status === 'PASS'
    ? 'Tested composition is feasible for this fixed workload, subject to the recorded lifecycle, audit and memory limitations. This is input to the combined gate, not migration or capacity approval.'
    : 'Do not approve runtime migration from this execution. Resolve failed or missing evidence and reassess design/effort where needed.';
  report.finishedAt = new Date().toISOString();
  return report;
}

export async function writeReport(directory, report) {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
  const limitations = report.phases.run?.runtime?.limitations ?? [];
  const markdown = [
    '# SQLite runtime proof', '', `Result: **${report.status}**`, '', report.recommendation, '',
    `Started: ${report.startedAt}`, `Finished: ${report.finishedAt}`, '',
    '## Reproduction', '', '```sh', report.command, '```', '',
    '## Environment', '', '```json', JSON.stringify(report.environment, null, 2), '```', '',
    '## Acceptance', '', ...report.acceptance.map((entry) => `- ${entry.criterion}: ${entry.status}. ${entry.evidence}`), '',
    '## Phases', '', ...Object.entries(report.phases).map(([name, phase]) => `- ${name}: ${phase.status}`), '',
    '## Limitations', '', ...limitations.map((value) => `- ${value}`), '',
    'Machine-readable checks, metrics and failure stages are in report.json.', '',
    '## Sources', '', '- https://www.sqlite.org/inmemorydb.html',
    '- https://node-postgres.com/apis/pool',
    '- https://nodejs.org/docs/latest-v22.x/api/process.html#processmemoryusage', '',
  ].join('\n');
  await writeFile(join(directory, 'report.md'), markdown);
}
