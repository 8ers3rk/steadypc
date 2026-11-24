'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeSecurity, loadSignatures } = require('../electron/security');
const { scoreFindings, scoreReportFindings } = require('../electron/scoring');

const signatures = loadSignatures();

function snapshot(overrides = {}) {
  return {
    processes: [],
    connections: [],
    tasks: [],
    autorun: [],
    defender: null,
    signatureStates: {},
    ...overrides,
  };
}

function proc(pid, name, path, commandLine, parentPid = 4) {
  return { pid, parentPid, name, path, commandLine };
}

function assertSafeFindings(findings) {
  for (const item of findings) {
    assert.equal(item.category, 'security');
    assert.equal(item.action, null);
    assert.deepEqual(item.presets, []);
    assert.equal(item.recommended, false);
    assert.equal(item.reversible, false);
  }
}

test('loadSignatures exposes the built-in detection groups', () => {
  assert.ok(signatures.minerNames.includes('xmrig'));
  assert.ok(signatures.minerCommandPatterns.some((value) => value.includes('stratum+tcp')));
  assert.ok(signatures.minerPorts.includes(3333));
  assert.ok(Array.isArray(signatures.minerPortRanges));
  assert.ok(signatures.suspiciousPathFragments.some((value) => value.toLowerCase().includes('temp')));
  assert.ok(signatures.suspiciousCommandPatterns.some((value) => value.toLowerCase().includes('encodedcommand')));
  assert.ok(signatures.systemProcessNames.includes('svchost.exe'));
});

test('loadSignatures merges user overrides without losing defaults', () => {
  const merged = loadSignatures({ minerNames: ['customminer'], minerPorts: [9999] });
  assert.ok(merged.minerNames.includes('xmrig'));
  assert.ok(merged.minerNames.includes('customminer'));
  assert.ok(merged.minerPorts.includes(3333));
  assert.ok(merged.minerPorts.includes(9999));
});

test('a miner process with a pool connection is a high-confidence finding', () => {
  const process = proc(
    4242,
    'xmrig.exe',
    'C:\\Users\\Public\\Downloads\\xmrig.exe',
    '"C:\\Users\\Public\\Downloads\\xmrig.exe" -o stratum+tcp://pool.example:3333 -u 48abc',
  );
  const report = analyzeSecurity(
    snapshot({
      processes: [process],
      connections: [{ pid: 4242, port: 3333, address: '1.2.3.4' }],
      signatureStates: { [process.path]: { status: 'invalid', signer: '' } },
    }),
    signatures,
  );

  const processFinding = report.findings.find((item) => item.id === 'security-miner-process');
  const networkFinding = report.findings.find((item) => item.id === 'security-miner-network');
  assert.ok(processFinding);
  assert.equal(processFinding.confidence, 'high');
  assert.equal(processFinding.severity, 'high');
  assert.ok(processFinding.evidence.some((line) => line.includes('4242')));
  assert.ok(processFinding.evidence.some((line) => line.includes('3333')));
  assert.ok(networkFinding);
  assertSafeFindings(report.findings);
});

test('a pool port alone is reported as information, not as a finding', () => {
  const process = proc(
    10,
    'chrome.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'chrome.exe --type=renderer',
  );
  const report = analyzeSecurity(
    snapshot({
      processes: [process],
      connections: [{ pid: 10, port: 3333, address: '1.2.3.4' }],
      signatureStates: { [process.path]: { status: 'valid', signer: 'Google LLC' } },
    }),
    signatures,
  );

  assert.equal(report.findings.some((item) => item.id === 'security-miner-network'), false);
  const check = report.checks.find((item) => item.id === 'security-miner-network');
  assert.ok(check);
  assert.notEqual(check.status, 'issue');
});

test('a signed svchost.exe in System32 is not a masquerade', () => {
  const process = proc(
    600,
    'svchost.exe',
    'C:\\Windows\\System32\\svchost.exe',
    'C:\\Windows\\System32\\svchost.exe -k netsvcs',
  );
  const report = analyzeSecurity(
    snapshot({
      processes: [process],
      signatureStates: { [process.path]: { status: 'valid', signer: 'Microsoft Windows Publisher' } },
    }),
    signatures,
  );

  assert.equal(report.findings.some((item) => item.id === 'security-process-masquerade'), false);
  assertSafeFindings(report.findings);
});

test('an unsigned svchost.exe outside System32 is a masquerade', () => {
  const process = proc(
    601,
    'svchost.exe',
    'C:\\Users\\Public\\Temp\\svchost.exe',
    'C:\\Users\\Public\\Temp\\svchost.exe',
  );
  const report = analyzeSecurity(
    snapshot({
      processes: [process],
      signatureStates: { [process.path]: { status: 'invalid', signer: '' } },
    }),
    signatures,
  );

  const finding = report.findings.find((item) => item.id === 'security-process-masquerade');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.ok(finding.evidence.some((line) => line.includes('601')));
});

test('a system process with an unreadable path is not a masquerade', () => {
  const process = proc(744, 'smss.exe', '', '');
  const report = analyzeSecurity(snapshot({ processes: [process] }), signatures);

  assert.equal(report.findings.some((item) => item.id === 'security-process-masquerade'), false);
});

test('encoded PowerShell is reported only for PowerShell processes', () => {
  const shell = proc(
    11,
    'powershell.exe',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'powershell.exe -EncodedCommand UABvAHcAZQByAFMAaABlAGwAbA==',
  );
  const other = proc(
    12,
    'notepad.exe',
    'C:\\Windows\\System32\\notepad.exe',
    'notepad.exe -EncodedCommand UABvAHcAZQByAFMAaABlAGwAbA==',
  );
  const report = analyzeSecurity(
    snapshot({
      processes: [shell, other],
      signatureStates: {
        [shell.path]: { status: 'valid', signer: 'Microsoft Windows Publisher' },
        [other.path]: { status: 'valid', signer: 'Microsoft Windows Publisher' },
      },
    }),
    signatures,
  );

  const findings = report.findings.filter((item) => item.id === 'security-encoded-powershell');
  assert.equal(findings.length, 1);
  assert.ok(findings[0].evidence.some((line) => line.includes('11')));
  assert.equal(findings[0].evidence.some((line) => line.includes('12')), false);
});

test('a scheduled task running from Temp is reported', () => {
  const report = analyzeSecurity(
    snapshot({
      tasks: [
        {
          name: 'DailyUpdate',
          path: '\\',
          execute: 'C:\\Users\\Public\\Temp\\update.exe',
          arguments: '/silent',
          state: 'Ready',
        },
      ],
    }),
    signatures,
  );

  const finding = report.findings.find((item) => item.id === 'security-scheduled-task');
  assert.ok(finding);
  assert.ok(finding.evidence.some((line) => line.includes('DailyUpdate')));
});

test('a vendor task writing a ProgramData log is not a finding', () => {
  const report = analyzeSecurity(
    snapshot({
      tasks: [
        {
          name: 'VendorTask',
          path: '\\Vendor',
          execute: 'C:\\Program Files\\Vendor\\tool.exe',
          arguments: '/log C:\\ProgramData\\Vendor\\tool.log',
          state: 'Ready',
        },
      ],
    }),
    signatures,
  );

  assert.equal(report.findings.some((item) => item.id === 'security-scheduled-task'), false);
});

test('a Defender MpCmdRun task is not treated as a shell task', () => {
  const report = analyzeSecurity(
    snapshot({
      tasks: [
        {
          name: 'Windows Defender Cache Maintenance',
          path: '\\Microsoft\\Windows\\Windows Defender\\',
          execute: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpCmdRun.exe',
          arguments: '-IdleTask -TaskName WdCacheMaintenance',
          state: 'Ready',
        },
      ],
    }),
    signatures,
  );

  assert.equal(report.findings.some((item) => item.id === 'security-scheduled-task'), false);
});

test('an autorun anomaly needs a user path, no signature and a random name', () => {
  const suspicious = {
    name: 'a1b2c3d4e5',
    command: 'C:\\Users\\Public\\Temp\\a1b2c3d4e5.exe',
    path: 'C:\\Users\\Public\\Temp\\a1b2c3d4e5.exe',
    signer: '',
    signature: 'invalid',
    source: 'registry',
  };
  const signed = { ...suspicious, name: 'TrustedApp', signature: 'valid', signer: 'Trusted Vendor' };
  const report = analyzeSecurity(snapshot({ autorun: [suspicious, signed] }), signatures);

  const findings = report.findings.filter((item) => item.id === 'security-autorun-anomaly');
  assert.equal(findings.length, 1);
  assert.ok(findings[0].evidence.some((line) => line.includes('a1b2c3d4e5')));
});

test('Defender state is informational and never a finding', () => {
  const report = analyzeSecurity(
    snapshot({ defender: { realTimeProtectionEnabled: false, antimalwareEnabled: true } }),
    signatures,
  );

  assert.equal(report.findings.some((item) => item.id === 'security-defender-status'), false);
  const check = report.checks.find((item) => item.id === 'security-defender-status');
  assert.ok(check);
  assert.equal(check.status, 'info');
});

test('security findings do not change the report score', () => {
  const security = { id: 'security-miner-process', category: 'security', severity: 'high' };
  const storage = { id: 'storage-temp', category: 'storage', severity: 'low' };

  assert.equal(scoreReportFindings([security, storage]).value, scoreFindings([storage]).value);
  assert.equal(scoreFindings([security, storage]).value < scoreFindings([storage]).value, true);
});
