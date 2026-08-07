/**
 * Tests for the harness-wide non-destructive backstop.
 *
 * The two halves of this suite are equally important:
 *  - BLOCK: catastrophic OS/disk/infra operations are refused.
 *  - ALLOW: real red-team tooling — including scans carrying destructive-LOOKING
 *    payloads ("'; DROP TABLE--") — is NEVER false-positived. A backstop that
 *    breaks live assessments is worse than no backstop, so the allow-list is the
 *    proof that this is safe to run in production.
 */

import { screenCommand, isDestructiveIntent } from '../../src/utils/destructive-guard';

describe('screenCommand — catastrophic operations are blocked', () => {
  const BLOCKED: Array<[string, string, string]> = [
    ['filesystem-wipe', 'rm -rf /', 'rm -rf /'],
    ['filesystem-wipe', 'rm -rf /*', 'rm -rf /*'],
    ['filesystem-wipe', 'rm -rf ~', 'rm -rf ~'],
    ['filesystem-wipe', 'rm -rf $HOME', 'rm -rf $HOME'],
    ['filesystem-wipe', 'rm -rf /etc', 'rm -rf /etc'],
    ['filesystem-wipe', 'rm -fr /var', 'rm -fr /var (flag order)'],
    ['filesystem-wipe', 'rm -r /usr', 'rm -r /usr (no force flag)'],
    ['filesystem-wipe', 'rm --recursive --force /boot', 'long-form flags'],
    ['filesystem-format', 'mkfs.ext4 /dev/sda1', 'mkfs'],
    ['disk-overwrite', 'dd if=/dev/zero of=/dev/sda bs=1M', 'dd to block device'],
    ['disk-wipe', 'wipefs -a /dev/sdb', 'wipefs'],
    ['disk-shred', 'shred -n 3 /dev/sda', 'shred device'],
    ['disk-overwrite', 'echo x > /dev/sda1', 'redirect over block device'],
    ['fork-bomb', ':(){ :|:& };:', 'fork bomb'],
    ['system-control', 'shutdown -h now', 'shutdown'],
    ['system-control', 'reboot', 'reboot'],
    ['system-control', 'poweroff', 'poweroff'],
    ['system-control', 'init 0', 'init 0'],
  ];

  it.each(BLOCKED)('blocks [%s]: %s', (category, command) => {
    const screen = screenCommand(command);
    expect(screen.blocked).toBe(true);
    expect(screen.category).toBe(category);
    expect(screen.reason).toBeTruthy();
  });
});

describe('screenCommand — real red-team tooling is never false-positived', () => {
  const ALLOWED: string[] = [
    // Scanners carrying destructive-LOOKING payloads as quoted arguments.
    'sqlmap -u "http://t/x?id=1" --batch --level=2 --risk=2 --data="id=1\'; DROP TABLE users--"',
    'sqlmap -u "http://t/login" --batch --technique=B --tamper=space2comment',
    `curl -s "http://t/api" -d "q=1; TRUNCATE accounts"`,
    `nuclei -u http://t -tags cve,rce -severity critical`,
    'nikto -h http://target -Tuning 9',
    'whatweb https://target.example.com',
    'nmap -sV -p- 10.0.0.5',
    'ffuf -u http://t/FUZZ -w wordlist.txt -mc 200',
    // Legitimate scoped cleanup — tools do this constantly and it must pass.
    'rm -rf /tmp/scan-output-1234',
    'rm -rf /opt/pentest/output/run-9',
    'rm -f /tmp/sqlmap.log',
    'rm -rf ./node_modules',
    'rm -rf target_dump',
    // Targets / args whose NAMES contain destructive substrings.
    'curl -s https://dropbox.com/api/files',
    'nuclei -u https://my-redshift-cluster.example.com',
    'echo "deleted_at column check" >> /tmp/notes.txt',
    'git init && git add -A',
    // dd that is not writing to a block device.
    'dd if=payload.bin of=/tmp/out.bin bs=512',
    // mysql/redis reads (no destructive verb at command position).
    `mysql -h target -e "SELECT * FROM users LIMIT 5"`,
    `redis-cli -h target GET session:abc`,
  ];

  it.each(ALLOWED)('allows: %s', (command) => {
    expect(screenCommand(command).blocked).toBe(false);
  });
});

describe('isDestructiveIntent — exploit-tool intent guard', () => {
  it('flags destructive metasploit module paths', () => {
    expect(isDestructiveIntent('auxiliary/dos/tcp/synflood {}')).toBe(true);
    expect(isDestructiveIntent('exploit/windows/smb/ms08_067 {"action":"delete"}')).toBe(true);
  });

  it('flags destructive script bodies', () => {
    expect(isDestructiveIntent('DROP TABLE users; -- payload')).toBe(true);
    expect(isDestructiveIntent('redis-cli FLUSHALL')).toBe(true);
    expect(isDestructiveIntent('rm -rf /data')).toBe(true);
  });

  it('does NOT flag a target named like a destructive word', () => {
    // word-boundary fix: "dropbox" must not match "drop"
    expect(isDestructiveIntent('exploit/multi/http/scan {"RHOST":"dropbox.com"}')).toBe(false);
    expect(isDestructiveIntent('auxiliary/scanner/http/dir {"VHOST":"redshift.internal"}')).toBe(false);
  });

  it('does NOT flag a benign read-only exploit', () => {
    expect(isDestructiveIntent('auxiliary/scanner/http/title {"RHOSTS":"10.0.0.1"}')).toBe(false);
  });
});
