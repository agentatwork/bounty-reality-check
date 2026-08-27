#!/usr/bin/env node
'use strict';
// Tests for signedlib.js.
//
// The headline of this survey is a *negative*: most signed files cannot be verified from what they
// publish. A negative finding is only as good as the harness's ability to tell "this genuinely does
// not verify" from "my pipeline is broken", and those look identical from the outside. So the core
// of this file is not the table of hand-made bodies — it is the round trip at the bottom, which
// makes a real key, signs a real body, and checks that the same code says GOOD here, BAD on a
// tampered byte, and NO MATCHING KEY against a second key generated for that purpose.
//
//   node signed_test.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const lib = require('./signedlib');

let failures = 0;
function check(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g !== w) { failures++; console.log(`FAIL ${name}\n  got  ${g}\n  want ${w}`); }
}

// ---------------------------------------------------------------- detection
const SIG_BLOCK = `${lib.SIG_HEADER}\n\niQIzBAEBCgAdFiEE\n-----END PGP SIGNATURE-----\n`;
const signedBody = `${lib.CLEARTEXT_HEADER}\nHash: SHA512\n\nContact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\n${SIG_BLOCK}`;

const DETECT = [
  ['plain unsigned file', 'Contact: mailto:security@example.com\n', { signed: false, strict: false, why: 'unsigned' }],
  ['empty body', '', { signed: false, strict: false, why: 'empty' }],
  ['conforming signed file (§4: the cleartext header opens the body)', signedBody,
    { signed: true, strict: true, why: 'cleartext' }],
  ['signed but with junk before the header — a verifier starting at byte 0 sees nothing',
    `# hello\n${signedBody}`, { signed: true, strict: false, why: 'cleartext_with_preamble' }],
  ['leading blank lines are still strict', `\n\n${signedBody}`, { signed: true, strict: true, why: 'cleartext' }],
  ['a pasted public key is not a signature',
    `Contact: mailto:security@example.com\n${lib.KEY_HEADER}\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n`,
    { signed: false, strict: false, why: 'key_block_only' }],
  ['cleartext header with no signature block', `${lib.CLEARTEXT_HEADER}\n\nContact: x\n`,
    { signed: false, strict: false, why: 'header_without_signature' }],
  ['signature block with no cleartext header', `Contact: x\n${SIG_BLOCK}`,
    { signed: false, strict: false, why: 'signature_without_header' }],
  ['armor strings are case-sensitive (%s"..." in the ABNF)',
    signedBody.replace(lib.CLEARTEXT_HEADER, '-----begin pgp signed message-----'),
    { signed: false, strict: false, why: 'signature_without_header' }],
];
for (const [name, body, want] of DETECT) check(`signedState: ${name}`, lib.signedState(body), want);

// ---------------------------------------------------------------- splitting
{
  const p = lib.splitSigned(signedBody);
  check('splitSigned: signed content excludes the armor headers',
    p.content, 'Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\n');
  check('splitSigned: signature block is captured whole',
    p.signature.startsWith(lib.SIG_HEADER) && p.signature.includes(lib.SIG_TAIL), true);

  // RFC 4880 §7.1: a line starting with a dash is escaped as "- -" in the cleartext body, and the
  // escape is not part of what was signed. Miss this and every field on such a line is invisible.
  const dashed = `${lib.CLEARTEXT_HEADER}\nHash: SHA256\n\n- -----------------\nContact: mailto:a@example.com\n${SIG_BLOCK}`;
  check('splitSigned: undoes dash-escaping', lib.splitSigned(dashed).content,
    '-----------------\nContact: mailto:a@example.com\n');

  // No Hash: header at all — still legal, and the blank line still ends the armor headers.
  const noHash = `${lib.CLEARTEXT_HEADER}\n\nContact: mailto:a@example.com\n${SIG_BLOCK}`;
  check('splitSigned: no Hash header', lib.splitSigned(noHash).content, 'Contact: mailto:a@example.com\n');

  // A line holding a single space is not empty, but gpg treats it as the end of the armor headers
  // and verifies such files. Two live files in the corpus are written this way, and rejecting them
  // would have reported them as unparseable while the reference implementation reads them fine.
  const spaceSep = `${lib.CLEARTEXT_HEADER}\r\nHash: SHA512\r\n \r\nContact: mailto:a@example.com\r\n${SIG_BLOCK}`;
  check('splitSigned: a whitespace-only line ends the armor headers, as gpg does',
    lib.splitSigned(spaceSep).content, 'Contact: mailto:a@example.com\r\n');
}

// ---------------------------------------------------------------- fields
check('fieldsOf: comments and blanks ignored, names lowercased, repeats kept',
  lib.fieldsOf('# a comment\n\nContact: mailto:a@example.com\ncontact: https://example.com/report\nExpires: 2030-01-01T00:00:00Z\nnot a field line\n'),
  { contact: ['mailto:a@example.com', 'https://example.com/report'], expires: ['2030-01-01T00:00:00Z'] });

// ---------------------------------------------------------------- Encryption forms (§2.5.6)
for (const [v, want] of [
  ['https://example.com/pgp-key.txt', 'https'],
  ['http://example.com/pgp-key.txt', 'http_violates_2_5_6'],
  ['dns:5d2d37ab76d47d36._openpgpkey.example.com?type=OPENPGPKEY', 'dns'],
  ['openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f', 'openpgp4fpr'],
  ['security@example.com', 'other'],
]) check(`encryptionKind: ${v.slice(0, 28)}`, lib.encryptionKind(v), want);

// ------------------------------------------------------- published exit codes
// sigcheck.js documents these in an article as something readers will script against. An exit code
// is the one output nobody eyeballs, so the mapping is tested rather than trusted — and the states
// below are otherwise reachable only by finding a live domain in each of six conditions.
const VERDICTS = [
  ['host did not answer', { fetch_failed: true }, ['NO-FILE', 1]],
  ['no signature', { signed: false, why: 'unsigned' }, ['UNSIGNED', 5]],
  ['a pasted key block is not a signature', { signed: false, why: 'key_block_only' }, ['UNSIGNED', 5]],
  ['malformed armor', { signed: true, parseable: false }, ['UNPARSEABLE', 1]],
  ['signed, no key published', { signed: true, parseable: true, canonical: true, encryption_kinds: [], has_http_key_url: false },
    ['NO-KEY-PUBLISHED', 3]],
  ['signed, key only out-of-band — not a fault', { signed: true, parseable: true, canonical: true,
    encryption_kinds: ['openpgp4fpr'], has_http_key_url: false }, ['NO-KEY-PUBLISHED', 3]],
  // The pass. Everything else is a warning or worse.
  ['verifies against an off-origin key', { signed: true, parseable: true, canonical: true, has_http_key_url: true,
    key: { verified: true, same_origin: false, keyserver: true } }, ['VERIFIES', 0]],
  // A key from the origin that served the file cannot testify about that file.
  ['verifies circularly', { signed: true, parseable: true, canonical: true, has_http_key_url: true,
    key: { verified: true, same_origin: true } }, ['VERIFIES-CIRCULARLY', 4]],
  ['verifies but no Canonical', { signed: true, parseable: true, canonical: false, has_http_key_url: true,
    key: { verified: true, same_origin: false } }, ['VERIFIES', 4]],
  ['bad signature outranks a missing Canonical', { signed: true, parseable: true, canonical: false,
    has_http_key_url: true, key: { verified: false, verify: 'bad_signature', same_origin: false } },
    ['BAD-SIGNATURE', 2]],
  // §2.5.6 permits signing with a key that appears nowhere in the file, so this is never the
  // site's error — it is reported as "you cannot check this", not "they got it wrong".
  ['issuer is not the published key', { signed: true, parseable: true, canonical: true, has_http_key_url: true,
    key: { verified: false, verify: 'no_matching_key', fetch: 'ok' } }, ['UNVERIFIABLE', 3]],
  ['key URL did not fetch', { signed: true, parseable: true, canonical: true, has_http_key_url: true,
    key: { verified: false, fetch: 'HTTP 404' } }, ['UNVERIFIABLE', 3]],
];
for (const [name, facts, [result, exit]] of VERDICTS) {
  const v = lib.sigVerdict(facts);
  check(`sigVerdict: ${name}`, [v.result, v.exit], [result, exit]);
}
check('sigVerdict: a revoked key is a warning on top of a pass, not a different verdict',
  !!lib.sigVerdict({ signed: true, parseable: true, canonical: true, has_http_key_url: true,
    key: { verified: true, same_origin: false, key_revoked: true } }).warning, true);

// ---------------------------------------------------------------- round trip
// Everything above tests my string handling against my own expectations. This tests the crypto
// verdicts against gpg, using keys made here, so a GOOD is really good and a "no matching key" is
// really a different key rather than a broken invocation.
// No passphrase, and loopback pinentry — there is no tty here, and without it gpg-agent fails with
// "Inappropriate ioctl for device" rather than anything about keys.
const NOPIN = ['--pinentry-mode', 'loopback', '--passphrase', ''];
function makeKey(home, name) {
  execFileSync('gpg', ['--batch', '--no-tty', ...NOPIN, '--quick-generate-key', `${name} <${name}@example.com>`,
    'ed25519', 'sign', 'never'], { env: { ...process.env, GNUPGHOME: home, LC_ALL: 'C' }, encoding: 'utf8', timeout: 60000 });
  return execFileSync('gpg', ['--batch', '--no-tty', '--armor', '--export', `${name}@example.com`],
    { env: { ...process.env, GNUPGHOME: home, LC_ALL: 'C' }, encoding: 'latin1', timeout: 60000 });
}
function clearsign(home, name, text) {
  return execFileSync('gpg', ['--batch', '--no-tty', ...NOPIN, '--yes', '--local-user', `${name}@example.com`,
    '--clearsign', '--output', '-'], { input: text, env: { ...process.env, GNUPGHOME: home, LC_ALL: 'C' },
    encoding: 'latin1', timeout: 60000 });
}

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'stxttest-'));
fs.chmodSync(home, 0o700);
let roundTripRan = false;
try {
  const CONTENT = 'Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\n';
  const keyA = makeKey(home, 'alice');
  const keyB = makeKey(home, 'bob');
  const file = clearsign(home, 'alice', CONTENT);
  roundTripRan = true;

  check('round trip: a real clearsigned file is detected as strictly signed',
    lib.signedState(file), { signed: true, strict: true, why: 'cleartext' });

  const parts = lib.splitSigned(file);
  check('round trip: recovered content is byte-identical to what was signed', parts.content, CONTENT);

  const issuer = lib.signatureIssuer(parts.signature);
  check('round trip: issuer key ID is readable with no key present', issuer.parsed && !!issuer.keyid, true);

  const kA = lib.inspectKey(keyA);
  const kB = lib.inspectKey(keyB);
  check('round trip: the issuer is one of the signer key\'s IDs',
    kA.keyids.some((id) => id.endsWith(issuer.keyid)), true);
  // The negative control the whole survey rests on. Bob's key is a real, valid, importable key —
  // it is simply not the one that signed. If this ever reported anything but no_matching_key, the
  // published "cannot be verified from what the file publishes" number would be an artefact.
  check('round trip: a DIFFERENT valid key does not match the issuer',
    kB.keyids.some((id) => id.endsWith(issuer.keyid)), false);

  check('round trip: verifying with the right key is good', lib.verifyWith(keyA, file),
    { verified: true, reason: 'good' });
  check('round trip: verifying with a different valid key is no_matching_key',
    lib.verifyWith(keyB, file), { verified: false, reason: 'no_matching_key' });

  const tampered = file.replace('security@example.com', 'attacker@example.com');
  check('round trip: a tampered body is a BAD signature, not a missing key',
    lib.verifyWith(keyA, tampered), { verified: false, reason: 'bad_signature' });

  check('round trip: a key that is not a key is reported as such', lib.inspectKey('hello, not a key\n').ok, false);
  check('round trip: neither generated key is expired or revoked',
    [kA.expired, kA.revoked, kB.expired, kB.revoked], [false, false, false, false]);
} finally {
  try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
}

if (!roundTripRan) { failures++; console.log('FAIL round trip never ran — gpg key generation failed'); }

if (failures) { console.log(`\n${failures} failing`); process.exit(1); }
console.log('OK — detection states, dash-escaping, Encryption forms, and a real sign/verify/tamper round trip');
