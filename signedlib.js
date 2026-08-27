'use strict';
// Detection and offline inspection of OpenPGP cleartext signatures on security.txt files.
//
// One copy of these rules, imported by both the analyzer and the test. The last survey shipped a
// wrong published number because a four-line parser existed twice and the fix only landed in one
// of them, so nothing in this directory gets hand-copied again.

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// RFC 9116 §4:
//   body    = signed / unsigned
//   signed  = cleartext-header CRLF hash-header ... signature
// The cleartext header opens the *body*, so a conforming signed file starts with it at offset 0.
// The armor strings are %s"..." productions in the ABNF, i.e. case-sensitive.
const CLEARTEXT_HEADER = '-----BEGIN PGP SIGNED MESSAGE-----';
const SIG_HEADER = '-----BEGIN PGP SIGNATURE-----';
const SIG_TAIL = '-----END PGP SIGNATURE-----';
// A public key block is not a signature. Files paste one inline and a naive "contains PGP" test
// counts them as signed; they are the opposite — an unsigned file carrying a key.
const KEY_HEADER = '-----BEGIN PGP PUBLIC KEY BLOCK-----';

// Strict = the wrapper opens the body, as the ABNF requires. Lenient = it appears anywhere, which
// catches files with a stray BOM or leading blank lines. Both are reported: the gap between them
// is a measurement of sloppiness, not something to silently absorb into one number.
function signedState(body) {
  if (typeof body !== 'string' || !body) return { signed: false, strict: false, why: 'empty' };
  const hasHeader = body.includes(CLEARTEXT_HEADER);
  const hasSig = body.includes(SIG_HEADER) && body.includes(SIG_TAIL);
  if (!hasHeader && !hasSig) {
    return { signed: false, strict: false, why: body.includes(KEY_HEADER) ? 'key_block_only' : 'unsigned' };
  }
  if (hasHeader && !hasSig) return { signed: false, strict: false, why: 'header_without_signature' };
  if (!hasHeader && hasSig) return { signed: false, strict: false, why: 'signature_without_header' };
  // Leading whitespace/BOM only; anything else before the header means the header is not opening
  // the body and a verifier that starts at offset 0 will not see a signed file.
  const pre = body.slice(0, body.indexOf(CLEARTEXT_HEADER));
  const strict = /^﻿?\s*$/.test(pre);
  return { signed: true, strict, why: strict ? 'cleartext' : 'cleartext_with_preamble' };
}

// The bytes the signature actually covers: everything between the blank line that ends the
// cleartext headers and the start of the armored signature. Dash-escaping ("- " prefixes) is
// undone, per RFC 4880 §7.1.
function splitSigned(body) {
  const h = body.indexOf(CLEARTEXT_HEADER);
  if (h < 0) return null;
  const afterHeader = body.indexOf('\n', h);
  if (afterHeader < 0) return null;
  // Optional Hash: armor headers, terminated by a blank line. gpg accepts a whitespace-only line
  // here, and two real files in the corpus terminate their headers with a line containing a single
  // space — gpg verifies them, so a stricter reading would report them as unparseable when the
  // reference implementation has no trouble. The question being measured is what a researcher's
  // tool can do, which makes gpg the authority rather than my reading of the ABNF.
  let i = afterHeader + 1;
  while (i < body.length) {
    const eol = body.indexOf('\n', i);
    const line = (eol < 0 ? body.slice(i) : body.slice(i, eol)).replace(/\r$/, '');
    i = eol < 0 ? body.length : eol + 1;
    if (line.trim() === '') break;
  }
  const s = body.indexOf(SIG_HEADER, i);
  if (s < 0) return null;
  const e = body.indexOf(SIG_TAIL, s);
  if (e < 0) return null;
  const content = body.slice(i, s).replace(/^- /gm, '');
  const signature = body.slice(s, e + SIG_TAIL.length) + '\n';
  return { content, signature };
}

// spawnSync, not execFileSync: gpg writes its verdict to stderr, and execFileSync only hands back
// stderr when the command *fails*. On a good signature it exits 0, so the one line that mattered
// was being inherited to the terminal and lost — every verification came back "unknown". The test
// below caught it; nothing about the output looked wrong until an assertion asked.
function gpg(args, input, home) {
  const r = spawnSync('gpg', ['--batch', '--no-tty', ...args], {
    input: input === undefined || input === null ? undefined : input,
    encoding: 'latin1',
    timeout: 20000,
    maxBuffer: 8 << 20,
    env: { ...process.env, GNUPGHOME: home, LC_ALL: 'C' },
  });
  return { out: String(r.stdout || ''), err: String(r.stderr || (r.error && r.error.message) || ''),
    code: r.status ?? -1 };
}

function withHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'stxtgpg-'));
  try { fs.chmodSync(home, 0o700); return fn(home); }
  finally { try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ } }
}

// Who made this signature, read off the packet. No key required, so this does not assume the
// Encryption key is the signing key — RFC 9116 §2.5.6 says not to, and this is the whole reason
// the measurement is possible without making that assumption.
function signatureIssuer(signatureArmor) {
  return withHome((home) => {
    const r = gpg(['--list-packets'], signatureArmor, home);
    const text = r.out + '\n' + r.err;
    const keyid = /keyid ([0-9A-Fa-f]{8,40})/.exec(text);
    const fpr = /issuer fpr v\d ([0-9A-Fa-f]{32,40})/.exec(text);
    const created = /\(sig created (\d{4}-\d{2}-\d{2})\)/.exec(text);
    const epoch = /created (\d{9,12})/.exec(text);
    const algo = /:signature packet: algo (\d+)/.exec(text);
    if (!keyid && !fpr) return { parsed: false, error: text.trim().split('\n')[0] || 'no packet' };
    return {
      parsed: true,
      keyid: keyid ? keyid[1].toUpperCase() : null,
      fingerprint: fpr ? fpr[1].toUpperCase() : null,
      created: created ? created[1] : null,
      created_epoch: epoch ? Number(epoch[1]) : null,
      algo: algo ? Number(algo[1]) : null,
    };
  });
}

// What the published key actually is: its key IDs (primary and subkeys — a signature is usually
// made by a signing *subkey*, so comparing only the primary would undercount coincidence),
// whether it is expired, and whether it is revoked.
function inspectKey(keyArmorOrBin) {
  return withHome((home) => {
    const imp = gpg(['--import'], keyArmorOrBin, home);
    const colons = gpg(['--with-colons', '--fixed-list-mode', '--list-keys'], null, home);
    const ids = new Set(), fprs = new Set();
    let expired = false, revoked = false, any = false, expires = null;
    let lastWasKey = false;
    for (const line of colons.out.split('\n')) {
      const f = line.split(':');
      if (f[0] === 'pub' || f[0] === 'sub') {
        any = true; lastWasKey = true;
        if (f[4]) ids.add(f[4].toUpperCase());
        // Validity flags are per-key: e=expired, r=revoked. Read them off both pub and sub.
        if (f[1] && f[1].includes('e')) expired = true;
        if (f[1] && f[1].includes('r')) revoked = true;
        if (f[0] === 'pub' && f[6]) expires = Number(f[6]) || null;
      } else if (f[0] === 'fpr' && lastWasKey) {
        if (f[9]) fprs.add(f[9].toUpperCase());
      } else if (f[0] === 'uid') {
        lastWasKey = false;
      }
    }
    if (!any) return { ok: false, error: (imp.err.split('\n').find((l) => l.includes('gpg:')) || 'no key').trim().slice(0, 120) };
    return { ok: true, keyids: [...ids], fingerprints: [...fprs], expired, revoked, expires_epoch: expires };
  });
}

// Does the signature verify against this key? Run in a throwaway keyring so no earlier import can
// make a later file look verifiable.
function verifyWith(keyArmorOrBin, body) {
  return withHome((home) => {
    const imp = gpg(['--import'], keyArmorOrBin, home);
    if (/no valid OpenPGP data|invalid|failed/i.test(imp.err) && !/imported/i.test(imp.err)) {
      return { verified: false, reason: 'key_import_failed' };
    }
    const f = path.join(home, 'stxt.asc');
    fs.writeFileSync(f, body, 'latin1');
    // --status-fd 1 gives stable [GNUPG:] tokens instead of English prose. It also distinguishes
    // things the prose blurs: EXPKEYSIG and REVKEYSIG are *good* signatures from a key that has
    // since expired or been revoked, which is a different fact from a bad signature.
    const r = gpg(['--status-fd', '1', '--verify', f], null, home);
    const status = r.out;
    if (/^\[GNUPG:\] GOODSIG /m.test(status)) return { verified: true, reason: 'good' };
    if (/^\[GNUPG:\] EXPKEYSIG /m.test(status)) return { verified: true, reason: 'good_but_key_expired' };
    if (/^\[GNUPG:\] REVKEYSIG /m.test(status)) return { verified: true, reason: 'good_but_key_revoked' };
    if (/^\[GNUPG:\] EXPSIG /m.test(status)) return { verified: true, reason: 'good_but_signature_expired' };
    if (/^\[GNUPG:\] BADSIG /m.test(status)) return { verified: false, reason: 'bad_signature' };
    if (/^\[GNUPG:\] NO_PUBKEY /m.test(status)) return { verified: false, reason: 'no_matching_key' };
    if (/^\[GNUPG:\] NODATA/m.test(status)) return { verified: false, reason: 'no_signature_data' };
    const errsig = /^\[GNUPG:\] ERRSIG \S+ \S+ \S+ \S+ \S+ (\d+)/m.exec(status);
    if (errsig) return { verified: false, reason: errsig[1] === '9' ? 'no_matching_key' : 'errsig_' + errsig[1] };
    return { verified: false, reason: (r.err.split('\n').find((l) => l.startsWith('gpg: ')) || 'unknown').slice(0, 120) };
  });
}

// Field parsing over the *signed* region only. Fields outside the signature are not covered by it,
// which matters: a Contact line sitting after the armor tail is unsigned even in a "signed" file.
function fieldsOf(text) {
  const out = {};
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line || line.startsWith('#')) continue;
    const m = /^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const k = m[1].toLowerCase();
    (out[k] = out[k] || []).push(m[2].trim());
  }
  return out;
}

// RFC 9116 §2.5.6: the value MUST be a URI, and a web URI MUST begin with "https://". The other
// two legal forms cannot be fetched over HTTP at all, so they are counted, not resolved.
function encryptionKind(v) {
  if (/^https:\/\//i.test(v)) return 'https';
  if (/^http:\/\//i.test(v)) return 'http_violates_2_5_6';
  if (/^dns:/i.test(v)) return 'dns';
  if (/^openpgp4fpr:/i.test(v)) return 'openpgp4fpr';
  return 'other';
}

function hostOf(u) {
  try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return null; }
}

/**
 * The published contract of sigcheck.js: given what was observed about a file, what does the tool
 * conclude and what does it exit with?
 *
 * This lives here rather than inline in the CLI for the same reason stxtlib.triage does. The exit
 * codes are documented in an article as something readers will script against, and an exit code is
 * the one output nobody eyeballs — inline, the only way to exercise the mapping would be to find a
 * live domain in each of six states, which is exactly how a wrong one survives.
 *
 * The precedence that matters: a BAD signature outranks everything, because it is the only state
 * that tells a researcher your file may have been tampered with. "Verifies, but circularly" is a
 * warning and not a pass, because a key served from the origin that served the file cannot testify
 * about that file. And an unverifiable signature is never reported as the site's error: §2.5.6
 * permits signing with a key that appears nowhere in the file.
 *
 * `facts.key` is the best candidate among the published Encryption URLs, or null if none was
 * fetchable.
 */
function sigVerdict(facts) {
  const f = facts || {};
  if (f.fetch_failed) return { result: 'NO-FILE', exit: 1 };
  if (!f.signed) {
    return { result: 'UNSIGNED', exit: 5, detail:
      f.why === 'key_block_only' ? 'the file pastes a PGP PUBLIC KEY BLOCK — that is a key, not a signature'
      : f.why === 'header_without_signature' ? 'a cleartext header with no signature block after it'
      : f.why === 'signature_without_header'
        ? 'a signature block with no BEGIN PGP SIGNED MESSAGE header — nothing states what it covers'
        : 'no OpenPGP cleartext signature' };
  }
  if (!f.parseable) {
    return { result: 'UNPARSEABLE', exit: 1,
      detail: 'the armor is malformed — no signature can be extracted, by any tool, with any key' };
  }
  if (!f.has_http_key_url) {
    return { result: 'NO-KEY-PUBLISHED', exit: 3, detail:
      (f.encryption_kinds || []).length
        ? `Encryption is published only as ${f.encryption_kinds.join(', ')} — a reader must resolve `
          + 'it out of band (which is the stronger choice, and cannot be checked from here)'
        : 'no Encryption field, so nothing in the file leads to a key' };
  }
  const k = f.key || {};
  if (k.verified) {
    const problems = [];
    if (k.same_origin) {
      problems.push('the key is served from your own origin, so anyone who can replace the file '
        + 'can replace the key: the signature restates your TLS certificate and adds nothing');
    }
    if (!f.canonical) {
      problems.push('no Canonical, so the signature authenticates these bytes but not their '
        + 'location — copied verbatim to another origin it still verifies (RFC 9116 §2.3)');
    }
    return {
      result: k.same_origin ? 'VERIFIES-CIRCULARLY' : 'VERIFIES',
      exit: problems.length ? 4 : 0,
      detail: problems.length ? problems.join('; ')
        : 'the signature verifies against a key you do not serve yourself'
          + (k.keyserver ? ' (a public keyserver)' : ''),
      warning: k.key_revoked
        ? 'the key you publish is REVOKED — its owner has asked the world to stop trusting it' : undefined,
    };
  }
  if (k.verify === 'bad_signature') {
    return { result: 'BAD-SIGNATURE', exit: 2,
      detail: 'the signature does not match this file under the key you publish. The usual cause '
        + 'is an edit after signing — a bumped Expires, a changed address — with no re-sign.' };
  }
  return { result: 'UNVERIFIABLE', exit: 3, detail:
    k.fetch && k.fetch !== 'ok' ? `your Encryption URL did not fetch (${k.fetch})`
    : k.key_error ? `your Encryption URL does not serve a key (${k.key_error})`
      : 'the signature was made by a key that is not the one you publish — legal under §2.5.6, '
        + 'and it leaves a researcher with no way to check' };
}

module.exports = {
  CLEARTEXT_HEADER, SIG_HEADER, SIG_TAIL, KEY_HEADER,
  signedState, splitSigned, signatureIssuer, inspectKey, verifyWith, fieldsOf, encryptionKind, hostOf,
  sigVerdict,
};
