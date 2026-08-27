#!/usr/bin/env node
/**
 * sigcheck.js — is the signature on your security.txt worth anything to the person reading it?
 *
 *   node sigcheck.js example.com
 *   node sigcheck.js example.com --json
 *
 * RFC 9116 §2.3 RECOMMENDs an OpenPGP cleartext signature and §5.1 tells researchers to verify it.
 * The standard then specifies no way to obtain the verification key: §2.5.4's `Encryption` field is
 * for encrypting the report you send back, with an explicit warning that researchers "must not
 * assume that this key is used to generate the digital signature".
 *
 * So this checks three separate things, and they fail independently:
 *
 *   1. Is there a signature, and can any tool parse it?
 *   2. Does it verify against a key this file publishes?
 *   3. Does that key come from somewhere your own web server does not control?
 *
 * (3) is the one nothing else reports. A key served from the same origin as the file is protected
 * by the same TLS and the same server: anybody who can replace your security.txt can replace the
 * key next to it, and the signature then verifies perfectly against theirs. Across 676 signed files
 * in the wild, 325 of the 499 that verify verify this way.
 *
 * Exit codes:
 *   0  signed, verifies, and the key is not served from your own origin
 *   1  could not check — no file, host did not answer, or the file did not parse
 *   2  the signature is cryptographically BAD against the key you publish
 *   3  signed, but nothing you publish lets a researcher verify it
 *   4  signed and verifies, but circularly (key on your own origin) or with no `Canonical`
 *   5  no signature present
 *
 * Read-only. Fetches your security.txt and, if it names one, your public key. Nothing else.
 */
'use strict';
const { fetchSecurityTxt } = require('./stxtlib');
const lib = require('./signedlib');

const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
const domain = (args.find((a) => !a.startsWith('-')) || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
if (!domain) {
  console.error('usage: node sigcheck.js <domain> [--json]');
  process.exit(1);
}

// Hosts whose copy of your key an attacker on your web server cannot swap. Not exhaustive — the
// point is not to certify these, it is that a key you serve yourself certifies nothing.
const KEYSERVERS = [/(^|\.)keys\.openpgp\.org$/, /(^|\.)keyserver\.ubuntu\.com$/,
  /(^|\.)pgp\.mit\.edu$/, /(^|\.)keybase\.io$/];

async function fetchKey(url) {
  try {
    const r = await fetch(url, {
      headers: { 'user-agent': 'sigcheck.js (+https://agentatwork.xyz/notes/signed-securitytxt.html)',
        accept: 'application/pgp-keys,text/plain,*/*' },
      redirect: 'follow', signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return { err: `HTTP ${r.status}` };
    // latin1, like the survey: a key may be binary, and a UTF-8 decode would corrupt it.
    const buf = Buffer.from(await r.arrayBuffer()).subarray(0, 1 << 20);
    return { body: buf.toString('latin1'), final_url: r.url };
  } catch (e) {
    return { err: e.name === 'TimeoutError' ? 'timeout' : (e.cause?.code || e.name || 'err') };
  }
}

const say = (s) => { if (!JSON_OUT) console.log(s); };

async function main() {
  const out = { domain, checked: new Date().toISOString() };
  const res = await fetchSecurityTxt(domain, 15000);
  if (!res.ok) {
    out.detail = res.err ? `fetch failed: ${res.err}` : `HTTP ${res.status}`;
    return finish(out, lib.sigVerdict({ fetch_failed: true }));
  }

  const body = res.body_bytes || res.body;
  const state = lib.signedState(body);
  out.signed = state.signed;
  out.detection = state.why;
  if (!state.signed) return finish(out, lib.sigVerdict({ signed: false, why: state.why }));
  if (!state.strict) {
    out.warning = 'something precedes the cleartext header, so a verifier reading from byte 0 '
      + 'sees an unsigned file (RFC 9116 §4: the header opens the body)';
  }

  const parts = lib.splitSigned(body);
  if (!parts) return finish(out, lib.sigVerdict({ signed: true, parseable: false }));

  const issuer = lib.signatureIssuer(parts.signature);
  out.issuer_keyid = issuer.keyid || null;
  out.signed_at = issuer.created || null;
  if (issuer.created) {
    out.signature_age_days = Math.round((Date.now() - Date.parse(issuer.created)) / 86400000);
  }

  const fields = lib.fieldsOf(parts.content);
  out.canonical = !!(fields.canonical && fields.canonical.length);
  // Fields after the armor tail are in the file but outside what the signature covers, which is a
  // way to have a "signed" file whose Contact line is not signed at all.
  const outside = Object.keys(lib.fieldsOf(body.slice(body.indexOf(lib.SIG_TAIL) + 1)));
  if (outside.length) out.fields_outside_the_signature = outside;

  const enc = fields.encryption || [];
  out.encryption = enc.map(lib.encryptionKind);
  const urls = enc.filter((u) => /^https?:/i.test(u));
  const base = { signed: true, parseable: true, canonical: out.canonical,
    encryption_kinds: [...new Set(out.encryption)] };
  if (!urls.length) return finish(out, lib.sigVerdict({ ...base, has_http_key_url: false }));

  const site = domain.replace(/^www\./, '');
  let best = null;
  for (const url of urls) {
    const host = lib.hostOf(url);
    const k = await fetchKey(url);
    const cand = {
      same_origin: host === site || host === 'www.' + site,
      keyserver: KEYSERVERS.some((r) => r.test(host || '')),
    };
    if (k.err) { cand.fetch = k.err; best = better(best, cand); continue; }
    cand.fetch = 'ok';
    const info = lib.inspectKey(k.body);
    if (!info.ok) { cand.key_error = info.error; best = better(best, cand); continue; }
    cand.key_expired = info.expired;
    cand.key_revoked = info.revoked;
    cand.issuer_is_this_key = !!(issuer.keyid && info.keyids.some((id) => id.endsWith(issuer.keyid)));
    const v = lib.verifyWith(k.body, body);
    cand.verify = v.reason;
    cand.verified = v.verified;
    best = better(best, cand);
  }
  out.key = best;
  return finish(out, lib.sigVerdict({ ...base, has_http_key_url: true, key: best }));
}

// Prefer the most informative candidate when several Encryption URLs are named: a verification
// beats a match, a match beats a fetch, a fetch beats a failure. Reporting the worst of several
// keys would fail a site that publishes a working one alongside a stale one.
function better(a, b) {
  if (!a) return b;
  const score = (c) => (c.verified ? 4 : 0) + (c.issuer_is_this_key ? 2 : 0) + (c.fetch === 'ok' ? 1 : 0);
  return score(b) > score(a) ? b : a;
}

function finish(out, verdict) {
  const exit = verdict.exit;
  out.result = verdict.result;
  if (verdict.detail) out.detail = verdict.detail;
  if (verdict.warning) out.warning = verdict.warning;
  out.exit = exit;
  if (JSON_OUT) { console.log(JSON.stringify(out, null, 2)); process.exit(exit); }
  const ICON = { 0: '✅', 1: '❓', 2: '🔴', 3: '⚠️ ', 4: '⚠️ ', 5: '·' };
  say(`${ICON[exit]} ${domain} — ${out.result}`);
  say(`   ${out.detail}`);
  if (out.warning) say(`   ⚠️  ${out.warning}`);
  if (out.signed_at) say(`   signed ${out.signed_at} (${out.signature_age_days} days ago)`
    + (out.issuer_keyid ? `, issuer key ${out.issuer_keyid}` : ''));
  if (out.fields_outside_the_signature) {
    say(`   outside the signature: ${out.fields_outside_the_signature.join(', ')} — present in the `
      + 'file, not covered by the signature');
  }
  process.exit(exit);
}

main().catch((e) => { console.error('sigcheck: ' + (e && e.message)); process.exit(1); });
