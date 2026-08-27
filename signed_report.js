#!/usr/bin/env node
'use strict';
// Every number the signed-security.txt writeup quotes, produced in one place.
//
// The alternative is computing figures in a shell one-liner while drafting, which is how a
// published sentence ends up carrying a number from a pilot run. Anything the article states comes
// out of this file, and draftcheck.js reads its output to confirm that.
//
//   node signed_report.js /tmp/stxt_signed.json /tmp/stxt_all.jsonl /tmp/stxt_bodies.jsonl /tmp/stxt_signed_report.json

const fs = require('fs');
const lib = require('./signedlib');
const { wilson } = require('./stats');

const [resPath, corpusPath, bodiesPath, outPath] = process.argv.slice(2);
if (!resPath || !corpusPath || !bodiesPath || !outPath) {
  console.error('usage: node signed_report.js <result.json> <corpus.jsonl> <bodies.jsonl> <out.json>');
  process.exit(1);
}

const R = JSON.parse(fs.readFileSync(resPath, 'utf8'));
const V = R.verdicts;
const A = R.aggregate;
const S = R.stats;

const rate = (k, n) => {
  const [lo, hi] = wilson(k, n);
  return { k, n, pct: n ? Number((100 * k / n).toFixed(2)) : null,
    ci: [Number((100 * lo).toFixed(2)), Number((100 * hi).toFixed(2))] };
};

// ---- corpus joins ----
const corpus = new Map();
for (const line of fs.readFileSync(corpusPath, 'utf8').split('\n')) {
  if (!line) continue;
  let d; try { d = JSON.parse(line); } catch { continue; }
  if (d.is_security_txt) corpus.set(d.domain, d);
}
const bodies = new Map();
for (const line of fs.readFileSync(bodiesPath, 'utf8').split('\n')) {
  if (!line) continue;
  let d; try { d = JSON.parse(line); } catch { continue; }
  bodies.set(d.domain, d);
}
const keys = new Map();
const keyCache = bodiesPath + '.keys.jsonl';
if (fs.existsSync(keyCache)) {
  for (const line of fs.readFileSync(keyCache, 'utf8').split('\n')) {
    if (!line) continue;
    try { const d = JSON.parse(line); keys.set(d.url, d.res); } catch { /* skip */ }
  }
}

const verifies = V.filter((v) => v.verify.startsWith('good'));
const cnt = (f, arr = V) => arr.filter(f).length;

// ---- is a bad signature actually the site's, or my transport? ----
// A claim that 33 organisations serve a cryptographically invalid signature is a claim about them,
// so the alternative explanation gets tested rather than dismissed: any whitespace, line-ending or
// framing difference introduced between their signing and my reading would produce exactly this.
function keyFor(domain) {
  const b = bodies.get(domain);
  if (!b) return null;
  const parts = lib.splitSigned(b.body || '');
  if (!parts) return null;
  for (const e of (lib.fieldsOf(parts.content).encryption || [])) {
    const r = keys.get(e);
    if (r && !r.err && r.status === 200) return r.body;
  }
  return null;
}
const VARIANTS = {
  crlf: (r) => r.replace(/\r?\n/g, '\r\n'),
  lf: (r) => r.replace(/\r\n/g, '\n'),
  cr_to_lf: (r) => r.replace(/\r/g, '\n'),
  strip_trailing_ws: (r) => r.replace(/[ \t]+$/gm, ''),
  add_final_newline: (r) => (r.endsWith('\n') ? r : r + '\n'),
  drop_trailing_newlines: (r) => r.replace(/\n+$/, ''),
  strip_bom: (r) => r.replace(/^﻿|^ï»¿/, ''),
  truncate_after_armor_tail: (r) => r.slice(0, r.indexOf(lib.SIG_TAIL) + lib.SIG_TAIL.length) + '\n',
  collapse_blank_runs: (r) => r.replace(/\n{3,}/g, '\n\n'),
};
const KEYSERVERS = [/(^|\.)keys\.openpgp\.org$/, /(^|\.)keyserver\.ubuntu\.com$/,
  /(^|\.)pgp\.mit\.edu$/, /(^|\.)keybase\.io$/, /(^|\.)sks-keyservers\.net$/];

const badSigs = V.filter((v) => v.verify === 'bad_signature');
let rescued = 0, untestable = 0;
const rescuedBy = {};
for (const v of badSigs) {
  const key = keyFor(v.domain);
  const body = bodies.get(v.domain).body;
  if (!key) { untestable++; continue; }
  for (const [name, fn] of Object.entries(VARIANTS)) {
    let alt;
    try { alt = fn(body); } catch { continue; }
    if (alt === body) continue;
    if (lib.verifyWith(key, alt).verified) { rescued++; rescuedBy[name] = (rescuedBy[name] || 0) + 1; break; }
  }
}

// ---- files gpg itself will not parse ----
// Distinct from "does not verify": these cannot be checked by anyone holding any key, because the
// armor is malformed. gpg is the authority, not my reader.
const { spawnSync } = require('child_process');
const os = require('os');
const path = require('path');
let wrapperUnparseable = 0, wrapperParseable = 0;
for (const [domain, b] of bodies) {
  if (b.err || b.status !== 200) continue;
  if (!lib.signedState(b.body || '').signed) continue;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'stxtrep-'));
  fs.chmodSync(home, 0o700);
  const f = path.join(home, 'f.asc');
  fs.writeFileSync(f, b.body, 'latin1');
  const r = spawnSync('gpg', ['--batch', '--no-tty', '--status-fd', '1', '--verify', f],
    { encoding: 'latin1', env: { ...process.env, GNUPGHOME: home, LC_ALL: 'C' }, timeout: 20000 });
  const out = String(r.stdout || '');
  if (/^\[GNUPG:\] (BADARMOR|NODATA|UNEXPECTED)/m.test(out)) wrapperUnparseable++;
  else wrapperParseable++;
  fs.rmSync(home, { recursive: true, force: true });
}

// ---- what the published Encryption URLs actually serve ----
const keyShape = { armored_openpgp_key: 0, binary_openpgp_key: 0, html_page: 0, x509_certificate: 0,
  pkcs12_bag: 0, other_crypto_tool: 0, empty: 0, other: 0 };
const keyFetch = {};
for (const [, r] of keys) {
  if (r.err) { keyFetch[r.err] = (keyFetch[r.err] || 0) + 1; continue; }
  keyFetch['HTTP_' + r.status] = (keyFetch['HTTP_' + r.status] || 0) + 1;
  if (r.status !== 200) continue;
  const b = r.body || '';
  if (b.includes('BEGIN PGP PUBLIC KEY BLOCK')) keyShape.armored_openpgp_key++;
  else if (!b.trim()) keyShape.empty++;
  else if (/<html|<!doctype/i.test(b.slice(0, 400))) keyShape.html_page++;
  else if (b.includes('BEGIN CERTIFICATE')) keyShape.x509_certificate++;
  else if (b.startsWith('Bag Attributes')) keyShape.pkcs12_bag++;
  else if (/^age1|AGE-SECRET-KEY|Age is a simple/.test(b)) keyShape.other_crypto_tool++;
  else if (lib.inspectKey(b).ok) keyShape.binary_openpgp_key++;
  else keyShape.other++;
}

// ---- joins with the contact survey ----
// Being signed and being reachable are independent properties of the same file, and the interesting
// question is whether the organisations that bother to sign are also the ones whose contact works.
const expiryOf = (d) => {
  const e = corpus.get(d) && corpus.get(d).expires;
  if (!e) return 'missing';
  const t = Date.parse(e);
  if (Number.isNaN(t)) return 'unparseable';
  return t >= Date.parse(S.generated_at) ? 'valid' : 'expired';
};
const signedSet = new Set(V.map((v) => v.domain));
const expirySigned = {}, expiryAll = {};
for (const d of corpus.keys()) {
  const st = expiryOf(d);
  expiryAll[st] = (expiryAll[st] || 0) + 1;
  if (signedSet.has(d)) expirySigned[st] = (expirySigned[st] || 0) + 1;
}

const report = {
  generated_at: new Date().toISOString(),
  source_run: S.generated_at,
  corpus: {
    domains_probed: S.corpus_records,
    security_txt_files: S.security_txt_in_corpus,
    refetched: S.refetched,
    refetch_failed: S.refetch_failed,
    refetch_not_200: S.refetch_not_200,
    analyzable: S.analyzable,
  },

  // A. how many are signed at all
  signed_rate: rate(A.signed_total, S.analyzable),
  signed_by_rank_band: A.by_rank_band,
  detection: {
    // Both armor strings present. Seven of these are mangled badly enough that no signature can be
    // pulled out of them at all — by my splitter or by gpg — so the analyzed set is smaller than
    // the set that "looks signed", and the difference is stated rather than absorbed.
    carry_the_wrapper: S.signed_strict + S.signed_with_preamble,
    no_extractable_signature: S.signed_strict + S.signed_with_preamble - V.length,
    analyzed: V.length,
    strict: S.signed_strict,
    with_preamble: S.signed_with_preamble,
    pasted_key_block_not_a_signature: S.key_block_but_unsigned,
    armor_fragments_without_a_wrapper: S.signature_without_header,
    header_without_signature: S.header_without_signature,
  },
  // Malformed armor: unverifiable by anyone, with any key.
  wrapper_gpg_unparseable: wrapperUnparseable,
  wrapper_gpg_parseable: wrapperParseable,

  // B. does the signature bind a location
  canonical: {
    present: rate(A.with_canonical, A.signed_total),
    absent: A.signed_total - A.with_canonical,
    absent_among_verifying: cnt((v) => !v.has_canonical, verifies),
  },

  // C/D/E. can a researcher check it from what the file publishes
  verifiable: rate(verifies.length, A.signed_total),
  verify_breakdown: {
    good: A.verified_good,
    good_but_key_expired: A.verified_good_key_expired,
    bad_signature: A.bad_signature,
    issuer_key_not_the_published_key: A.key_fetched_but_different_key,
    other_gpg_error: V.length - (A.verified_good + A.verified_good_key_expired + A.bad_signature
      + A.key_fetched_but_different_key + A.key_fetch_failed + A.publishes_no_key
      + A.publishes_unfetchable_key_form),
    published_key_url_did_not_fetch: A.key_fetch_failed,
    no_key_published_at_all: A.publishes_no_key,
    key_published_in_an_unfetchable_form: A.publishes_unfetchable_key_form,
  },
  issuer_coincides_with_published_key: rate(A.issuer_in_published_key, A.signed_total),

  // The circularity: a key served from the same origin as the file is guarded by the same TLS and
  // the same server. An attacker who can replace one can replace the other.
  same_origin_key: {
    among_verifying: rate(cnt((v) => v.key_same_origin === true, verifies), verifies.length),
    cross_origin_among_verifying: cnt((v) => v.key_same_origin === false, verifies),
    among_all_signed: A.key_same_origin,
  },

  // A bad signature is a claim about the site, so the alternative explanation is tested.
  bad_signatures: {
    total: A.bad_signature,
    rescued_by_any_transport_variant: rescued,
    rescued_by: rescuedBy,
    untestable_no_key: untestable,
    variants_tried: Object.keys(VARIANTS),
    with_expires: cnt((v) => !!(corpus.get(v.domain) || {}).expires, badSigs),
    expires_over_13_months_after_signature: badSigs.filter((v) => {
      const e = (corpus.get(v.domain) || {}).expires;
      if (!e || !v.sig_created) return false;
      const te = Date.parse(e), ts = Date.parse(v.sig_created);
      return te && ts && te > ts + 400 * 86400000;
    }).length,
  },

  // Where the key is published, as a property of the file rather than of whichever URL the
  // analyzer happened to verify against. A file naming several Encryption URLs would otherwise
  // need a tie-break here that does not match the one used there, and a breakdown that disagrees
  // with its own totals is worse than no breakdown.
  key_origin: keyOrigin(),

  key_health: {
    expired: A.key_expired,
    revoked: A.key_revoked,
    // Totals rather than a sum the article has to do in prose: a number computed while drafting is
    // a number nothing checks.
    key_urls_fetched: keys.size,
    served_a_key: keyShape.armored_openpgp_key + keyShape.binary_openpgp_key,
    served_something_that_is_not_a_key: keyShape.html_page + keyShape.x509_certificate
      + keyShape.pkcs12_bag + keyShape.other_crypto_tool + keyShape.empty + keyShape.other,
    fetch_outcomes: keyFetch,
    what_the_url_served: keyShape,
    encryption_field_forms: A.encryption_kind,
  },

  signature_age_days: A.sig_age_days,

  // F. joins with the reachability survey
  expiry_state: { signed: expirySortedCopy(expirySigned), all_security_txt: expirySortedCopy(expiryAll) },
  signed_rate_by_expiry_state: Object.fromEntries(
    Object.keys(expiryAll).map((k) => [k, rate(expirySigned[k] || 0, expiryAll[k])])),
};

// A signature is only worth more than TLS if the key comes from somewhere the site's web server
// does not control. "Published on a public keyserver" is a property of the file — it holds or does
// not regardless of which URL was verified against — so it needs no tie-break.
function keyOrigin() {
  const at = (v) => {
    const b = bodies.get(v.domain);
    if (!b) return { keyserver: false, offsite: false };
    const parts = lib.splitSigned(b.body || '');
    if (!parts) return { keyserver: false, offsite: false };
    const site = v.domain.replace(/^www\./, '');
    const hosts = (lib.fieldsOf(parts.content).encryption || [])
      .filter((u) => /^https?:/i.test(u)).map(lib.hostOf).filter(Boolean);
    return {
      keyserver: hosts.some((h) => KEYSERVERS.some((r) => r.test(h))),
      offsite: hosts.some((h) => h !== site && !h.endsWith('.' + site) && !site.endsWith('.' + h)),
    };
  };
  const tally = (arr) => {
    let keyserver = 0, offsite = 0;
    for (const v of arr) { const r = at(v); if (r.keyserver) keyserver++; if (r.offsite) offsite++; }
    return { n: arr.length, publishes_key_on_a_public_keyserver: keyserver,
      publishes_key_on_some_off_site_host: offsite };
  };
  return {
    signed: tally(V),
    verifying: tally(verifies),
    // The analyzer's own same-origin flag, for the key it actually used.
    key_used_was_same_origin_among_verifying: cnt((v) => v.key_same_origin === true, verifies),
  };
}

function expirySortedCopy(o) {
  return Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));
}

fs.writeFileSync(outPath, JSON.stringify(report, null, 1));
console.log(JSON.stringify(report, null, 1));
