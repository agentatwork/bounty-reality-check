#!/usr/bin/env node
'use strict';
// Does a signed security.txt give a researcher anything they can actually check?
//
// RFC 9116 §2.3 RECOMMENDs an OpenPGP cleartext signature; §5.1 tells researchers to verify it.
// §2.5.4 tells them not to assume the Encryption key is the signing key. Those three sentences
// together describe a researcher who has been told to verify something and told that the only key
// in front of them might be the wrong one. This measures what that researcher can do.
//
// The measurement is deliberately of *coincidence*, not identity: an OpenPGP signature packet
// carries its issuer key ID, so I can ask whether the issuer happens to be a key the file itself
// publishes, without ever assuming it should be.
//
//   node analyze_signed.js <bodies.jsonl> <corpus.jsonl> <out.json>
//
// Key fetches are cached in <bodies.jsonl>.keys.jsonl so a re-run costs no network.

const fs = require('fs');
const https = require('https');
const http = require('http');
const lib = require('./signedlib');

const KEY_TIMEOUT = 20000;
const KEY_MAX = 1 << 20;   // 1 MiB: a keyring dump can be big, an HTML error page is bigger

function fetchKey(url, redirects = 0) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ err: 'BADURL' }); }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return resolve({ err: 'NOTHTTP' });
    const mod = u.protocol === 'http:' ? http : https;
    const req = mod.request(u, {
      method: 'GET',
      headers: {
        'user-agent': 'agentatwork-securitytxt-survey/1.0 (+https://agentatwork.xyz/notes/security-txt.html)',
        'accept': 'application/pgp-keys,text/plain,*/*',
      },
      timeout: KEY_TIMEOUT,
    }, (res) => {
      const loc = res.headers.location;
      if (res.statusCode >= 300 && res.statusCode < 400 && loc && redirects < 5) {
        res.resume();
        let next;
        try { next = new URL(loc, u).toString(); } catch { return resolve({ err: 'BADREDIR' }); }
        return resolve(fetchKey(next, redirects + 1));
      }
      const chunks = [];
      let n = 0;
      res.on('data', (c) => { n += c.length; if (n <= KEY_MAX) chunks.push(c); else res.destroy(); });
      res.on('end', () => resolve({
        status: res.statusCode,
        final_url: u.toString(),
        content_type: res.headers['content-type'] || null,
        body: Buffer.concat(chunks).toString('latin1'),
      }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ err: 'TIMEOUT' }); });
    req.on('error', (e) => resolve({ err: e.code || String(e.message).slice(0, 60) }));
    req.end();
  });
}

async function main() {
  const [bodiesPath, corpusPath, outPath] = process.argv.slice(2);
  if (!bodiesPath || !corpusPath || !outPath) {
    console.error('usage: node analyze_signed.js <bodies.jsonl> <corpus.jsonl> <out.json>');
    process.exit(1);
  }

  // Rank comes from the corpus file's line order (it is a popularity-ranked domain list), so a
  // signed rate can be reported by rank band rather than as one average over wildly different
  // kinds of operator.
  const rank = new Map();
  const corpusMeta = new Map();
  {
    let i = 0;
    for (const line of fs.readFileSync(corpusPath, 'utf8').split('\n')) {
      if (!line) continue;
      i++;
      let d;
      try { d = JSON.parse(line); } catch { continue; }
      rank.set(d.domain, i);
      if (d.is_security_txt) corpusMeta.set(d.domain, { expires: d.expires, contact: (d.contact || []).length });
    }
  }

  const recs = [];
  for (const line of fs.readFileSync(bodiesPath, 'utf8').split('\n')) {
    if (!line) continue;
    try { recs.push(JSON.parse(line)); } catch { /* half-written line */ }
  }

  const stats = {
    generated_at: new Date().toISOString(),
    corpus_records: rank.size,
    security_txt_in_corpus: corpusMeta.size,
    refetched: recs.length,
    refetch_failed: 0,
    refetch_not_200: 0,
    analyzable: 0,
    signed_strict: 0,
    signed_with_preamble: 0,
    header_without_signature: 0,
    signature_without_header: 0,
    key_block_but_unsigned: 0,
    unsigned: 0,
  };

  const signed = [];
  for (const r of recs) {
    if (r.err) { stats.refetch_failed++; continue; }
    if (r.status !== 200) { stats.refetch_not_200++; continue; }
    stats.analyzable++;
    const st = lib.signedState(r.body || '');
    if (!st.signed) {
      if (st.why === 'key_block_only') stats.key_block_but_unsigned++;
      else if (st.why === 'header_without_signature') stats.header_without_signature++;
      else if (st.why === 'signature_without_header') stats.signature_without_header++;
      else stats.unsigned++;
      continue;
    }
    if (st.strict) stats.signed_strict++; else stats.signed_with_preamble++;
    const parts = lib.splitSigned(r.body);
    if (!parts) { stats.signature_without_header++; continue; }
    const issuer = lib.signatureIssuer(parts.signature);
    const fields = lib.fieldsOf(parts.content);
    const outside = lib.fieldsOf(r.body.slice(r.body.indexOf(lib.SIG_TAIL) + lib.SIG_TAIL.length));
    signed.push({
      domain: r.domain,
      rank: rank.get(r.domain) || null,
      strict: st.strict,
      issuer,
      fields,
      // Fields sitting after the armor tail are inside the file but outside the signature.
      fields_outside_signature: Object.keys(outside),
      encryption: (fields.encryption || []).map((v) => ({ kind: lib.encryptionKind(v), value: v })),
      canonical: fields.canonical || [],
      expires: (fields.expires || [])[0] || null,
      body: r.body,
      file_host: lib.hostOf(r.url),
    });
  }

  console.error(`signed: ${signed.length} of ${stats.analyzable} analyzable`);

  // ---- key fetching, cached ----
  const keyCachePath = bodiesPath + '.keys.jsonl';
  const keyCache = new Map();
  if (fs.existsSync(keyCachePath)) {
    for (const line of fs.readFileSync(keyCachePath, 'utf8').split('\n')) {
      if (!line) continue;
      try { const d = JSON.parse(line); keyCache.set(d.url, d.res); } catch { /* skip */ }
    }
  }
  const keyOut = fs.createWriteStream(keyCachePath, { flags: 'a' });

  const wanted = [];
  for (const s of signed) {
    for (const e of s.encryption) {
      if (e.kind === 'https' || e.kind === 'http_violates_2_5_6') {
        if (!keyCache.has(e.value) && !wanted.includes(e.value)) wanted.push(e.value);
      }
    }
  }
  console.error(`key URLs to fetch: ${wanted.length} (${keyCache.size} cached)`);
  {
    let i = 0;
    const worker = async () => {
      while (i < wanted.length) {
        const url = wanted[i++];
        const res = await fetchKey(url);
        keyCache.set(url, res);
        keyOut.write(JSON.stringify({ url, res }) + '\n');
      }
    };
    await Promise.all(Array.from({ length: 6 }, worker));
  }
  keyOut.end();

  // ---- per-file verdicts ----
  const verdicts = [];
  for (const s of signed) {
    const v = {
      domain: s.domain,
      rank: s.rank,
      strict: s.strict,
      sig_created: s.issuer.created,
      sig_age_days: s.issuer.created_epoch
        ? Math.floor((Date.parse(stats.generated_at) / 1000 - s.issuer.created_epoch) / 86400) : null,
      issuer_keyid: s.issuer.keyid,
      has_canonical: s.canonical.length > 0,
      encryption_kinds: s.encryption.map((e) => e.kind),
      key_same_origin: null,
      key_fetch: null,
      key_expired: null,
      key_revoked: null,
      issuer_in_published_key: null,
      verify: null,
    };

    const fetchable = s.encryption.filter((e) => e.kind === 'https' || e.kind === 'http_violates_2_5_6');
    if (!fetchable.length) {
      v.verify = s.encryption.length ? 'no_fetchable_key_published' : 'no_key_published';
      verdicts.push(v);
      continue;
    }

    let best = null;
    for (const e of fetchable) {
      const res = keyCache.get(e.value);
      const cand = { url: e.value, same_origin: lib.hostOf(e.value) === s.file_host };
      if (!res || res.err) { cand.fetch = res ? res.err : 'NOTFETCHED'; }
      else if (res.status !== 200) { cand.fetch = 'HTTP_' + res.status; }
      else {
        cand.fetch = 'ok';
        const k = lib.inspectKey(res.body);
        if (!k.ok) { cand.fetch = 'not_a_key'; }
        else {
          cand.expired = k.expired; cand.revoked = k.revoked;
          cand.match = s.issuer.keyid ? k.keyids.some((id) => id.endsWith(s.issuer.keyid)
            || s.issuer.keyid.endsWith(id)) : false;
          if (cand.match) cand.verify = lib.verifyWith(res.body, s.body);
        }
      }
      // Prefer the candidate that actually gets furthest: verified > matched > fetched > failed.
      const score = (c) => (c.verify && c.verify.verified ? 4 : c.match ? 3 : c.fetch === 'ok' ? 2 : 1);
      if (!best || score(cand) > score(best)) best = cand;
    }

    v.key_same_origin = best.same_origin;
    v.key_fetch = best.fetch;
    v.key_expired = best.expired ?? null;
    v.key_revoked = best.revoked ?? null;
    v.issuer_in_published_key = best.match ?? null;
    v.verify = best.verify ? (best.verify.verified ? best.verify.reason : best.verify.reason)
      : (best.fetch === 'ok' ? 'key_fetched_but_different_key' : 'key_unfetchable');
    verdicts.push(v);
  }

  // ---- aggregates ----
  const n = verdicts.length;
  const count = (f) => verdicts.filter(f).length;
  const agg = {
    signed_total: n,
    strict: count((v) => v.strict),
    with_canonical: count((v) => v.has_canonical),
    publishes_no_key: count((v) => v.verify === 'no_key_published'),
    publishes_unfetchable_key_form: count((v) => v.verify === 'no_fetchable_key_published'),
    key_fetch_failed: count((v) => v.verify === 'key_unfetchable'),
    key_fetched_but_different_key: count((v) => v.verify === 'key_fetched_but_different_key'),
    issuer_in_published_key: count((v) => v.issuer_in_published_key === true),
    verified_good: count((v) => v.verify === 'good'),
    verified_good_key_expired: count((v) => v.verify === 'good_but_key_expired'),
    bad_signature: count((v) => v.verify === 'bad_signature'),
    key_same_origin: count((v) => v.key_same_origin === true),
    key_cross_origin: count((v) => v.key_same_origin === false),
    key_expired: count((v) => v.key_expired === true),
    key_revoked: count((v) => v.key_revoked === true),
    encryption_kind: {},
    sig_age_days: {},
  };
  for (const v of verdicts) for (const k of v.encryption_kinds) agg.encryption_kind[k] = (agg.encryption_kind[k] || 0) + 1;
  const ages = verdicts.map((v) => v.sig_age_days).filter((x) => x !== null).sort((a, b) => a - b);
  if (ages.length) {
    agg.sig_age_days = {
      n: ages.length,
      median: ages[Math.floor(ages.length / 2)],
      p90: ages[Math.floor(ages.length * 0.9)],
      max: ages[ages.length - 1],
      over_1_year: ages.filter((a) => a > 365).length,
      over_2_years: ages.filter((a) => a > 730).length,
    };
  }

  // Signed rate by popularity band: one average over the whole list would hide that the practice
  // is concentrated at the top.
  const bands = [[1, 1000], [1001, 10000], [10001, 100000], [100001, 1e9]];
  agg.by_rank_band = bands.map(([lo, hi]) => {
    const inBand = (d) => { const r = rank.get(d); return r >= lo && r <= hi; };
    const analyzable = recs.filter((r) => !r.err && r.status === 200 && inBand(r.domain)).length;
    const s = verdicts.filter((v) => v.rank >= lo && v.rank <= hi).length;
    return { band: `${lo}-${hi === 1e9 ? 'end' : hi}`, analyzable, signed: s,
      pct: analyzable ? Number((100 * s / analyzable).toFixed(2)) : null };
  });

  const result = { stats, aggregate: agg, verdicts };
  fs.writeFileSync(outPath, JSON.stringify(result, null, 1));
  console.error(JSON.stringify(agg, null, 1));
}

main();
