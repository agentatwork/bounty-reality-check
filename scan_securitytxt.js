#!/usr/bin/env node
/**
 * scan_securitytxt.js — fetch and parse RFC 9116 security.txt across a domain list.
 *
 *   node scan_securitytxt.js <domainlist> <out.jsonl> [concurrency] [limit]
 *
 * Companion to contactcheck.js. That one asks whether a GitHub project's SECURITY.md
 * names a reachable contact; this asks the same question of the IETF standard that real
 * companies actually publish, at their apex domain.
 *
 * Existing measurement work on security.txt (Digital Threats 2023, MADWeb 2022, URIports
 * 2024/25) counts ADOPTION and SYNTACTIC CONFORMITY — is Expires present, does the Contact
 * match an email regex. None of it resolves the contact. "63.5% of emails valid" means the
 * string looked like an address, not that anything would receive mail sent to it. The
 * interesting question is downstream of the regex: does the domain exist, and if not, can
 * a stranger register it and collect the reports?
 *
 * SOFT-404 IS THE TRAP. A large share of hosts answer 200 with an HTML page for any path,
 * so status code alone massively over-counts adoption. A file counts only if the body
 * parses as security.txt: a `Contact:` field, per RFC 9116 §2.5.3 (which makes Contact
 * mandatory), and no HTML doctype.
 *
 * Read-only: one GET per domain of a file whose entire purpose is to be read by exactly
 * this kind of tool. Nothing is registered, ever.
 */
'use strict';
const fs = require('fs');

const [, , listPath, outPath, concArg, limitArg] = process.argv;
if (!listPath || !outPath) {
  console.error('usage: node scan_securitytxt.js <domainlist> <out.jsonl> [concurrency] [limit]');
  process.exit(1);
}
const CONC = parseInt(concArg || '40', 10);
const LIMIT = parseInt(limitArg || '0', 10);
const TIMEOUT_MS = 8000;

/** RFC 9116 §4: fields are `name: value`, case-insensitive, one per line, `#` comments. */
function parseSecurityTxt(body) {
  const out = { contact: [], expires: null, policy: [], canonical: [], fields: {} };
  for (const line of body.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const m = s.match(/^([A-Za-z-]+)\s*:\s*(.+)$/);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    out.fields[k] = (out.fields[k] || 0) + 1;
    if (k === 'contact') out.contact.push(v);
    else if (k === 'expires' && !out.expires) out.expires = v;
    else if (k === 'policy') out.policy.push(v);
    else if (k === 'canonical') out.canonical.push(v);
  }
  return out;
}

/**
 * Is this actually a security.txt, or a soft-404 / SPA shell? Requiring a Contact field is
 * both the cheapest and the most correct test, because RFC 9116 makes Contact mandatory —
 * a file without one is not a conforming security.txt by definition.
 */
function looksReal(body, parsed) {
  if (!parsed.contact.length) return false;
  if (/<!doctype html|<html[\s>]/i.test(body.slice(0, 2000))) return false;
  return true;
}

async function fetchOne(domain) {
  const url = `https://${domain}/.well-known/security.txt`;
  try {
    const r = await fetch(url, {
      headers: { 'user-agent': 'securitytxt-survey (+https://agentatwork.xyz) contact: security@agentatwork.xyz' },
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!r.ok) return { domain, ok: false, status: r.status };
    const ct = (r.headers.get('content-type') || '').split(';')[0];
    // Cap the read: a soft-404 can be a multi-megabyte SPA, and we only need the head of it.
    const body = (await r.text()).slice(0, 32768);
    const parsed = parseSecurityTxt(body);
    const real = looksReal(body, parsed);
    return {
      domain, ok: true, status: r.status, content_type: ct, final_url: r.url,
      is_security_txt: real,
      contact: real ? parsed.contact : [],
      expires: real ? parsed.expires : null,
      policy: real ? parsed.policy : [],
      canonical: real ? parsed.canonical : [],
      field_names: real ? Object.keys(parsed.fields) : [],
      bytes: body.length,
    };
  } catch (e) {
    return { domain, ok: false, err: (e.name === 'TimeoutError' ? 'timeout' : (e.cause?.code || e.name || 'err')) };
  }
}

async function main() {
  let domains = fs.readFileSync(listPath, 'utf8').split('\n')
    .map(l => l.trim()).filter(Boolean)
    .map(l => l.includes(',') ? l.split(',')[1] : l)
    .filter(Boolean);
  if (LIMIT) domains = domains.slice(0, LIMIT);

  // Resume. A run over six figures of domains WILL be interrupted -- this box has one core and
  // no swap, and an unrelated job scheduled next to the scanner is enough to end it. The output
  // is append-mode JSONL, so anything already recorded is still good: skip those and continue.
  // Rebuilding from zero after 15k results is a self-inflicted hour.
  let skipped = 0;
  try {
    const seen = new Set();
    for (const line of fs.readFileSync(outPath, 'utf8').split('\n')) {
      if (!line) continue;
      const i = line.indexOf('"domain":"');
      if (i < 0) continue;
      const j = line.indexOf('"', i + 10);
      if (j > 0) seen.add(line.slice(i + 10, j));
    }
    if (seen.size) {
      const before = domains.length;
      domains = domains.filter(d => !seen.has(d));
      skipped = before - domains.length;
      console.log(`resume: ${seen.size} already scanned, ${skipped} skipped, ${domains.length} remaining`);
    }
  } catch { /* no prior output — fresh run */ }

  const out = fs.createWriteStream(outPath, { flags: 'a' });
  let i = 0, found = 0, done = 0;
  const t0 = Date.now();

  async function worker() {
    while (i < domains.length) {
      const d = domains[i++];
      const r = await fetchOne(d);
      if (r.is_security_txt) found++;
      out.write(JSON.stringify(r) + '\n');
      if (++done % 1000 === 0) {
        const rate = done / ((Date.now() - t0) / 1000);
        console.log(`${done}/${domains.length}  found=${found}  ${rate.toFixed(1)}/s  eta=${((domains.length - done) / rate / 60).toFixed(0)}m  rss=${(process.memoryUsage().rss / 1048576).toFixed(0)}MB`);
      }
    }
  }
  await Promise.all(Array.from({ length: CONC }, worker));
  out.end();
  console.log(`SCAN_DONE scanned=${done} security_txt=${found}`);
}

main();
