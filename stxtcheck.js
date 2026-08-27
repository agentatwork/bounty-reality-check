#!/usr/bin/env node
/**
 * stxtcheck.js — is your security.txt actually a working way to reach you?
 *
 *   node stxtcheck.js example.com
 *   node stxtcheck.js example.com --json
 *
 * Existing validators check that the file PARSES. This checks that it WORKS: that the domain
 * in every Contact still exists, that mail can be delivered to it, that the portal answers,
 * and — the part nothing else checks — that no contact domain has lapsed into a state where a
 * stranger could register it and receive your vulnerability reports instead of you.
 *
 * Exit codes:
 *   0  all contacts reachable
 *   1  no security.txt, or it does not parse
 *   2  a contact domain is UNREGISTERED — anyone can claim it and collect your reports
 *   3  a contact is broken but not claimable (dead subdomain, null MX, portal gone), or
 *      nothing verifiable answered at all
 *   4  file is valid but expired, or Expires is missing (RFC 9116 requires it)
 *
 * Read-only. Nothing is registered, and no report address is written to.
 */
'use strict';
const {
  parseContact, expiryState, domainFacts, emailVerdict, urlVerdict, probePortal, fetchSecurityTxt,
  triage,
} = require('./stxtlib');
const { publicSuffixOf } = require('./psl');

const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
const domain = args.find(a => !a.startsWith('-'));
if (!domain) {
  console.error('usage: node stxtcheck.js <domain> [--json]');
  process.exit(1);
}

const ICON = {
  'LIVE-MX': '✅', 'RESOLVES': '✅', 'IMPLICIT-A': '⚠️ ', 'NULL-MX': '⛔',
  'NO-MAIL': '⛔', 'NO-ADDRESS': '⛔', 'DEAD-SUBDOMAIN': '🚫', 'INVALID-TLD': '🚫',
  'UNREGISTERED': '🔴',
};
const EXPLAIN = {
  'LIVE-MX': 'mail server accepts reports',
  'RESOLVES': 'host resolves',
  'IMPLICIT-A': 'no MX, A record only — deliverable via RFC 5321 implicit MX, but fragile',
  'NULL-MX': 'RFC 7505 null MX — this domain declares it accepts no mail',
  'NO-MAIL': 'domain exists but has no MX and no A record — mail cannot be delivered',
  'NO-ADDRESS': 'domain exists but has no A record — nothing to connect to',
  'DEAD-SUBDOMAIN': 'does not exist, but only the parent zone owner could create it — bounces, NOT claimable',
  'INVALID-TLD': 'not a delegated TLD — a typo. Unreachable, but nobody can register it either',
  'UNREGISTERED': 'DOES NOT EXIST AND ANYONE CAN REGISTER IT',
};

async function main() {
  const NOW = Date.now();
  const res = await fetchSecurityTxt(domain);
  const out = { domain, checked: new Date(NOW).toISOString() };

  if (!res.ok) {
    out.result = 'NO-FILE';
    out.detail = res.err ? `fetch failed: ${res.err}` : `HTTP ${res.status}`;
    if (JSON_OUT) console.log(JSON.stringify(out, null, 1));
    else {
      console.log(`\n  ${domain}`);
      console.log(`  ⛔ no security.txt at /.well-known/security.txt (${out.detail})\n`);
      console.log('  RFC 9116 says the file MUST live at that path. Without it, a researcher');
      console.log('  who wants to report a bug has to guess how to reach you.\n');
    }
    process.exit(1);
  }
  if (!res.real) {
    out.result = 'NOT-A-SECURITY-TXT';
    out.detail = res.parsed.contact.length
      ? 'response looks like HTML, not text/plain — probably a soft 404'
      : 'no Contact field — RFC 9116 2.5.3 makes it mandatory';
    if (JSON_OUT) console.log(JSON.stringify(out, null, 1));
    else console.log(`\n  ${domain}\n  ⛔ ${out.detail}\n`);
    process.exit(1);
  }

  const p = res.parsed;
  const contacts = p.contact.map(parseContact);
  const siteReg = publicSuffixOf(domain).registrable;

  const rows = [];
  for (const c of contacts) {
    if (!c.domain) { rows.push({ ...c, verdict: c.kind === 'tel' ? 'TEL' : 'MALFORMED' }); continue; }
    const f = await domainFacts(c.domain);
    const verdict = c.kind === 'url' ? urlVerdict(f) : emailVerdict(f);
    const row = {
      kind: c.kind, value: c.addr || c.url, contact_domain: c.domain, verdict,
      third_party: publicSuffixOf(c.domain).registrable !== siteReg,
      // MX records explain an email verdict and mean nothing for a portal — don't print them there.
      detail: f.detail || (c.kind === 'email' && f.mx && f.mx.length ? f.mx.join(', ') : undefined),
    };
    if (c.kind === 'url' && f.state === 'EXISTS') {
      const pr = await probePortal(c.url);
      row.portal = pr;
    }
    rows.push(row);
  }

  const exp = expiryState(p.expires, NOW);
  out.expires = p.expires || null;
  out.expiry = exp;
  out.contacts = rows;

  // Canonical: RFC 9116 2.5.2 — if the retrieval URI is not listed, do not trust the file.
  if (p.canonical.length) {
    const fetched = res.final_url || res.url;
    let fh = null; try { fh = new URL(fetched).hostname.toLowerCase().replace(/^www\./, ''); } catch {}
    const hosts = p.canonical.map(c => { try { return new URL(c).hostname.toLowerCase().replace(/^www\./, ''); } catch { return null; } });
    out.canonical = p.canonical.some(c => c.trim() === fetched) ? 'exact_match'
      : (fh && hosts.includes(fh)) ? 'host_match_path_differs' : 'MISMATCH';
  } else out.canonical = 'absent';

  // Verdict, result string and exit code all come from stxtlib.triage — see the contract note
  // there. Kept in the library rather than here so exit_codes_test.js can drive all five outcomes
  // from row fixtures instead of needing a real domain in each state.
  const verdict = triage(rows, exp);
  const { hijack, broken, working } = verdict;

  out.hijackable = hijack.length;
  out.broken = broken.length;
  out.working = working.length;
  out.result = verdict.result;

  if (JSON_OUT) { console.log(JSON.stringify(out, null, 1)); }
  else {
    console.log(`\n  ${domain} — security.txt found\n`);
    for (const r of rows) {
      if (!r.contact_domain) { console.log(`  ${r.kind === 'tel' ? '📞' : '❓'} ${r.kind}: ${r.value || r.raw || ''}`); continue; }
      const ic = ICON[r.verdict] || '  ';
      const tp = r.third_party ? '  [third-party domain]' : '';
      console.log(`  ${ic} ${r.kind.padEnd(5)} ${r.value}${tp}`);
      console.log(`        ${r.verdict} — ${EXPLAIN[r.verdict] || ''}`);
      if (r.detail && r.verdict !== 'UNREGISTERED') console.log(`        ${r.detail}`);
      if (r.portal) {
        const pw = { ok: 'portal responds', alive_gated: 'server alive but refused this client (bot wall) — a browser is likely fine',
          page_gone: 'PORTAL PAGE IS GONE (404)', server_error: 'server error', timeout: 'timed out' }[r.portal.why] || r.portal.why;
        console.log(`        portal: ${pw}${r.portal.status ? ` [HTTP ${r.portal.status}]` : ''}`);
      }
    }
    const expTxt = { valid: `valid until ${p.expires}`, expired: `EXPIRED ${p.expires}`,
      missing: 'MISSING — RFC 9116 2.5.5 requires it', unparseable: `unparseable (${p.expires})` }[exp];
    console.log(`\n  Expires: ${expTxt}`);
    if (out.canonical === 'MISMATCH') {
      console.log('  Canonical: MISMATCH — the file does not list the URI it was fetched from.');
      console.log('             RFC 9116 2.5.2 says its contents SHOULD NOT be trusted.');
    }
    console.log(`\n  → ${out.result}`);
    if (hijack.length) {
      console.log('\n  One or more contact domains do not exist and are registerable by anyone.');
      console.log('  This is not a bounce. Whoever registers the domain receives your inbound');
      console.log('  vulnerability reports, silently, with no error visible to the reporter.');
      console.log('  Register the domain yourself, or change the contact — today.');
    }
    console.log('');
  }

  process.exit(verdict.exit);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
