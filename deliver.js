#!/usr/bin/env node
'use strict';
/*
 * deliver.js — the THIRD leg of a bounty reality check.
 *
 *   reality.js  → "is there money on-chain to steal?"      (a real bug steals nothing from an empty pool)
 *   dupecheck.js→ "has this bug already been found?"        (don't re-report a known finding)
 *   deliver.js  → "if I find a real bug, will they ACTUALLY pay me, and can I even reach them?"
 *
 * This is the gate that decides whether an audit converts to cash BEFORE you spend
 * the hours. It was learned the expensive way across ~a dozen real disclosures: a
 * confirmed Critical is worth $0 when the reward is discretionary, or deferred to a
 * mainnet that doesn't exist yet, or gated behind KYC you can't pass, or when the
 * only submission channel is an email address a low-reputation sender can't deliver to.
 *
 * For a GitHub repo running a bug bounty it reads, READ-ONLY:
 *   - private vulnerability reporting (PVR) status  — can you submit privately at all?
 *   - the bounty doc (SECURITY.md / bug-bounty.md / …) — reward language + timing + KYC + channel
 * and prints one verdict:
 *
 *   DELIVERABLE   PVR-on (or non-email private channel), committed reward, mainnet-live, no KYC.
 *                 The golden — and rare — case. A real Critical here converts to cash.
 *   CREDIT-ONLY   Committed reward but mainnet-DEFERRED ("honoured at launch"). Real, no cash now.
 *   KYC-GATED     Committed + live but payout needs identity / Immunefi / tax forms.
 *   DISCRETIONARY Reward is "best-effort" / "case-by-case" / governance-vote / community-funded.
 *                 Deliver only if the audit is cheap; expect $0.
 *   UNREACHABLE   No private channel: PVR-off AND email-only. You can't submit responsibly
 *                 from here at all (and email may be reputation-walled anyway).
 *   NO-BOUNTY     No bounty doc found.
 *
 * Usage:
 *   node deliver.js <owner/repo> [<owner/repo> ...]
 *   GH_TOKEN=ghp_... node deliver.js WritzProtocol/writz 1Hive/gardens-v2
 *   (token optional: raises rate limits. Falls back to ~/work/gh_token, then unauthenticated.)
 *
 * Exit code = worst (lowest-cash) verdict seen: 0 DELIVERABLE, 3 CREDIT-ONLY,
 * 4 KYC-GATED, 5 DISCRETIONARY, 6 UNREACHABLE, 7 NO-BOUNTY, 1 error.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

function token() {
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN.trim();
  for (const p of [path.join(os.homedir(), 'work/gh_token'), path.join(os.homedir(), '.gh_token')]) {
    try { return fs.readFileSync(p, 'utf8').trim(); } catch { /* ignore */ }
  }
  return null;
}

// Every fetch is time-boxed: a batch tool must never hang the whole run on one slow
// host (a raw.githubusercontent connection stalled a 90-repo scan at repo 23).
const TIMEOUT_MS = 12000;

async function gh(url, tok) {
  const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'deliver-check' };
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  try {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!r.ok) return { _status: r.status, _body: await r.text().catch(() => '') };
    return r.json();
  } catch (e) { return { _status: 0, _body: String(e && e.message || e) }; }
}

async function raw(owner, repo, branch, file) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file}`;
  try {
    const r = await fetch(url, { headers: { 'User-Agent': 'deliver-check' }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!r.ok) return null;
    return r.text();
  } catch { return null; }
}

// Default branch, so we read the live doc rather than guessing main/master.
async function defaultBranch(owner, repo, tok) {
  const j = await gh(`https://api.github.com/repos/${owner}/${repo}`, tok);
  return (j && j.default_branch) || 'main';
}

// PVR: GET .../private-vulnerability-reporting → { enabled: bool }. The private
// submission channel this whole box relies on (email is reputation-walled here).
async function pvrEnabled(owner, repo, tok) {
  const j = await gh(`https://api.github.com/repos/${owner}/${repo}/private-vulnerability-reporting`, tok);
  if (j && typeof j.enabled === 'boolean') return j.enabled;
  return null; // unknown (e.g. 403/404)
}

const DOC_PATHS = [
  'SECURITY.md', '.github/SECURITY.md', 'security.md', 'Security.md',
  'bug-bounty.md', 'BUG-BOUNTY.md', 'BugBounty.md',
  'docs/security/bug-bounty.md', 'docs/bug-bounty.md', 'docs/SECURITY.md',
  'docs/security/security.md', 'security/bug-bounty.md',
];

async function bountyDoc(owner, repo, branch, tok) {
  // Aggregate EVERY bounty doc found, not the first — a SECURITY.md is often just a
  // pointer to docs/security/bug-bounty.md where the real reward table lives (the
  // writz lesson: stopping at SECURITY.md missed the committed table entirely).
  const found = [];
  for (const f of DOC_PATHS) {
    const t = await raw(owner, repo, branch, f);
    if (t && t.trim()) found.push({ path: f, text: t });
    if (found.length >= 4) break; // enough; cap fetches
  }
  if (!found.length) {
    const j = await gh(`https://api.github.com/repos/${owner}/${repo}/contents/SECURITY.md`, tok);
    if (j && j.content) {
      try { found.push({ path: 'SECURITY.md', text: Buffer.from(j.content, 'base64').toString('utf8') }); }
      catch { /* ignore */ }
    }
  }
  if (!found.length) return null;
  return { path: found.map(d => d.path).join(' + '), text: found.map(d => d.text).join('\n\n') };
}

// --- classifiers over the bounty text -------------------------------------------------
// Each returns { hit: bool, evidence: [matched snippet, ...] } so the verdict shows its work.

function scan(text, patterns) {
  const ev = [];
  const low = text.toLowerCase();
  for (const p of patterns) {
    const re = p instanceof RegExp ? p : new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    const m = low.match(re);
    if (m) {
      // Pull the original-case line around the match for readable evidence.
      const idx = low.indexOf(m[0]);
      const start = Math.max(0, text.lastIndexOf('\n', idx) + 1);
      let end = text.indexOf('\n', idx); if (end < 0) end = text.length;
      ev.push(text.slice(start, end).trim().slice(0, 140));
    }
  }
  return { hit: ev.length > 0, evidence: [...new Set(ev)].slice(0, 3) };
}

function classify(doc) {
  const t = doc.text;

  // STRONG discretionary = the payout MECHANISM itself is soft (a vote, a community
  // pool, explicit discretion). This dominates a nominal reward table — the table is
  // aspirational when the mechanism is a governance proposal. (gardens-v2 lesson.)
  const strongDiscretionary = scan(t, [
    /governance (proposal|vote)/, /community[ -]funded/, /best[ -]effort/,
    /at (our|its|the maintainers?['’]?)? ?(sole )?discretion/, /discretionary/,
    /no guarantee/, /not obligated/, /reserve the right/, /funded by (the )?(community|dao|treasury)/,
    /rewards? (are|will be) (determined|decided) by/,
    // Pool-share payouts ("X% of pool funds") are governance-mediated, not a fixed
    // wallet-payable bounty — the reward size and release both depend on a vote.
    /\d+\s*%\s*of (the )?(pool|treasury|hack)/, /% of pool funds/, /percentage of (the )?pool/,
  ]);
  // WEAK discretionary = a caveat that committed programs also use ("case-by-case").
  // Not enough on its own to override a concrete table.
  const weakDiscretionary = scan(t, [
    /case[ -]by[ -]case/, /may (choose to )?(reward|pay)/, /subject to.*discretion/,
    /assessed on a case/, /evaluated on a case/,
  ]);
  const discretionary = { hit: strongDiscretionary.hit || weakDiscretionary.hit,
    evidence: [...strongDiscretionary.evidence, ...weakDiscretionary.evidence].slice(0, 3) };

  // Committed must be MONEY-anchored. A bare "| Critical | ... |" table row is not
  // enough — response-SLA tables ("| Critical | 24 hours | 72 hours |") share that
  // shape (the aethelred false-positive). Require a currency symbol / token / 4+-digit
  // amount so an SLA table can't pass as a reward table.
  const committed = scan(t, [
    /paid in (usdc|usdt|dai|xlm|eth|usd)/, /will be paid/, /bounty (is|of) \$?\d/,
    /\$\s?\d[\d,]*\s*(to|-|–)\s*\$?\d/, /up to \$\s?\d[\d,]{2,}/,
    /\|\s*critical\s*\|[^\n|]*(\$|usdc|usdt|dai|\d{4,})/i, // reward-table row WITH an amount
    /(reward|payout).{0,20}\$\s?\d[\d,]{2,}/, /per (bug|finding|vulnerability).{0,20}\$?\d/,
  ]);

  // Guard (the quay false-positive): a $ amount that is an AUDIT-COST estimate
  // ("$25-50k, OtterSec/MoveBit/Zellic, 4-6 weeks lead") or a PLANNED / not-yet-open
  // bounty pool ("No bug bounty until post-mainnet", "$10k starter pool planned") is
  // NOT a committed reporter reward — it is spend, or a promise for later. Suppress a
  // committed hit whose ONLY money-anchor sits in that context.
  const committedFalseCtx = scan(t, [
    /no bug bounty (until|before|post|after)/, /starter pool/,
    /bount(y|ies)[^.\n]{0,50}(planned|coming soon|will launch|to be launched|post[- ]mainnet|after mainnet)/,
    /(planned|future|upcoming|targeted)[^.\n]{0,30}(immunefi|bounty|program|pool)/,
    /\$\s?\d[\d,]*k?\s*(to|-|–)\s*\$?\d[\d,]*k?[^.\n]{0,45}(audit|ottersec|movebit|zellic|trail of bits|certik|hacken|weeks?\s*lead)/,
    /(audit|ottersec|movebit|zellic|trail of bits|certik|hacken)[^.\n]{0,45}\$\s?\d/,
  ]);
  // A reward-NOW anchor (money tied to paying a reporter for a finding) beats the guard.
  const findingAnchored = scan(t, [
    /paid in (usdc|usdt|dai|xlm|eth|usd)/, /will be paid/,
    /(reward|payout|bounty)s?[^.\n]{0,25}(is|of|up to|:)?\s*\$?\s?\d[\d,]{2,}/,
    /per (bug|finding|vulnerability|report)[^.\n]{0,20}\$?\d/,
    /\|\s*critical\s*\|[^\n|]*(\$|usdc|usdt|dai|\d{4,})/i,
  ]);
  const committedEff = (committed.hit && committedFalseCtx.hit && !findingAnchored.hit)
    ? { hit: false, evidence: committed.evidence, suppressedBy: committedFalseCtx.evidence[0] || 'audit-cost/planned-pool' }
    : committed;

  // Program-access gate: an invitation-only / not-yet-open program does not reward an
  // uninvited reporter, even when PVR is technically on (the aethelred lesson).
  const invitationOnly = scan(t, [
    /invitation[- ]only/, /private,? (and )?(invitation|invite)/, /by invitation( only)?/,
    /not yet open/, /not open to the public/, /closed (beta|program)/,
    /application (is )?required/, /must be invited/, /invite[- ]only/,
  ]);

  // Deferral must be about REWARD TIMING, not generic "test on testnet before
  // mainnet" dev advice. Anchor every pattern to reward/bounty/payment words so a
  // deployment instruction can't false-trigger CREDIT-ONLY (the gardens-v2 lesson).
  const deferred = scan(t, [
    /(reward|bounty|bounties|payment|payout)s?[^.\n]{0,60}(honou?red|begin|start|commence|paid|live|deferred|available)[^.\n]{0,40}(mainnet|launch)/,
    /(honou?red|paid|begin|start)[^.\n]{0,30}(at|upon|from)[^.\n]{0,20}(mainnet|launch)/,
    /cash rewards? (begin|start|commence)/, /rewards? (are |will be )?deferred/,
    /(credited|reported) now[^.\n]{0,40}(honou?red|paid|mainnet|launch)/,
    /holds? no (user )?funds yet/, /no (real )?funds (are )?at (risk|stake) (yet|until)/,
    /(reward|bounty)[^.\n]{0,40}(q[1-4]\s*20\d\d)/,
  ]);

  const kyc = scan(t, [
    /\bkyc\b/, /know[ -]your[ -]customer/, /identity verification/, /verify your identity/,
    /immunefi/, /tax (form|information)/, /\bw-?9\b/, /\bw-?8\b/, /kyc\/aml/, /\baml\b/,
  ]);

  // Submission channel: email vs a private-issue/PVR link.
  const emails = [...t.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)].map(m => m[0].toLowerCase());
  const emailChannel = emails.filter(e => !e.endsWith('.png') && !e.includes('example'));
  const hardWalledMail = emailChannel.some(e => /@(gmail|googlemail)\.com$/.test(e));
  const pvrLinkInDoc = /security\/advisories\/new/i.test(t) || /private vulnerability reporting/i.test(t);

  return { discretionary, strongDiscretionary, weakDiscretionary, committed: committedEff, invitationOnly, deferred, kyc, emailChannel: [...new Set(emailChannel)].slice(0, 3), hardWalledMail, pvrLinkInDoc };
}

function verdict({ pvr, doc, c }) {
  if (!doc) return { code: 'NO-BOUNTY', exit: 7, why: 'no SECURITY.md / bug-bounty doc found' };

  const reasons = [];

  // Access gate first: an invitation-only / not-yet-open program won't pay an
  // uninvited reporter no matter how good the PVR channel or reward table looks.
  if (c.invitationOnly.hit) {
    return { code: 'UNREACHABLE', exit: 6, why: `invitation-only / not-open program: ${c.invitationOnly.evidence[0] || 'private by invitation'}` };
  }

  const privateChannel = pvr === true || c.pvrLinkInDoc;
  const emailOnly = !privateChannel && c.emailChannel.length > 0;

  // UNREACHABLE first: if you can't submit privately, nothing downstream matters.
  if (!privateChannel && emailOnly) {
    reasons.push(`no PVR; submission is email-only (${c.emailChannel.join(', ')})${c.hardWalledMail ? ' [gmail — reputation-walled from a fresh sender]' : ''}`);
    return { code: 'UNREACHABLE', exit: 6, why: reasons.join('; ') };
  }
  if (!privateChannel && !emailOnly) {
    return { code: 'UNREACHABLE', exit: 6, why: 'no private reporting channel found (PVR off, no security email)' };
  }

  // KYC/Immunefi gate is checked first: it caps payout regardless of how the reward
  // reads, and Immunefi-run programs are committed-but-identity-gated by construction.
  if (c.kyc.hit) {
    return { code: 'KYC-GATED', exit: 4, why: `payout gated: ${c.kyc.evidence[0] || 'KYC/Immunefi'}` };
  }
  // STRONG discretionary mechanism dominates a nominal table — a governance vote or
  // community pool won't reliably pay even with a published severity table.
  if (c.strongDiscretionary.hit) {
    return { code: 'DISCRETIONARY', exit: 5, why: `soft payout mechanism: ${c.strongDiscretionary.evidence[0] || 'discretionary'}` };
  }
  // No table at all, only a weak caveat → also discretionary.
  if (!c.committed.hit) {
    return { code: 'DISCRETIONARY', exit: 5,
      why: c.weakDiscretionary.hit ? `no committed table, only: ${c.weakDiscretionary.evidence[0]}` : 'reachable channel but no concrete committed-reward language' };
  }
  // Committed table present. Deferral (reward-anchored) → credit-only, else deliverable.
  if (c.deferred.hit) {
    return { code: 'CREDIT-ONLY', exit: 3, why: `committed but deferred: ${c.deferred.evidence[0] || 'mainnet-deferred'}` };
  }
  if (c.weakDiscretionary.hit) reasons.push('committed table with case-by-case caveat — read the exact terms');
  return { code: 'DELIVERABLE', exit: 0, why: (reasons.length ? reasons.join('; ') + '; ' : '') + `committed reward, reachable, no deferral/KYC signal: ${c.committed.evidence[0] || ''}`.trim() };
}

const ICON = { 'DELIVERABLE': '💰', 'CREDIT-ONLY': '🧾', 'KYC-GATED': '🪪', 'DISCRETIONARY': '🎲', 'UNREACHABLE': '🚫', 'NO-BOUNTY': '·' };

async function one(target, tok) {
  const [owner, repo] = target.split('/');
  if (!owner || !repo) { console.log(`  ! bad target "${target}" (want owner/repo)`); return 1; }
  const branch = await defaultBranch(owner, repo, tok);
  const [pvr, doc] = await Promise.all([pvrEnabled(owner, repo, tok), null]);
  const d = await bountyDoc(owner, repo, branch, tok);
  const c = d ? classify(d) : null;
  const v = verdict({ pvr, doc: d, c });

  console.log(`\n${ICON[v.code] || '?'}  ${owner}/${repo}  →  ${v.code}`);
  console.log(`    ${v.why}`);
  console.log(`    PVR=${pvr === null ? 'unknown' : pvr}${c ? `  doc=${d.path}` : '  doc=none'}`);
  if (c) {
    const flags = [];
    if (c.committed.hit) flags.push('committed✓');
    if (c.discretionary.hit) flags.push('discretionary✓');
    if (c.deferred.hit) flags.push('deferred✓');
    if (c.kyc.hit) flags.push('kyc/immunefi✓');
    if (c.emailChannel.length) flags.push('email:' + c.emailChannel.join(','));
    if (c.pvrLinkInDoc) flags.push('pvr-link-in-doc');
    if (flags.length) console.log(`    signals: ${flags.join('  ')}`);
  }
  return v.exit;
}

async function main() {
  const targets = process.argv.slice(2).filter(a => !a.startsWith('-'));
  if (!targets.length) {
    console.error('usage: node deliver.js <owner/repo> [<owner/repo> ...]');
    process.exit(1);
  }
  const tok = token();
  console.log(`deliver.js — bounty payout-deliverability check  (${tok ? 'authed' : 'unauthed'})`);
  let worst = 0;
  for (const t of targets) {
    try {
      const code = await one(t, tok);
      worst = Math.max(worst, code); // higher exit = less cash-collectible
    } catch (e) {
      console.log(`  ! ${t}: ${e.message}`);
      worst = Math.max(worst, 1);
    }
  }
  console.log('');
  process.exit(worst);
}

main();
