#!/usr/bin/env node
/*
 * bounty-reality-check — is a direct-pay bug bounty backed by REAL deployed contracts,
 * or is its "live multi-chain production protocol" on-chain theater?
 *
 * Motivation: a SECURITY.md can advertise a $500k–$2M program on "20 mainnets" and list a
 * deployments/ registry full of addresses — and every one of them can be a contract that has
 * never received a single transaction, holds nothing, and isn't the source you're auditing.
 * You can burn a whole audit on a target with no funds to steal and no budget behind it.
 * This checks the cheap, decisive signal FIRST: do the claimed addresses show real on-chain life?
 *
 *   node reality.js deployments <dir>          # parse deployments/*.json, check every address
 *   node reality.js check <chain> <addr>...     # check specific addresses on one chain
 *
 * Sources per address:
 *   - RPC eth_getCode     -> is there bytecode at all?
 *   - RPC eth_getBalance  -> native balance
 *   - Blockscout counters -> lifetime tx count + token-transfer count (real usage)
 *   - Blockscout contract -> is the source verified?
 *
 * Verdict per address:
 *   THEATER  bytecode present but 0 txs AND 0 balance AND 0 transfers (never used)
 *   DEAD     no bytecode at the address (nothing deployed)
 *   THIN     some signal but < 5 txs and 0 balance (barely touched)
 *   LIVE     real transactions and/or a real balance
 *   UNKNOWN  no explorer for this chain; only code/balance known
 */
const { ethers } = require('ethers');

// chain registry: rpc for code/balance (everywhere), blockscout for usage counters (where it exists)
const CHAINS = {
  ethereum: { chainId: 1,     rpc: 'https://ethereum-rpc.publicnode.com', scout: 'https://eth.blockscout.com' },
  base:     { chainId: 8453,  rpc: 'https://mainnet.base.org', rpc2: 'https://base-rpc.publicnode.com', scout: 'https://base.blockscout.com' },
  optimism: { chainId: 10,    rpc: 'https://optimism-rpc.publicnode.com', scout: 'https://optimism.blockscout.com' },
  arbitrum: { chainId: 42161, rpc: 'https://arb1.arbitrum.io/rpc',        scout: 'https://arbitrum.blockscout.com' },
  gnosis:   { chainId: 100,   rpc: 'https://rpc.gnosischain.com',         scout: 'https://gnosis.blockscout.com' },
  polygon:  { chainId: 137,   rpc: 'https://polygon-rpc.com',             scout: 'https://polygon.blockscout.com' },
  celo:     { chainId: 42220, rpc: 'https://forno.celo.org',              scout: 'https://celo.blockscout.com' },
  cronos:   { chainId: 25,    rpc: 'https://evm.cronos.org',              scout: null },
  bsc:      { chainId: 56,    rpc: 'https://bsc-rpc.publicnode.com',      scout: null },
};
const ALIASES = { mainnet: 'ethereum', eth: 'ethereum', matic: 'polygon', xdai: 'gnosis' };
const norm = (n) => ALIASES[String(n).toLowerCase()] || String(n).toLowerCase();

async function j(url, ms = 12000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try { const r = await fetch(url, { signal: ctl.signal }); return r.ok ? await r.json() : null; }
  catch { return null; } finally { clearTimeout(t); }
}

async function checkAddr(chainKey, addr, label) {
  const chain = CHAINS[chainKey];
  const out = { chain: chainKey, addr, label, code: null, native: null, txs: null, transfers: null, verified: null, verdict: 'UNKNOWN' };
  if (!chain) { out.verdict = 'NO_CHAIN'; return out; }
  // RPC: code + balance (works on every chain). Try primary then fallback so a flaky
  // endpoint can't make a real contract look codeless.
  for (const rpc of [chain.rpc, chain.rpc2].filter(Boolean)) {
    try {
      const p = new ethers.JsonRpcProvider(rpc, chain.chainId, { staticNetwork: true });
      const [code, bal] = await Promise.all([p.getCode(addr), p.getBalance(addr)]);
      out.code = code && code !== '0x';
      out.native = Number(ethers.formatEther(bal));
      break;
    } catch { /* try fallback */ }
  }
  // Blockscout: real-usage counters + verification (where an instance exists)
  if (chain.scout) {
    const c = await j(`${chain.scout}/api/v2/addresses/${addr}/counters`);
    if (c) { out.txs = Number(c.transactions_count); out.transfers = Number(c.token_transfers_count); }
    const sc = await j(`${chain.scout}/api/v2/smart-contracts/${addr}`);
    if (sc) out.verified = !!sc.is_verified;
  }
  // verdict
  if (out.code === false) out.verdict = (out.txs > 0 || out.native > 0) ? 'EOA' : 'DEAD';
  else if (out.txs === null) out.verdict = out.native > 0 ? 'LIVE' : 'UNKNOWN';
  else if (out.txs === 0 && out.native === 0 && (out.transfers || 0) === 0) out.verdict = 'THEATER';
  else if (out.txs < 5 && out.native === 0) out.verdict = 'THIN';
  else out.verdict = 'LIVE';
  return out;
}

// pull {network, [addresses]} out of a deployments/*.json shape
function parseDeployment(obj) {
  const network = norm(obj.network || obj.chain || '');
  const addrs = [];
  const walk = (o, path) => {
    if (o == null) return;
    if (typeof o === 'string') { if (/^0x[0-9a-fA-F]{40}$/.test(o)) addrs.push({ addr: o, label: path }); return; }
    if (typeof o === 'object') for (const k of Object.keys(o)) walk(o[k], path ? `${path}.${k}` : k);
  };
  // prefer the contracts{} block for labels, else whole object
  walk(obj.contracts || obj, 'contracts');
  return { network, addrs };
}

async function main() {
  const [mode, ...rest] = process.argv.slice(2);
  let jobs = [];
  if (mode === 'deployments') {
    const fs = require('fs'), path = require('path');
    const dir = rest[0];
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
      let obj; try { obj = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); } catch { continue; }
      const { network, addrs } = parseDeployment(obj);
      if (!network || !CHAINS[network]) continue; // only chains we can reach
      for (const a of addrs) jobs.push({ chain: network, addr: a.addr, label: `${f}:${a.label}` });
    }
  } else if (mode === 'check') {
    const chain = norm(rest[0]);
    for (const a of rest.slice(1)) jobs.push({ chain, addr: a, label: '' });
  } else {
    console.error('usage: reality.js deployments <dir>  |  reality.js check <chain> <addr>...');
    process.exit(1);
  }
  // de-dup identical (chain,addr)
  const seen = new Set();
  jobs = jobs.filter((x) => { const k = x.chain + x.addr.toLowerCase(); return seen.has(k) ? false : seen.add(k); });

  console.error(`checking ${jobs.length} address(es) across ${new Set(jobs.map(j=>j.chain)).size} chain(s)...\n`);
  const tally = {};
  const rows = [];
  for (const jb of jobs) {
    const r = await checkAddr(jb.chain, jb.addr, jb.label);
    tally[r.verdict] = (tally[r.verdict] || 0) + 1;
    rows.push(r);
    const flag = { THEATER: '🎭', DEAD: '💀', THIN: '🌱', LIVE: '✅', EOA: '👤', UNKNOWN: '❔', NO_CHAIN: '⏭️' }[r.verdict] || '?';
    console.log(`${flag} ${r.verdict.padEnd(8)} ${jb.chain.padEnd(9)} ${jb.addr}  txs=${r.txs ?? '?'} bal=${r.native ?? '?'} verified=${r.verified ?? '?'}  ${jb.label}`);
  }
  console.log('\n== summary ==');
  for (const [k, v] of Object.entries(tally).sort((a,b)=>b[1]-a[1])) console.log(`  ${k}: ${v}`);
  // EOAs (deployer/funder wallets) are not protocol contracts — exclude from the contract verdict.
  const real = (tally.LIVE || 0);
  const fake = (tally.THEATER || 0) + (tally.DEAD || 0) + (tally.THIN || 0);
  if (tally.EOA) console.log(`  (${tally.EOA} EOA wallet(s) excluded from the contract verdict)`);
  // The decisive signal for a FUND-LOSS bounty: does any contract actually hold value?
  const contracts = rows.filter((r) => r.verdict !== 'EOA' && r.verdict !== 'NO_CHAIN');
  const held = contracts.reduce((s, r) => s + (r.native || 0), 0);
  const funded = contracts.filter((r) => (r.native || 0) > 0).length;
  console.log(`  native value held across contracts: ${held} (in ${funded} of ${contracts.length} contract(s))`);
  console.log(`\nverdict (contracts only): ${real} live vs ${fake} theater/dead/thin` +
    (real === 0 && fake > 0 ? '  ->  NO REAL DEPLOYMENT BEHIND THIS BOUNTY. Do not spend an audit on it.' :
     fake > real ? '  ->  mostly theater; verify which specific instance (if any) holds funds before auditing.' :
     '  ->  real on-chain footprint; worth auditing the funded instances.'));
  if (held === 0 && contracts.length > 0)
    console.log('note: ZERO native value across all contracts. Even a real bug here steals nothing on-chain today —\n' +
      '      check for token (ERC-20) TVL before treating a "funds-at-risk" bounty as funds-at-risk.');
}
main();
