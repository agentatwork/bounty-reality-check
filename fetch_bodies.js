#!/usr/bin/env node
// Refetch the body of every real security.txt in the corpus.
//
// The original scan (scan_securitytxt.js) kept parsed fields and threw the body away, which was
// right for the contact-reachability question and useless for this one: an OpenPGP cleartext
// signature is a property of the raw bytes, not of any field. So this is a second pass over the
// 7,780 domains the first pass classified as is_security_txt, and nothing else — it does not
// re-discover, it re-reads.
//
// Append-only JSONL with a skip-set, because a scan this size has died silently on this box before
// and a partial file you can resume beats a complete file you have to restart.
//
// Bodies contain contact addresses. This output stays in /tmp, is never committed, and is never
// published.
//
//   node fetch_bodies.js <corpus.jsonl> <out.jsonl>

const fs = require('fs');
const https = require('https');
const http = require('http');

const CONC = 8;
const TIMEOUT_MS = 15000;
const MAX_BYTES = 262144;     // a security.txt is ~500 bytes; anything this big is not one
const MAX_REDIRECTS = 5;

function get(url, redirects = 0) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ err: 'BADURL' }); }
    const mod = u.protocol === 'http:' ? http : https;
    const req = mod.request(u, {
      method: 'GET',
      headers: {
        // Same UA the first pass used, so a site that treats me differently does so consistently.
        'user-agent': 'agentatwork-securitytxt-survey/1.0 (+https://agentatwork.xyz/notes/security-txt.html)',
        'accept': 'text/plain,*/*',
      },
      timeout: TIMEOUT_MS,
    }, (res) => {
      const loc = res.headers.location;
      if (res.statusCode >= 300 && res.statusCode < 400 && loc && redirects < MAX_REDIRECTS) {
        res.resume();
        let next;
        try { next = new URL(loc, u).toString(); } catch { return resolve({ err: 'BADREDIR' }); }
        return resolve(get(next, redirects + 1));
      }
      const chunks = [];
      let n = 0;
      res.on('data', (c) => {
        n += c.length;
        if (n <= MAX_BYTES) chunks.push(c);
        else { res.destroy(); }
      });
      res.on('end', () => resolve({
        status: res.statusCode,
        content_type: res.headers['content-type'] || null,
        final_url: u.toString(),
        truncated: n > MAX_BYTES,
        bytes: n,
        // latin1, not utf8: the signature check is over bytes, and utf8 decoding a file with a
        // stray high byte would silently replace it and break the hash the signature covers.
        body: Buffer.concat(chunks).toString('latin1'),
      }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ err: 'TIMEOUT' }); });
    req.on('error', (e) => resolve({ err: e.code || String(e.message).slice(0, 60) }));
    req.end();
  });
}

async function main() {
  const [corpusPath, outPath] = process.argv.slice(2);
  if (!corpusPath || !outPath) {
    console.error('usage: node fetch_bodies.js <corpus.jsonl> <out.jsonl>');
    process.exit(1);
  }

  const targets = [];
  for (const line of fs.readFileSync(corpusPath, 'utf8').split('\n')) {
    if (!line) continue;
    let d;
    try { d = JSON.parse(line); } catch { continue; }
    if (d.is_security_txt) targets.push({ domain: d.domain, url: d.final_url });
  }

  const done = new Set();
  if (fs.existsSync(outPath)) {
    for (const line of fs.readFileSync(outPath, 'utf8').split('\n')) {
      if (!line) continue;
      try { done.add(JSON.parse(line).domain); } catch { /* half-written last line */ }
    }
  }
  const todo = targets.filter((t) => !done.has(t.domain));
  console.error(`${targets.length} security.txt in corpus, ${done.size} already fetched, ${todo.length} to go`);

  const out = fs.createWriteStream(outPath, { flags: 'a' });
  let i = 0, ok = 0, fail = 0;
  async function worker() {
    while (i < todo.length) {
      const t = todo[i++];
      const r = await get(t.url);
      if (r.err) fail++; else ok++;
      out.write(JSON.stringify({ domain: t.domain, url: t.url, ...r }) + '\n');
      if ((ok + fail) % 250 === 0) console.error(`  ${ok + fail}/${todo.length}  ok=${ok} fail=${fail}`);
    }
  }
  await Promise.all(Array.from({ length: CONC }, worker));
  out.end();
  console.error(`done: ok=${ok} fail=${fail}`);
}

main();
