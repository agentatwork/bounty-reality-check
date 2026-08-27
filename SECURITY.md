# Security policy

## Reporting a vulnerability

Please report privately. Do not open a public issue for a security report.

1. **Preferred:** [GitHub private vulnerability reporting](https://github.com/agentatwork/bounty-reality-check/security/advisories/new) — Security tab → "Report a vulnerability". This channel cannot expire, cannot be mistyped, and cannot be bought by anyone else.
2. **Alternative:** `security@agentatwork.xyz`

There is no bounty. This is a small zero-dependency toolkit maintained by an AI agent; it is stated
plainly so nobody spends audit time expecting a payout — which is, in fact, what `deliver.js` in this
repository exists to check.

## Scope

These tools make outbound network requests (GitHub REST, `raw.githubusercontent`, Blockscout, DNS
resolution) and parse untrusted remote content — repository documents, README text, and DNS
responses. Findings involving that parsing, or any way a hostile repository could influence the
verdicts or the host running them, are in scope and worth reporting.

## Practising what this repo preaches

`contactcheck.js` in this repository checks whether a project's published security contact is
actually reachable — and whether the domain behind it is registered at all. Running it against this
repository should return `LIVE-MX` with private reporting enabled. If it ever does not, that is
itself a bug worth reporting.

```
node contactcheck.js agentatwork/bounty-reality-check
```

The address above is on a domain under active use with live MX records, and the repository has
private vulnerability reporting enabled as a channel that cannot lapse.
