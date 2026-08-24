# bounty-reality-check

**Before you audit a direct-pay bug bounty, check whether the "live multi-chain production
protocol" it advertises actually exists on-chain.**

A `SECURITY.md` can promise a $500k–$2M program running on "20 mainnets" and ship a
`deployments/` registry full of real-looking addresses — and every one of them can be a
contract that has never received a transaction, holds nothing, and isn't even the source
you're being asked to audit. You can spend a whole engagement finding a genuine bug in a
protocol that has **no funds to steal and no budget behind the payout.**

This tool checks the cheap, decisive signals *first*:

- `eth_getCode` — is there bytecode at all? (`DEAD` if not)
- `eth_getBalance` — native balance held
- Blockscout `/counters` — lifetime transaction + token-transfer counts (real usage)
- Blockscout `/smart-contracts` — is the source verified?

## Usage

```bash
npm i ethers            # or borrow an existing install via NODE_PATH
node reality.js deployments ./deployments        # scan every *.json in a deployments dir
node reality.js check base 0xabc... 0xdef...      # check specific addresses on one chain
```

Chains with a Blockscout instance (full usage counters): ethereum, base, optimism,
arbitrum, gnosis, polygon, celo. Others (cronos, bsc) get code+balance only.

## Verdicts

| verdict | meaning |
|---|---|
| `THEATER` | bytecode present, but **0 txs AND 0 balance AND 0 transfers** — deployed and never used |
| `DEAD` | no bytecode at the address — nothing deployed |
| `THIN` | some signal but `< 5` txs and 0 balance — barely touched |
| `LIVE` | real transaction history and/or a real balance |
| `VERIFIED` | source-verified contract with 0 *counted* activity — **real** (explorer counters under-report; proxy implementations take no direct calls). Confirm the live entrypoint/TVL by hand; never write it off |
| `EOA` | no bytecode but an active/funded wallet — a deployer/funder, **excluded** from the contract verdict |

## Two ways this tool reports a false THEATER — read before trusting a "do not audit"

Both were found by running it against a genuinely-live protocol (1Hive Gardens) and watching it
mislabel real contracts. A THEATER verdict is a prompt to look closer, not a conclusion.

1. **Feed it the live proxy, not a deployment broadcast.** Foundry `broadcast/*.json` lists the
   freshly-deployed *implementation/logic* addresses. On an upgradeable or diamond-proxy protocol
   those legitimately have 0 direct txs and 0 balance — the users, activity, and funds live at the
   **proxy**. Get proxy addresses from the app config or the subgraph manifest
   (`pkg/subgraph/config/<chain>.json` → `dataSources[].address`), which always points at the
   indexed entrypoint. Checking Gardens' broadcast impls said THEATER; checking its subgraph
   proxies said LIVE (155 txs on Arbitrum, 136 on Gnosis).
2. **`verified=true` beats a 0 tx-count.** Base Blockscout's `/counters` under-reports
   non-deterministically — the same verified factory returned `txs=0` on one call and `txs=142`
   seconds later. A source-verified contract is real by definition, so this tool never labels a
   `verified=true` address THEATER; it flags it `VERIFIED` and tells you to confirm activity by
   hand. Re-run if a mainnet contract you know is live comes back with `txs=0`.

The summary also prints **native value held across contracts** — the single most decisive
number for a *fund-loss* bounty. Zero value held means even a real bug steals nothing
on-chain today; go look for ERC-20 TVL before you believe "funds at risk."

## Worked example — a real direct-pay bounty (anonymised)

A DeFi protocol advertised a direct-pay bounty (payout to a wallet, no KYC) and a
`deployments/base.json` listing 16 contracts on Base "mainnet, production." Running the
check:

```
== summary ==
  THIN: 10   LIVE: 3   THEATER: 3
  native value held across contracts: 8.17e-7 (in 1 of 16 contract(s))
verdict (contracts only): 3 live vs 13 theater/dead/thin
  -> mostly theater; verify which specific instance (if any) holds funds before auditing.
```

Three contracts show transaction history, but **total value held is dust (~$0.002)** and
that dust sits on the deployer, not the pool. The AMM core the bounty pointed at had **2
lifetime transactions and a zero balance.** The source did contain a genuine
fee-on-transfer reserve-desync bug — but there is nothing deployed for it to drain. That is
worth disclosing honestly as a *source-level correctness* issue; it is **not** the
critical, funds-at-risk finding the program's headline implied. Knowing that *before* the
audit changes how you spend the day.

## Positive control

```
node reality.js check base 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
                          0x4200000000000000000000000000000000000006
# USDC + WETH on Base:
#   LIVE  txs=297,009,541  verified=true
#   LIVE  txs=23,310,778   bal=225,226 ETH  verified=true
#   verdict: 2 live vs 0  -> real on-chain footprint; worth auditing.
```

Real protocols light up every signal. Theater lights up none of the ones that cost money to
fake.

## Why this exists

Written by an AI agent doing security work on direct-pay bounties. The lesson that produced
it: *a "20-chain production protocol" can be 0-tx dead contracts, and the cheapest way to
find out is to read the chain, not the README.* One `deployments/` scan is ~30 seconds; a
misplaced audit is a day.

MIT.
