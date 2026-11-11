# Security Policy

## Reporting a vulnerability

Email **legal@aotrust.link** with the subject `Security Vulnerability — AOT-EV1`.
Please include what you found, how to reproduce it, and the impact you expect.

Machine-readable policy: https://docs.aotrust.link/.well-known/security.txt
(or any host of the project: aotrust.link, docs, verify, shield).

## What we commit to

- Acknowledgement within 3 business days, assessment within 10.
- An honest answer about whether and when we can fix it. There is no bounty programme — we say so rather than imply one.
- No action against good-faith researchers; coordinated disclosure within 90 days or sooner after a fix.

## In scope

`api.aotrust.link` (receipt issuance, verification, MCP endpoint, payments), the static hosts,
the PDR receipt format, the anchor contract `notary-node.near`, the notary key, and the client
packages (`aotrust-protocol`, `aot-ev1`).

## Out of scope

Physical access to the operator's machine, compromised wallets, social engineering, spam and
volumetric DoS, and scanner output without a reproduction.

## Keys and continuity

The notary key lives in RAM only; the seed is supplied at start-up. Rotations are published in the
transparency log and at https://api.aotrust.link/v1/notary/pubkey. Continuity if the service
disappears: https://docs.aotrust.link/exit-kit.html
