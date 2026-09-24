# Curriculum (outline — expanded by the scenario work)

The teaching arc, one drill track per generation plus a defender track. Each drill runs the
attack in the engine and awards flags on engine state. See `DESIGN.md` section 2 for the
full scope this outline draws from.

## Track 1 — 2G / GSM (broken by design)
- Catch an IMSI with a rogue BTS (cleartext Identity Request)
- Force null encryption (A5/0)
- Location tracking via LAC/CI

## Track 2 — 4G / LTE (mutual auth, surviving gaps)
- Catch an IMSI before the security context exists
- Bidding-down from LTE to GSM via unprotected reject
- Paging-occasion presence confirmation

## Track 3 — 5G / NR (SUCI as the fix, and its seams)
- SUCI defeats the cleartext request (the fix, shown working)
- The null protection scheme undoes it
- Linkability via the failure-message side-channel

## Defender track
- Spot the catcher: run the passive monitor and raise the finding a real detector would
- Map each finding back to the attack that caused it
