# Ethics and safety posture

Open Cell Range teaches how cellular identity attacks work so that people can **recognise
and defend against them**. This note states plainly what the project is and is not, so that
the line is not left to inference.

## What this is

- A **pure simulation**. The radio world is a data structure in memory. Nothing is
  transmitted, received, or measured. There is no SDR, no baseband, no SIM, no antenna,
  and no code path that could drive any of those.
- Built on **published, standardised knowledge**: the GSM one-way-authentication problem,
  the LTEInspector / aLTEr family of pre-authentication weaknesses, and the 5G-AKA
  linkability results, all of which are in the open standards and peer-reviewed literature.
- Keyed with the **3GPP published test vectors** (TS 35.207/35.208 for MILENAGE, TS 33.501
  Annex C for SUCI). No real subscriber keys exist anywhere in this project.
- **Defence-first.** `ocr-detect` — what a passive, Rayhunter-class monitor concludes from
  the same air — is a first-class part of the engine, not an add-on. Every attack the range
  can run has a matching detection the range can teach.

## What this is not

- Not an attack tool. It cannot produce, capture, or replay real radio traffic. The
  phase-two capture importer reads recordings a *separate* tool made; it never makes them,
  and importing a capture only feeds the same passive analyser.
- Not carrier-specific. No network operator, device model, or product is named or targeted.
- Not a source of working exploit code. The attacker actors manipulate the simulated stack
  at the level the public research describes; they are teaching models, not deployable
  payloads.

## Why it is built this way

Understanding the attack is a precondition for detecting it. Rayhunter exists because these
attacks are real and used against real people; a defender who has never seen how an IMSI
catcher behaves cannot reliably tell one from an ordinary cell. The range lets a defender
build that intuition safely, with no spectrum, no legal exposure, and no hardware.

## For workshop and classroom use

The range is designed to be run in a browser tab with no network access and no accounts.
Nothing a learner does leaves their machine. That is deliberate: it means the range can be
used anywhere, including places where operating real radio equipment would be illegal or
unsafe, and it means no data about a learner is ever collected.

If you extend the project, keep the seam: the simulation must remain a simulation, and any
real-capture work must stay on the **analysis** side, reading recordings made by tools that
carry their own legal and ethical responsibilities.
