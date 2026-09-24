// curriculum-notes.js — static text for the guided course and the workshop
// "instructor notes" toggle. Purely presentational content, keyed by the
// scenario slugs engine.listScenarios() already returns in teaching order
// (see site/ENGINE-API.md). Framing draws from docs/CURRICULUM.md and
// docs/PROTOCOL.md without duplicating their tables verbatim; instructor
// notes are new, workshop-facing material this project didn't have yet.
//
// This file never touches the engine and is not part of the engine contract —
// it's read-only reference copy for the UI layer.

export const LESSON_NOTES = {
  'gsm-2g-imsi-catch': {
    framing: 'GSM never asks the network to prove itself. Watch a rogue cell simply ' +
      'out-shout the real one on the same network id — the phone camps on it, and ' +
      'when it is asked for its IMSI, it just answers. There is no protocol step ' +
      'where it could object.',
    instructor: [
      'No cryptography is broken here — the whole attack is a protocol gap (one-way auth), not a cipher weakness.',
      'Have the group name the exact message that leaks the IMSI before revealing the findings panel: IdentityRequest(IMSI).',
      'Good place to mention this is the "Wiegand of cellular" framing from DESIGN.md, if the group has done Open Door Range.',
    ],
  },
  'gsm-2g-null-cipher': {
    framing: 'Same rogue cell, one step further. The network — never the phone — ' +
      'picks the cipher, and it is allowed to pick A5/0: no encryption at all. ' +
      'Watch the phone comply with no way to refuse.',
    instructor: [
      'Emphasize the phone has zero say in cipher selection — a useful contrast with protocols where the client can refuse a weak cipher suite.',
      'If asked "why would a real network do this," point out CleartextIdentityRequest and NullCipherCommanded differ in how ambiguous they are — see docs/DETECTION.md.',
    ],
  },
  'lte-4g-imsi-catch': {
    framing: 'LTE finally makes the network prove it holds the subscriber key — a ' +
      'fake eNodeB cannot fake that. But watch how it never needs to: the IMSI is ' +
      'still requested and handed over before mutual authentication even starts.',
    instructor: [
      'The key moment: put this drill\'s finding next to gsm-2g-imsi-catch\'s. Same finding kind, same severity, different generation underneath.',
      'If someone says "but EPS-AKA fixed 4G," this drill is the direct answer to that claim.',
    ],
  },
  'lte-4g-downgrade': {
    framing: 'An LTE reject message carries no integrity protection, so the phone ' +
      'cannot tell a forged one from a real one. Watch a rogue eNodeB reject the ' +
      'attach and steer the phone straight back down to GSM, where every Track 1 ' +
      'attack applies again.',
    instructor: [
      'A good place to introduce "bidding-down" as a general protocol-security pattern, not something cellular-specific.',
      'Ask the group to spot the shared tell (area code 65535) reappearing on two different RATs — that cross-cell correlation is an analyst\'s job, not the monitor\'s; docs/DETECTION.md says so explicitly.',
    ],
  },
  'lte-4g-paging': {
    framing: 'A different shape of attack: no rogue cell this time. Paging travels ' +
      'in the clear by design, so if you already have a target\'s IMSI, inducing ' +
      'the real network to page them — and watching for the reply — confirms ' +
      'they are right here.',
    instructor: [
      'Good moment to introduce ToRPEDO/PIERCER by name, and to separate "confirming presence" from "recovering an identity" — this drill only does the former.',
      'Point out explicitly: this is the first drill in the whole arc that needs no fake infrastructure at all.',
    ],
  },
  'nr-5g-suci-protects': {
    framing: 'Run the identical rogue-cell playbook against a 5G phone and watch it ' +
      'fail. The phone answers with a SUCI — ciphertext only the home network can ' +
      'open. Put the findings panel here next to the 2G/4G drills.',
    instructor: [
      'Slow down on this one: the flag captures because the attack was tried and failed, not because it was skipped. Make sure that distinction lands before moving on.',
      'A good pause point to ask "so is 5G just fixed now?" before the next drill answers it.',
    ],
  },
  'nr-5g-null-scheme': {
    framing: 'SUCI\'s protection is a configuration choice, not a law of physics. ' +
      'This subscriber profile is set to the null scheme — legal per spec — so the ' +
      '"concealed" identifier the phone hands back is just the SUPI, unencrypted.',
    instructor: [
      'Emphasize "legal, spec-compliant, and still fully exposed" — this is a deployment/policy failure, not a cryptographic bug in SUCI.',
      'Contrast the finding severity directly against the previous drill (Info/Low vs. this drill\'s High) to reinforce that configuration matters as much as protocol design.',
    ],
  },
  'nr-5g-linkability': {
    framing: 'SUCI is holding here — the SUPI never leaks. But replay two ' +
      'previously-captured authentication challenges and watch the phone\'s ' +
      'failure message give it away: "wrong key" versus "right key, stale ' +
      'counter" reveals which challenge was ever hers.',
    instructor: [
      'The subtlest drill in the arc — check that learners notice the identity was never recovered, only presence and linkage.',
      'A strong closing point for the 5G track: even the fix that works has a side channel living in how a protocol has to fail safely.',
    ],
  },
  'defend-spot-the-catcher': {
    framing: 'Switch sides. The attack already happened before you arrived — read ' +
      'the air log first and form a hypothesis, then run the passive monitor and ' +
      'see whether it agrees with you.',
    instructor: [
      'The button reads "Run the monitor," not "Run the attack" — worth calling out, since every earlier drill trained the opposite instinct.',
      'Good wrap-up discussion: ask what a finding can\'t tell you (intent, ground truth) even when it fires — tie back to "a finding is evidence, not a verdict" in docs/DETECTION.md.',
    ],
  },
};

export function framingFor(slug) {
  return (LESSON_NOTES[slug] && LESSON_NOTES[slug].framing) || '';
}

export function instructorNotesFor(slug) {
  return (LESSON_NOTES[slug] && LESSON_NOTES[slug].instructor) || [];
}
