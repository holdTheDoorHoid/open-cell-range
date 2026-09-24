# Open Cell Range

**A browser-based virtual range for cellular network attacks — and for detecting them.**
No SDR, no SIM, no spectrum. A simulated phone, cell towers, and core network let you run
and then catch IMSI-catcher and rogue-base-station attacks across the 2G → 4G → 5G arc,
entirely in a browser tab.

It is the cellular sibling of [Open Door Range](https://github.com/holdTheDoorHoid/open-door-range)
(physical access control) and pairs with [Rayhunter](https://github.com/EFForg/rayhunter),
which detects these attacks in the real world.

> **This is a simulation for defensive education.** Nothing is ever transmitted. See
> [`docs/ETHICS.md`](docs/ETHICS.md).

## The arc it teaches

| Generation | The lesson |
|-----------|------------|
| **2G / GSM** | One-way authentication and optional/null encryption: the phone can't tell a real tower from a fake one, and the IMSI is handed over on request. Broken by design. |
| **4G / LTE** | Mutual authentication closes the headline attack — but the IMSI still leaks in the clear before security starts, and unprotected rejects let an attacker force a downgrade back to 2G. |
| **5G / NR** | SUCI encrypts the permanent identity before it ever hits the air, killing the classic catcher — yet it's optional, downgradable, and the quiet linkability side-channels survive. |

For every attack, the defensive half shows what a passive monitor would conclude — the same
reasoning a real detector uses.

## Run it

Online: GitHub Pages (no build needed; the site runs on a JavaScript reference engine until
the WebAssembly module is built).

Locally:

```bash
# static site, reference engine, no toolchain:
python3 -m http.server -d site 8000   # then open http://localhost:8000

# the real engine:
cargo install wasm-pack
wasm-pack build crates/ocr-wasm --target web --out-dir ../../site/pkg
# then flip the import in site/js/app.js to engine-wasm.js
```

## How it's built

One Rust engine compiled to WebAssembly, so the teaching simulation and the real-capture
analyser are the same code and a drill can never teach something the analyser disagrees
with. Everything is deterministic — a virtual microsecond clock and a seeded RNG, no wall
clock and no OS entropy — so scenarios are reproducible and flags are stable.

See [`DESIGN.md`](DESIGN.md) for the authoritative design and the crate map, and
[`site/ENGINE-API.md`](site/ENGINE-API.md) for the engine contract.

## License

GPLv3. Copyleft keeps this from being absorbed into a closed vendor training product. The
project is free and open; the work around it — workshops, instructor material, and the
capture hardware it pairs with — is where [LSOH](https://github.com/holdTheDoorHoid) earns
its keep.
