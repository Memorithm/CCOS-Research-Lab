# The claim counter — selling annual, single-seat Pro licenses

CCOS Pro is sold as an **annual, single-seat** license: one claim code per
sale, redeemed once, bound to one machine. This page is the vendor runbook for
the claim counter (`tools/ccos-license-server`) and the customer-side flow
(`ccos license claim`). Verification at runtime is unchanged and stays fully
offline ([`SECURITY.md`](SECURITY.md) posture; see `src/license.rs`) — the
counter is a **fulfillment convenience, never a runtime dependency**. If it is
down, no deployed customer notices; only a new code redemption waits.

## The flow

```
VENDOR (anywhere the vault lives)                CUSTOMER (their machine)
─────────────────────────────────                ────────────────────────
ccos-license-admin new
  --licensee "Acme" --days 365
        │
        ├─► prints CCOS-XXXXX-XXXXX-XXXXX-XXXXX   (shown once)
        └─► vault.json: sha256(code) → unclaimed
                                                  ccos license claim CCOS-… \
                                                    --from https://licensing.memorithm.fr
                     POST /claim  ◄───────────────  { sha256(code), machine_fp }
COUNTER: flip unclaimed→claimed (atomic,
durable), sign token binding machine_fp
                     200 { token }  ─────────────► verify signature against the
                                                    key baked in the BINARY,
                                                    check the binding, install →
                                                    ~/.config/ccos/license
                                                  ccos doctor   → tier PRO
```

What crosses the wire, in total, once per sale: **two hashes up, one signed
token down.** The counter never sees the claim code (only its hash arrives),
never learns hardware identity (the fingerprint is an opaque
`sha256("ccos-machine-v1|" + /etc/machine-id)`), and the customer's runtime
never talks to it again.

## Single-seat semantics

- The token carries the machine fingerprint **inside the signed payload** — the
  binding is exactly as tamper-proof as the license itself.
- On any other machine the runtime drops to community with one explicit log
  line (`enforce_machine_binding` — never a silent downgrade, core untouched).
- **Lost token, same machine**: just re-run `ccos license claim` with the same
  code — the counter re-issues idempotently with the *original* expiry (a
  re-claim can never extend a license).
- **Machine died / replaced**: the vendor runs
  `ccos-license-admin rearm <code-or-hash>`; the same code becomes claimable
  once more (fresh expiry at the new claim). `revoke` is the hostile-case
  counterpart.
- Hosts without `/etc/machine-id` (unusual containers): the customer sets
  `CCOS_MACHINE_ID` to any stable identifier before claiming — the binding is
  then to that declared identity. Fail-closed: a bound license on a host with
  no derivable id reads community, announced.

## Vendor runbook

**Once — the keypair** (on an offline machine; the seed never enters the repo):

```sh
cargo run --features license --example license_sign -- keygen
# paste the printed LICENSE_PUBLIC_KEY into src/license.rs, rebuild + distribute;
# keep the 64-hex seed for the counter's environment.
```

**Deploy the counter** (any small VPS; e.g. `licensing.memorithm.fr` → an A
record at your registrar pointing at it):

```sh
cargo build --release -p ccos-license-server
# the counter listens on loopback; TLS + the public name are the proxy's job:
CCOS_LICENSE_SIGNING_SEED=<64-hex> \
  ./target/release/ccos-license-server --vault /var/lib/ccos-licenses/vault.json
```

Caddyfile (automatic HTTPS via Let's Encrypt):

```
licensing.memorithm.fr {
    reverse_proxy 127.0.0.1:8471
}
```

**Per sale:**

```sh
ccos-license-admin --vault vault.json new --licensee "Acme Corp" --days 365 --label invoice-42
# → hand the printed CCOS-… code to the customer (mail, invoice, portal).
ccos-license-admin --vault vault.json list
ccos-license-admin --vault vault.json rearm  <CODE or hash>   # machine replaced
ccos-license-admin --vault vault.json revoke <CODE or hash>
```

Back up `vault.json` (a durable JSON file): losing it means unclaimed codes
can no longer be redeemed. A *stolen* copy is harmless — it holds only hashes
and business labels, nothing redeemable and no key material.

## Variant B — shared hosting (no daemon)

The counter's state lives in `vault.json`, not in a process — so a script
invoked per request is an equally sound deployment. The repo ships a
**single-file PHP implementation** of the same protocol,
[`tools/ccos-license-server/php/claim.php`](../tools/ccos-license-server/php/claim.php)
(PHP ≥ 7.2 for libsodium's ed25519 — bundled by every hoster). Its tokens are
**byte-identical** to the Rust signer's; `php claim.php selftest` proves it
against a Rust-generated vector, so the two implementations cannot drift
silently. It also serves a small **web form** (paste the claim code + the
output of `ccos license fingerprint`) for customers who prefer a browser.

Deployment on a typical shared host (e.g. OVH mutualisé):

```
~/               (your hosting account)
├── ccos-license/          ← OUTSIDE the webroot, never web-served
│   ├── vault.json         ← managed with ccos-license-admin, uploaded via SFTP
│   ├── seed.hex           ← the 64-hex signing seed, single line
│   └── .htaccess          ← copy of php/ccos-license.htaccess (seatbelt)
└── www/                   ← the webroot
    ├── claim.php
    └── .htaccess          ← copy of php/webroot.htaccess (HTTPS + /claim rewrite)
```

The hoster's TLS covers `licensing.memorithm.fr`; the CLI accepts both
`--from https://licensing.memorithm.fr` (with the `/claim` rewrite) and
`--from https://…/claim.php` directly. Concurrency is handled with an
exclusive `flock` around the read-flip-write, and the flip is persisted
(atomic rename) **before** the token is echoed — the same discipline as the
daemon. Manage codes locally with `ccos-license-admin` and upload `vault.json`
over SFTP; don't upload while a customer is mid-claim (at one sale at a time
this is a non-issue, but it is a real race — the daemon variant is the answer
if volume ever makes it one).

### Hardening checklist (shared hosting)

There is no "absolute" security — anyone promising it is selling something.
What exists is **layers**, each of which must fail without giving everything
away. In this design the last layer is structural: even a fully compromised
counter cannot mint licenses your *customers'* binaries accept without the
signing seed, and cannot reach into any deployed runtime (there is no runtime
contact to hijack). Layer the rest:

- **Transport**: HTTPS forced by the webroot `.htaccess`; codes and tokens
  never transit in clear. Responses are `no-store` (no cache, no proxy copy).
- **State isolation**: `ccos-license/` outside the webroot + the deny-all
  `.htaccess` seatbelt inside it. The seed is the one real secret; the vault
  leaks nothing redeemable even if exfiltrated (hashes + labels only).
- **Account hygiene** (the actual attack surface on shared hosting): SFTP/SSH
  only — never FTP (it sends your password in clear); a strong unique hosting
  password + 2FA on the hoster's panel; keep the hoster's PHP version current
  (their panel, one click).
- **Injection surface**: the endpoint parses two fixed-shape hex strings and a
  JSON envelope; everything else is refused with a 400 before touching state.
  No database, no SQL, no file paths from user input, all HTML output escaped.
- **Brute force**: 100-bit codes behind a global per-minute limiter — the math
  is the defense, the limiter is politeness.
- **Blast radius if the seed leaks anyway** (hosting breach): rotate the
  keypair, ship the new public key in the next release, `revoke` nothing —
  deployed customers are untouched, and the leaked seed only signs tokens for
  binaries that still embed the old key. Practice this rotation once so it is
  boring.
- **Backups**: `vault.json` is small — schedule the hoster's backup on
  `ccos-license/` or pull a dated copy after each sale. Losing it strands
  unclaimed codes; leaking it is harmless.
- **The quiet one that matters most**: your *source tree* is the crown jewel,
  not the counter. Licensing gates binaries; it does not protect a public
  repository. Keep the premium repo private, 2FA on GitHub, and treat every
  machine holding the signing seed or a clone as production.

## Customer runbook

```sh
ccos license claim CCOS-XXXXX-XXXXX-XXXXX-XXXXX --from https://licensing.memorithm.fr
ccos doctor        # tier: PRO
```

Input is forgiving (case, dashes, `O/0`, `I/l/1` confusions are folded). The
explicit `--from` is the egress consent for this one call — the ambient
air-gap policy (`CCOS_EGRESS_ALLOW`) is not widened, and the runtime never
phones anywhere afterwards. The token installs to `$CCOS_LICENSE_FILE` or
`~/.config/ccos/license` (mode 0600); fully air-gapped customers can skip the
counter entirely and receive the token out-of-band, exactly as before
([`DEPLOYMENT.md`](DEPLOYMENT.md) §4).

## Updates — the private-repo distribution loop

With the premium repository private, customers receive **binaries**, and
`ccos update` closes the loop with the same trust root as everything else.
A release is two static files — any web space serves them, including the
same shared hosting as the claim counter:

```sh
# vendor, per release:
cargo build --release --features llm,license
CCOS_LICENSE_SIGNING_SEED=<64-hex> ccos-license-admin manifest \
  --version 0.5.0 --binary target/release/ccos \
  --url https://licensing.memorithm.fr/releases/ccos-0.5.0
# upload the binary at that URL + release.manifest next to it

# customer:
ccos update --from https://licensing.memorithm.fr/releases --check   # report only
ccos update --from https://licensing.memorithm.fr/releases --yes     # install
```

What the updater enforces, in order — every refusal announced:

1. **Signature first.** The manifest (`ccos-release.<payload>.<sig>`, the
   scheme tag bound into the signed bytes so tokens and manifests can never
   be replayed for one another) must verify against the vendor key **baked
   into the running binary**. A hijacked mirror or DNS can serve nothing the
   vendor did not sign.
2. **The annual, single-seat gate.** A `tier: "pro"` release requires an
   active license on this machine at update time — expired or wrong-machine
   reads as community, the update is refused with the renewal path, and the
   installed version keeps working (no kill-switch, ever).
3. **Artifact integrity.** The download must match the manifest's SHA-256
   byte-for-byte before anything is written; the install is an atomic rename
   over the running binary, and the new binary is executed (`--version`)
   before success is claimed. Re-certify with `ccos setup` after.

## Threat model, honestly

| scenario | outcome |
|---|---|
| vault stolen from the server | hashes + labels only — nothing redeemable, no keys |
| code intercepted before the customer claims | attacker can bind the seat first → the customer notices at claim (410), vendor `rearm`s after revoking; keep code delivery channels as private as invoices |
| counter compromised | worst case: the **seed** is exposed → attacker can sign tokens for *current* binaries. Mitigation: rotate the keypair and ship the new public key in the next release; deployed customers are unaffected meanwhile. The counter cannot reach into any deployment (no runtime contact). |
| MITM on the claim | TLS at the proxy, plus the client verifies the token against its **baked-in** key and its **own** fingerprint before installing — a wrong token is refused, announced |
| replayed claim | same machine: harmless idempotent re-issue; other machine: 410 |
| brute-forcing codes | 100 bits of entropy behind a global rate limiter — not a real path |
| customer clock rollback | accepted limitation of wall-clock expiry (annual model), as in most commercial software |
| customer with source access | can bake their own key and self-sign — the mechanism protects **distributed binaries** and structures the commercial relationship; it is deliberately not DRM (see `src/license.rs` module docs) |

Design invariants the counter must never break: runtime verification stays
offline; refusals are announced, never silent; the community core is never
gated; and the only secret the counter holds is the signing seed — held in its
environment, never in the vault.
