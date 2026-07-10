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
