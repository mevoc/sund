Sund — Client Pinning Contract

Status: v0.2 (Draft, 2026-07-23)

This is the normative contract a Sund client (sund-client, and thus each Family
Beacon platform — Android, iOS, web) MUST implement to connect to a Sund server.
It exists so three independent client implementations agree exactly, rather than
drifting. It describes only the transport-trust layer; request signing, queues
and payload encryption are specified elsewhere. Reference implementations:
`internal/tlsid` (Go server + client) and `tests/beaconsim/pinning.py` (Python
client). Key words MUST / SHOULD / MAY are used in the RFC 2119 sense.

There are two transport-trust modes, and a client MUST implement both:

- **Pinned mode** (§§1–7) — Sund terminates TLS itself with a self-signed
  certificate; identity is a pinned public key delivered out of band. Needs no
  CA, no domain and no correct DNS.
- **WebPKI mode** (§8) — Sund runs as plain HTTP behind a TLS-terminating
  reverse proxy holding a publicly trusted certificate; identity is the domain
  name, verified normally.

Which mode a deployment uses is the operator's choice and is fixed per server
address (§8.1); the mode is never negotiated at connection time and never
changes without re-pairing (§8.5). Background: the PRD (Server address) chooses
the SimpleX-style pinning model as Sund's self-host default, because it detects
a first-connect man-in-the-middle without a public CA, a domain, or correct DNS.
WebPKI mode exists because some consumers need reachability on port 443 — see
§8.6 — and because browsers cannot implement §4 at all.

---

1. The server address (pinned mode)

A server address is a single string, delivered out of band (QR at onboarding,
implementation guide Walkthrough 1/2):

    sund://<host>:<port>#<fingerprint>

- host — DNS name or IP literal. Identity does NOT depend on it; it is only where
  to connect. The same server reachable at a new host/IP keeps the same pin.
- port — TCP port.
- fingerprint — lowercase hex SHA-256 (64 hex chars) of the server's offline CA
  certificate's SubjectPublicKeyInfo (SPKI), DER-encoded. This is the pin.

Clients MUST store the (host, port, fingerprint) triple durably, associated with
the account, and use the fingerprint for every subsequent connection.

The fragment is REQUIRED under the `sund://` scheme. A `sund://` address with no
fragment, or with a fragment that is not 64 lowercase hex characters, is
malformed and MUST be rejected outright — a client MUST NOT treat it as a
WebPKI address (§8.1 explains why this fails closed).

---

2. What is pinned (exactly)

The pin is `SHA-256( DER(SubjectPublicKeyInfo of the offline CA) )`, hex-encoded,
lowercase.

- It is the CA's public key info, NOT the whole certificate's DER, and NOT the
  leaf. Pinning the SPKI makes the pin stable across certificate re-issuance with
  the same key; pinning the CA (not the leaf) lets the server rotate the leaf
  without re-pairing clients (see §5).
- The fingerprint is public (it travels in the QR). It is not a secret. Security
  comes from (a) out-of-band delivery over a trusted channel — physical
  co-presence — and (b) the server holding the CA private key.

Cross-check: an implementer can confirm their computation matches the server's
`sund cert fingerprint` output with OpenSSL over the CA certificate:

    openssl x509 -in ca.crt -noout -pubkey \
      | openssl pkey -pubin -outform der \
      | openssl dgst -sha256

(HPKP-style tools base64-encode the same digest; Sund hex-encodes it.)

---

3. The server's presentation

On the TLS handshake the server presents a chain of two certificates, leaf first:

    [ leaf (end-entity, serverAuth) , offline CA (self-signed, IsCA) ]

- The leaf is signed by the offline CA, is short-lived and rotatable, and carries
  the serverAuth extended key usage.
- The offline CA is self-signed and long-lived; its SPKI is what clients pin.

A degenerate single-certificate deployment (the leaf is itself the pinned,
self-signed cert) MUST also verify under §4, but the two-layer form above is the
model and the only one Sund generates.

---

4. Client verification algorithm (pinned mode, normative)

On every connection to a `sund://` address the client MUST:

1. Open a TLS 1.2+ connection to host:port. It MAY send SNI = host (ignored by
   the server for certificate selection).
2. Disable the platform's default trust evaluation: do NOT verify against the
   system/WebPKI trust store, and do NOT perform hostname/SAN verification.
   Identity is the pinned key, not a CA chain or a name.
3. Obtain the full certificate chain the server presented.
4. Compute the SPKI SHA-256 of each presented certificate. Select the certificate
   whose fingerprint equals the pinned fingerprint; call it the pinned cert. The
   comparison SHOULD be constant-time.
5. If no presented certificate matches the pin → REJECT the connection
   (this is the MITM case). Do not proceed.
6. Verify the end-entity (leaf) certificate validly chains to the pinned cert,
   using the pinned cert as the sole trust root:
   - signature valid up to the pinned cert;
   - every certificate in the built chain (including the pinned root) is within
     its notBefore/notAfter window at the current time;
   - the leaf asserts the serverAuth extended key usage.
   If verification fails → REJECT.
7. Only if steps 4–6 pass may the client send or receive application data.

Two implementation strategies satisfy this, both used by the reference clients:

- Inline callback: hook the TLS library's certificate-verification callback,
  disable default verification, and run steps 4–6 there. (Go: `InsecureSkipVerify`
  + `VerifyPeerCertificate` — `internal/tlsid.ClientTLSConfig`.)
- Extract-then-trust: connect with verification disabled, read the chain, run
  steps 4–5 to find and confirm the pinned cert, then re-establish (or continue)
  with that cert installed as the only trusted root, letting the platform run a
  normal chain verification (step 6) against it. The pinned cert MAY be cached per
  address. (`tests/beaconsim/pinning.py`, needed because Python 3.12's stdlib ssl
  cannot expose the peer chain.)

Both MUST reach the same accept/reject decision for a given (chain, pin).

---

5. Rotation

- Leaf rotation is transparent. The server may replace its leaf at any time
  (Sund: delete server.crt/server.key). Because clients pin the CA, not the leaf,
  a rotated leaf still verifies and no client action is needed. Clients MUST NOT
  pin the leaf.
- Pin change = re-pairing. The offline CA (and thus the fingerprint) changes only
  on a deliberate re-key: CA private-key compromise, or the CA's own expiry (Sund
  issues a ~10-year CA). A client holding the old pin will correctly REJECT the
  new certificate — it is indistinguishable from a MITM. Recovery is out of band:
  the operator distributes a new `sund://…#newfingerprint` address (new QR) and
  the client re-pins after the user re-verifies it. Clients MUST surface a
  distinct "server identity changed — re-verify" state; they MUST NOT silently
  trust the new key, and MUST NOT offer a one-tap "trust anyway" that trains users
  to click through.
- Leaf expiry forces rotation. Because step 6 checks validity dates, an expired
  leaf is rejected; operators rotate the leaf before it expires. This is a server
  operational concern, not a client one.

---

6. Hard requirements (pinned mode, MUST / MUST NOT)

- MUST reject on pin mismatch; MUST NOT retry the same connection without the pin.
- MUST NOT fall back to WebPKI/system-trust TLS, to an unpinned connection, or to
  plain HTTP if pinned verification fails.
- MUST pin per server identity (the fingerprint), independent of host/IP/DNS.
- MUST store the fingerprint durably and treat a change as §5 re-pairing.
- SHOULD compare fingerprints in constant time (defense-in-depth; the value is
  public, so this is hygiene, not a hard requirement).
- MUST NOT weaken to accept an expired leaf or CA.

---

7. What pinning does and does not protect

Protects:
- First-connect and every-connect MITM: an interceptor cannot present a
  certificate whose chain contains the pinned CA without the CA's private key.
- Removes dependence on the public CA ecosystem and on DNS/hostname correctness.

Does not protect:
- Metadata exposure to the host — that is the blindness model, unaffected by
  pinning. TLS only keeps on-path *network* observers from seeing the metadata a
  host can already see.
- A stolen offline-CA private key. Whoever holds it can mint valid leaves — the
  standard CA-compromise failure. Mitigation is keeping the CA key protected
  (ideally offline where the deployment allows) and re-keying (§5) if it leaks.
- Anything about payload content: payloads are end-to-end encrypted independently
  of the transport; pinned TLS neither adds nor removes that guarantee.

---

8. WebPKI mode (normative)

An operator may instead run Sund as plain HTTP behind a TLS-terminating reverse
proxy holding a publicly trusted certificate. §§2–7 do not apply to such a
deployment; this section replaces them. Everything above the transport —
signed requests, queue authentication, payload encryption — is unchanged and
mode-independent.

8.1 The WebPKI server address

    sund+webpki://<host>[:<port>]

- host — the DNS name. Unlike pinned mode, the host IS the identity: it is what
  the certificate is checked against. An IP literal MUST be rejected.
- port — optional TCP port; default 443 when omitted.
- There is NO fragment. An address under this scheme carrying a fragment is
  malformed and MUST be rejected.

Clients MUST store the (scheme, host, port) triple durably, associated with the
account, and MUST use the stored scheme to select the verification algorithm on
every subsequent connection.

Why a distinct scheme rather than "a `sund://` address with the fingerprint
omitted": that alternative fails open. An attacker who can strip the fragment
from an address before the user scans or types it would silently downgrade a
pinned deployment to one where any certificate from any public CA is accepted —
a downgrade achieved by deletion, the cheapest possible edit. With two explicit
schemes, deleting the fragment from a `sund://` address produces an address that
is malformed under §1 and rejected, and no deletion turns `sund://` into
`sund+webpki://`. Mode is stated, never inferred.

8.2 Client verification algorithm (normative)

On every connection the client MUST:

1. Open a TLS 1.2+ connection to host:port, sending SNI = host.
2. Perform the platform's standard trust evaluation, unmodified: build and
   verify the chain to the platform trust store, enforce validity windows, and
   verify the hostname against the certificate's SAN entries (a match on CN
   alone MUST NOT be accepted).
3. If verification fails for any reason → REJECT. Do not proceed, do not retry
   with verification relaxed.
4. Only if step 2 passes may the client send or receive application data.

This is deliberately "do the normal thing." A client MUST NOT install extra
trust anchors, MUST NOT disable hostname verification, and MUST NOT implement
its own chain-building for this mode. The correct implementation is the
platform's default TLS client with no options changed.

8.3 Hard requirements (MUST / MUST NOT)

- MUST NOT connect over plain HTTP in either mode, and MUST NOT fall back to
  plain HTTP if TLS fails.
- MUST NOT fall back between modes in either direction. A `sund+webpki://`
  address whose verification fails MUST NOT be retried as pinned, and the §6
  prohibition on a pinned address falling back to WebPKI stands unchanged.
- MUST NOT offer a "trust anyway" / "accept invalid certificate" affordance.
  This is the same rule as §5 and matters more here, because certificate errors
  in WebPKI mode are common enough operationally (expiry, renewal failure,
  captive portals) that users learn to click through them.
- MUST reject an IP-literal host under `sund+webpki://` (§8.1).
- SHOULD surface certificate-validation failures as a distinct, explicable
  state ("cannot verify the server's identity") rather than as a generic
  network error, so an intercepting network is distinguishable from an offline
  one.

8.4 What WebPKI mode protects, and what it costs

Compared with pinned mode, this is a weaker trust model, and clients and
consumer products MUST NOT describe it as equivalent:

- Trust widens from one operator-held key to the entire public CA ecosystem:
  any trusted CA can issue a certificate for the domain, so a compromised or
  coerced CA anywhere can mint a working interception certificate. Pinned mode
  has no such class of adversary.
- Identity becomes dependent on DNS. An attacker controlling DNS plus a
  fraudulent certificate is indistinguishable from the real server; under
  pinning, DNS control alone achieves nothing.
- The hostname is published in Certificate Transparency logs, permanently and
  publicly, revealing that the domain runs a service (not what, nor for whom).

What is unchanged: payloads are end-to-end encrypted independently of the
transport, so confidentiality of message content is identical in both modes.
The proxy is an additional component that sees request metadata in clear —
it is inside the trust boundary the operator already occupies (§7, blindness
model), but it is one more place that can log, and operators should keep its
access logging off.

Operators SHOULD publish CAA records restricting which CAs may issue for the
domain. This narrows the first bullet without changing anything client-side.

8.5 Mode changes are re-pairing events

The mode is part of the stored server identity. A client holding a
`sund://…#fingerprint` address MUST NOT accept a `sund+webpki://` address for
the same account, or the reverse, as a silent update: it MUST be treated
exactly as the pin change of §5 — a distinct "server identity changed —
re-verify" state, resolved out of band by the operator distributing a new
address and the user re-verifying it. Migration between modes therefore
re-pairs every device; operators should choose a mode before onboarding a
family, not after.

8.6 Choosing a mode (informative)

Pinned mode is Sund's self-host-first default and the stronger model; prefer it
where it is workable. Two things force WebPKI mode:

- **Browsers.** A browser cannot implement §4 — there is no API to pin, and a
  request to a self-signed origin fails. Any web client requires this mode.
- **Reachability on port 443.** Pinned mode is typically served on a
  non-standard port, which is blocked on many hotel, school, guest and
  corporate networks. A consumer whose value depends on working away from home
  may reasonably weigh this above the trust-model difference — Family Beacon
  does exactly that and recommends WebPKI mode for all of its deployments (see
  `../../family-beacon/ARCHITECTURE.md`, Deployment). Note that serving pinned
  mode on :443 recovers reachability on networks that merely block ports, but
  not on networks that intercept TLS: pinning correctly refuses those, so the
  connection fails rather than silently downgrading.

Sund takes no position on which a given consumer should pick. It specifies both
so the choice is a deployment decision, not a fork in the client.
