Sund — Client Pinning Contract

Status: v0.1 (Draft, 2026-07-22)

This is the normative contract a Sund client (sund-client, and thus each Family
Beacon platform — Android, iOS, web) MUST implement to connect to a Sund server
running in pinned-TLS mode. It exists so three independent client implementations
agree exactly, rather than drifting. It describes only the transport-trust layer;
request signing, queues and payload encryption are specified elsewhere. Reference
implementations: `internal/tlsid` (Go server + client) and
`tests/beaconsim/pinning.py` (Python client). Key words MUST / SHOULD / MAY are
used in the RFC 2119 sense.

Background: the PRD (Server address) chooses a SimpleX-style pinning model over
WebPKI. Identity is a pinned public key delivered out of band (the onboarding
QR), not a CA-issued, hostname-bound certificate. This detects a first-connect
man-in-the-middle without a public CA, a domain, or correct DNS.

---

1. The server address

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

4. Client verification algorithm (normative)

On every connection the client MUST:

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

6. Hard requirements (MUST / MUST NOT)

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

8. Alternative deployment (informative)

An operator may instead run Sund as plain HTTP behind a TLS-terminating reverse
proxy using ordinary WebPKI (a public CA and domain). In that mode this contract
does not apply and clients use standard platform TLS verification. Pinned TLS is
the self-host-first default this document specifies; the WebPKI-proxy path is a
supported alternative, not described further here.
