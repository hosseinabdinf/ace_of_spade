# AoS Protocol

`schemes/aos/protocol` provides an in-memory trusted-key-curator (KC) protocol
around the Ace of SPADE (AoS) selective partial-decryption scheme.

The protocol coordinates data owners, users, and a curator that owns the AoS
secret material. It authenticates requests, protects private labels and
functional keys, normalizes owner ciphertexts to one common label, and delivers
an equality-test key with the stored ciphertext vector.

This package is a protocol reference implementation for research and
integration tests. It does not provide a network server, persistent database,
session management, or transport framing.

## Participants

- **Data owner**: owns an AoS ciphertext and its private label.
- **User**: requests a functional key for a target value.
- **Key curator (KC)**: owns `aos.System.Secrets` and `aos.System.Helpers`,
  assigns owner slots, updates ciphertext labels, derives functional keys, and
  stores ciphertexts.

Create the AoS system with enough pre-provisioned slots for all owners:

```go
system, err := engine.Setup(ownerCount)
curator, err := protocol.NewCurator(engine, system, time.Minute)
```

`NewCurator` allocates in-memory owner, user, replay, and ciphertext state. Owner
registration consumes one existing `system.Public`/`system.Labels` slot; the
curator does not grow the AoS system dynamically.

## Protocol Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant O as Data Owner
    participant U as User
    participant KC as Key Curator
    participant AOS as AoS Engine/System

    Note over O,U: Each participant creates an Identity
    Note over O,U: Identity has Ed25519 signing and X25519 encryption keys
    KC->>AOS: Setup(ownerCount)
    AOS-->>KC: System secrets, helpers, public keys, labels
    KC->>KC: NewCurator(engine, system, maxAge)

    O->>O: SignEnvelope(owner registration)
    O->>KC: RegisterOwner(ownerID, signed envelope)
    KC->>KC: Verify sender, signature, timestamp, replay nonce
    KC->>KC: Assign pre-provisioned owner slot
    KC->>KC: Seal(slot label, owner's X25519 public key)
    KC-->>O: PublicKey + encrypted label Box
    O->>O: Open Box and keep label private

    U->>U: SignEnvelope(user registration)
    U->>KC: RegisterUser(userID, signed envelope)
    KC->>KC: Verify and authorize user
    KC-->>U: Registration accepted

    O->>AOS: Encrypt(public key, label, plaintext)
    AOS-->>O: Ciphertext
    O->>O: SignEnvelope(store request)
    O->>KC: StoreCiphertext(ownerID, envelope, ciphertext)
    KC->>KC: Verify owner and replay nonce
    KC->>AOS: TokGen(owner label, slot 0 label)
    AOS-->>KC: Update token
    KC->>AOS: UpdateChecked(token, ciphertext)
    AOS-->>KC: Normalized ciphertext
    KC->>KC: Store ciphertext in owner slot

    U->>U: SignEnvelope(target request)
    U->>KC: DeliverFunctionalKey(userID, envelope, target)
    KC->>KC: Verify user identity, signature, time, replay nonce
    KC->>KC: Require ciphertext in every owner slot
    KC->>AOS: KDer(system, slot 0, target)
    AOS-->>KC: Functional key
    KC->>KC: Marshal key and seal to user's X25519 public key
    KC-->>U: Encrypted functional-key Box + ciphertext vector
    U->>U: Open Box; unmarshal FunctionalKey
    U->>AOS: Decrypt(functional key, ciphertext vector)
    AOS-->>U: Boolean equality results
```

## Authentication and replay protection

`Identity` contains two independent key pairs:

- Ed25519 for signing protocol messages.
- X25519 for protected delivery boxes.

Create an identity with `NewIdentity` and sign every request with:

```go
envelope, err := protocol.SignEnvelope(identity, payload, time.Now())
```

`Envelope.Verify` checks:

1. Sender matches the expected registered Ed25519 public key.
2. Ed25519 signature covers timestamp, nonce, and payload.
3. Timestamp is within `[-maxAge, +maxAge]` of the curator clock.

The curator additionally hashes sender and nonce and rejects a nonce reused by
the same authenticated request stream. All registration, storage, and key
delivery operations pass through this validation.

## Protected delivery boxes

`Seal` and `Open` protect labels and functional keys:

1. `Seal` generates an ephemeral X25519 key pair.
2. Ephemeral ECDH derives a shared secret with the recipient.
3. The shared secret derives an XChaCha20-Poly1305 key.
4. The payload is encrypted with a fresh 24-byte nonce and protocol domain
   separation.

The box contains only the ephemeral public key, nonce, and ciphertext. Use
`Open` only with the intended recipient's `Identity`.

## Main curator operations

| Operation | Authenticated sender | Result |
|---|---|---|
| `RegisterOwner` | Owner | Assigns a slot; returns public key and encrypted private label |
| `RegisterUser` | User | Authorizes future key delivery |
| `StoreCiphertext` | Registered owner | Relabels ciphertext to slot 0 and stores it |
| `DeliverFunctionalKey` | Registered user | Returns encrypted functional key and ciphertext vector |

### Owner registration

`RegisterOwner` verifies the signed request, assigns the next free AoS slot,
encrypts that slot's label to the owner, and returns the matching public key.
The label must remain private to the owner.

### Ciphertext storage

`StoreCiphertext` verifies the registered owner's request, generates a token from
the owner's assigned label to `system.Labels[0]`, and calls `UpdateChecked`.
This normalization lets one functional key derived for slot 0 operate over the
complete stored vector. Updates consume noise budget; rejected updates must be
handled by re-encrypting or choosing a parameter/noise plan with more headroom.

### Functional-key delivery

`DeliverFunctionalKey` verifies the registered user's identity and request,
requires every pre-provisioned owner slot to contain a ciphertext, derives
`KDer(system, 0, target)`, serializes the functional key, and encrypts it to the
user. The returned ciphertext slice is a copy of the curator's stored vector.

## Protobuf wire format

The versioned schema is
[`proto/aos/v1/protocol.proto`](../../../proto/aos/v1/protocol.proto).

It defines:

- `Envelope`: timestamp, 24-byte nonce, payload, Ed25519 sender, signature.
- `Box`: ephemeral X25519 public key, nonce, ciphertext.
- `OwnerRegistrationRequest`.
- `UserRegistrationRequest`.
- `StoreCiphertextRequest`.
- `FunctionalKeyRequest`.
- `FunctionalKeyDelivery`.

Use the adapters in `protobuf.go` for structural validation and canonical
protobuf encoding:

```go
wire, err := protocol.MarshalEnvelope(envelope)
received, err := protocol.UnmarshalEnvelope(wire)
if err != nil {
    log.Fatal(err)
}
if err := received.Verify(identity.SignPublic, time.Now(), time.Minute); err != nil {
    log.Fatal(err)
}
```

`UnmarshalEnvelope` validates field sizes but does not authenticate the message;
call `Verify` before acting on its payload. The same distinction applies to
`UnmarshalBox` and `Open`.

Generate protobuf bindings with Buf when development tools are installed:

```sh
buf lint
buf generate
```

## Security boundaries and limitations

- Keep `System.Secrets` and `System.Helpers` inside the KC trust boundary.
- Never expose owner labels outside their intended owner or protected delivery
  channel.
- Authenticate and replay-check envelopes before processing payloads.
- `Curator` state is in memory and is not durable.
- `Curator` has no network listener or transport security layer; deployments
  must provide authenticated transport and request framing.
- The implementation uses pre-provisioned owner slots. Owner registration
  beyond `len(system.Public)` fails.
- `Engine` is not safe for concurrent use; serialize calls or use one engine per
  worker.
- Ciphertext updates add noise. `UpdateChecked` is a conservative guardrail,
  not a replacement for a complete scheme-specific noise proof.

## Tests

From repository root:

```sh
go test ./schemes/aos/protocol/...
```

Coverage includes end-to-end registration/storage/delivery, tamper rejection,
stale timestamps, replay rejection, and protobuf round trips.
