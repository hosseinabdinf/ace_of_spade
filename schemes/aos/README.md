# Ace of SPADE (AoS)

This package implements the Ace of SPADE selective partial-decryption scheme
over Lattigo's exact-modulus RLWE ring. AoS lets a user test whether encrypted
scalar values equal a chosen target without learning any other value.

The implementation is a scalar reference implementation. It is intended for
research, integration experiments, and validation of the construction; it is
not yet a production-ready encrypted-data service.

## What it does

For a target `v` and ciphertext vector `(ct_0, ..., ct_n)`, a functional key
returns one boolean per ciphertext:

```text
Decrypt(fk_v, ct_i) == true  iff  plaintext(ct_i) == v
```

The key does not reveal a matching plaintext beyond the equality result. Each
ciphertext contains an owner-specific public-key component and a private
label. A trusted key curator (KC) derives functional keys and, if needed,
updates a ciphertext from one label to another without decrypting it.

## Parameters

Use `ExampleParameters128Bit` for the current starting point:

```go
params, err := aos.ExampleParameters128Bit()
```

It wraps Lattigo's `bgv.ExampleParameters128BitLogN14LogQP438` parameters,
whose plaintext modulus is `65537`. AoS plaintext values and equality targets
must be in `[1, 65537)`; encryption also allows zero.

`Parameters.NoiseBoundSatisfied()` evaluates the bound stated in the AoS
specification. The small parameter row in that specification is not safe for
that bound; do not use it unchanged.

## Core API

`Engine` owns cryptographic sampling state. It is **not safe for concurrent
use**. Give each concurrent worker its own engine or serialize calls.

```go
package main

import (
    "fmt"
    "log"

    "github.com/tuneinsight/lattigo/v6/schemes/aos"
)

func main() {
    params, err := aos.ExampleParameters128Bit()
    if err != nil {
        log.Fatal(err)
    }
    if !params.NoiseBoundSatisfied() {
        log.Fatal("AoS noise bound is not satisfied")
    }

    engine, err := aos.NewEngine(params)
    if err != nil {
        log.Fatal(err)
    }
    system, err := engine.Setup(2) // trusted KC setup for two ciphertext slots
    if err != nil {
        log.Fatal(err)
    }

    // Ciphertexts in one query vector must share the functional key's label.
    first, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
    if err != nil {
        log.Fatal(err)
    }
    second, err := engine.Encrypt(system.Public[1], system.Labels[0], 7)
    if err != nil {
        log.Fatal(err)
    }

    // KC derives a key for the query "equals 42" under label slot 0.
    key, err := engine.KDer(system, 0, 42)
    if err != nil {
        log.Fatal(err)
    }
    matches, err := engine.Decrypt(key, []aos.Ciphertext{first, second})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(matches) // [true false]
}
```

`System.Secrets` and `System.Helpers` are KC-only material. Do not send them
to data owners, users, or untrusted storage. `System.Public` can be given to
the corresponding data owner. A `Label` is private and must only reach its
owner over protected transport.

## Ciphertext updates

The KC can move a ciphertext to a new label. Generate one token with the
public key that created that ciphertext, then update it:

```go
token, err := engine.TokGen(system.Public[0], system.Labels[0], system.Labels[1])
if err != nil {
    log.Fatal(err)
}
updated := engine.Update(token, first)

key, err := engine.KDer(system, 1, 42) // key now uses label slot 1
if err != nil {
    log.Fatal(err)
}
matches, err := engine.Decrypt(key, []aos.Ciphertext{updated})
if err != nil {
    log.Fatal(err)
}
```

For a multi-owner vector, generate a token for each ciphertext's originating
public key, normalize all ciphertexts to one target label, then call `KDer`
for that label. The protocol package does this automatically when storing an
owner ciphertext.

Updates add noise. This implementation does not bootstrap or refresh
ciphertexts, so applications must set and enforce a maximum update count from
their chosen parameter/noise analysis.

Every `Ciphertext` carries an `Updates` counter. `Update` increments it and
`UpdateChecked` rejects a relabeling operation if the package's conservative
linear accumulated-noise bound would exceed `Q/2`. `Decrypt` also refuses a
ciphertext whose recorded count fails that check. Use `UpdateChecked` at
service boundaries:

```go
updated, err := engine.UpdateChecked(token, ciphertext)
if err != nil {
    // Re-encrypt or use a parameter set/noise plan with more headroom.
    log.Fatal(err)
}
```

`Parameters.LogNoiseBoundAfter(updates)` and
`Parameters.NoiseBoundSatisfiedAfter(updates)` expose the ledger calculation.
It charges each update linearly and is deliberately conservative; it is a
runtime guardrail, not a substitute for a scheme-specific noise proof.

## Protocol package

`schemes/aos/protocol` supplies an in-memory KC/data-owner/user flow:

- Ed25519 signed envelopes bind timestamp, random nonce, and payload.
- KC rejects invalid, stale/future, or replayed envelopes.
- X25519 plus XChaCha20-Poly1305 protects owner labels and delivered
  functional keys.
- A registered owner uploads a ciphertext; KC relabels it to a common stored
  label.
- A registered user requests a target; KC delivers the encrypted functional
  key and stored ciphertext vector.

Minimal flow:

```go
owner, _ := protocol.NewIdentity()
user, _ := protocol.NewIdentity()
curator, _ := protocol.NewCurator(engine, system, time.Minute)

registration, _ := protocol.SignEnvelope(owner, []byte("owner registration"), time.Now())
publicKey, labelBox, err := curator.RegisterOwner("owner-0", owner, registration, time.Now())
// Owner opens labelBox with protocol.Open(owner, labelBox), decodes aos.Label,
// and calls engine.Encrypt(publicKey, label, value).

registration, _ = protocol.SignEnvelope(user, []byte("user registration"), time.Now())
err = curator.RegisterUser("user-0", user, registration, time.Now())

// Owner signs StoreCiphertext. User signs DeliverFunctionalKey, opens its Box,
// decodes aos.FunctionalKey, then calls engine.Decrypt on returned ciphertexts.
```

See `protocol/protocol_test.go` for a complete, checked end-to-end example.
`NewCurator` uses the slots created by `Setup`: owner registration assigns a
free slot but does not dynamically enlarge the AoS system.

## Vanilla BGV comparison baseline

`VanillaBGVEquality(params, values, target)` is an ordinary BGV comparison
baseline. It encrypts the vector with normal BGV, decrypts every value, then
compares them in the clear. Its boolean output matches AoS for the same input,
but it does **not** preserve AoS's selective-decryption property.

`TestAoSMatchesVanillaBGV` checks both paths using `values=[42, 7]` and
`target=42`; both output `[true false]`.

## Serialization

The following types have binary transport methods:

- `Ciphertext`
- `UpdateToken`
- `Label`
- `FunctionalKey`

Decode methods take `aos.Parameters`, for example:

```go
encoded, err := ciphertext.MarshalBinary()
var restored aos.Ciphertext
err = restored.UnmarshalBinary(encoded, params)
```

The bytes are parameter-bound operational encodings, not a stable long-term
cross-version protocol. Envelope and box objects are in-memory Go structures;
a network service still needs an explicit versioned wire schema.

## Protobuf wire protocol

The ready-to-use protobuf schema is
[`proto/aos/v1/protocol.proto`](../../proto/aos/v1/protocol.proto). Generated
Go bindings are in `protocol/pb`. It defines signed envelopes, protected boxes,
owner/user registration, ciphertext storage, functional-key requests, and
functional-key delivery.

Use the protocol adapters for signed/encrypted fields rather than manually
copying their byte fields:

```go
wire, err := protocol.MarshalEnvelope(envelope)
received, err := protocol.UnmarshalEnvelope(wire)
err = received.Verify(expectedSigner, time.Now(), time.Minute)

wire, err = protocol.MarshalBox(box)
receivedBox, err := protocol.UnmarshalBox(wire)
plaintext, err := protocol.Open(identity, receivedBox)
```

For `StoreCiphertextRequest`, set `ciphertext` to
`aos.Ciphertext.MarshalBinary()` output. For delivery, each protobuf
`ciphertexts` entry is the same ciphertext binary encoding. A receiver must
structurally decode, verify signatures, validate authorization/replay state,
and only then act on a request.

The repository uses Buf generation. With `buf` and `protoc-gen-go` installed:

```sh
buf lint
buf generate
```

Generated bindings use the official `google.golang.org/protobuf` runtime.

## Run tests and benchmarks

From repository root:

```sh
go test ./schemes/aos/...
go test ./schemes/aos/protocol -run 'TestProtobuf' -v
go test ./schemes/aos -run '^TestAoSMatchesVanillaBGV$' -v
go test ./schemes/aos -run '^$' -bench . -benchmem
go test ./schemes/aos -run '^$' -bench '^BenchmarkFullLifecycleNoise$' -benchtime=1x -benchmem
```

Benchmarks cover setup, encryption, key derivation, selective decryption,
token generation, and updating. `BenchmarkFullLifecycleNoise` runs setup,
two encryptions, relabeling, KDer, and decryption as one checked flow. It
reports `updates/op` and the final conservative `noise-log2` ledger metric.
Current decryption uses a bigint-based coefficient check and is intentionally
simple rather than allocation-optimal.

## Current limitations and security notes

- Scalar plaintexts only; there is no BGV batching/encoder API.
- The KC is trusted and holds secret/helper material.
- No persistence, network service, authorization policy engine, revocation,
  audit log, or concurrent curator wrapper yet.
- No bootstrap/refresh path. CKKS bootstrapping in Lattigo is not compatible
  with this exact-modulus AoS construction.
- Use authenticated encrypted channels and retain replay state durably in a
  real deployment. The in-memory curator loses replay history on restart.
- Have independent cryptographic review before protecting sensitive data.
