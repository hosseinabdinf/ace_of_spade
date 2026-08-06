# Ace of SPADE (AoS)

This repository implements the Ace of SPADE (AoS) selective partial-decryption
scheme in Go. AoS uses Lattigo's exact-modulus RLWE infrastructure and ring
arithmetic as its cryptographic foundation.

AoS lets a user test whether encrypted scalar values equal a chosen target
without revealing the underlying plaintext values. It also supports ciphertext
updates: a trusted key curator can change a ciphertext's label without
decrypting or re-encrypting it.

This is a research and integration implementation, not a production-ready
encrypted-data service.

## What is included

- AoS core scheme in [`schemes/aos`](schemes/aos)
- Selective equality decryption over ciphertext vectors
- Ciphertext relabeling with update tokens
- Conservative ciphertext-noise tracking and update limits
- Signed, replay-protected curator protocol in
  [`schemes/aos/protocol`](schemes/aos/protocol)
- Versioned protobuf schema in
  [`proto/aos/v1/protocol.proto`](proto/aos/v1/protocol.proto)
- Benchmarks for the core lifecycle and optimized `*2` operations
- Ordinary BGV comparison baseline for correctness checks

## Lattigo foundation

AoS is built on Lattigo packages, including:

- `ring` for polynomial arithmetic, NTT operations, and sampling
- `core/rlwe` for RLWE elements and cryptographic primitives
- `schemes/bgv` for exact-modulus parameter references

AoS does not use CKKS bootstrapping. Its current starting parameters wrap
Lattigo's `bgv.ExampleParameters128BitLogN14LogQP438` set.

## Quick start

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
	engine, err := aos.NewEngine(params)
	if err != nil {
		log.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		log.Fatal(err)
	}

	first, _ := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	second, _ := engine.Encrypt(system.Public[1], system.Labels[0], 7)
	key, _ := engine.KDer(system, 0, 42)
	matches, err := engine.Decrypt(key, []aos.Ciphertext{first, second})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matches) // [true false]
}
```

`Engine` owns mutable sampling and scratch state and is not safe for concurrent
use. Use one engine per concurrent worker or serialize calls. Keep
`System.Secrets` and `System.Helpers` private to the key curator.

See [`schemes/aos/README.md`](schemes/aos/README.md) for the complete core API,
protocol flow, serialization, parameters, security limits, and protobuf usage.

## Tests and benchmarks

From repository root:

```sh
go test ./schemes/aos/...
go test ./schemes/aos/... -run '^$' -bench . -benchmem
```

## Project status

AoS core and protocol implementations are complete. Current work focuses on
integration, public API review, and reducing sampler allocations through cached
samplers in `Engine`.

## Relationship to Lattigo

This project is based on the Lattigo codebase and retains Lattigo's module
structure and upstream dependencies. Lattigo provides the underlying
lattice-based cryptographic components; AoS adds the selective
partial-decryption scheme and its protocol layer.

See [Lattigo](https://github.com/tuneinsight/lattigo) for the upstream project.

## License

This project retains the upstream Lattigo Apache 2.0 license. See
[`LICENSE`](LICENSE).
