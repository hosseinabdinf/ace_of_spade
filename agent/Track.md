## AoS implementation

- Status: phase 1 complete with Lattigo's 128-bit BGV example parameters (`logN=14`, `logQ≈359`, `t=65537`); AoS stated bound passes with wide margin.
- Status: AoS core and protocol phase complete.
- Complete: scalar `Setup`/`Encrypt`/`KDer`/`Decrypt`, `TokGen`/`Update`, binary ciphertext/token transport, equality/mismatch/wrong-label/wrong-target/update/randomized tests.
- Complete: `schemes/aos/protocol` signed timestamp+nonce envelopes, replay protection, X25519/XChaCha20-Poly1305 label/key delivery, owner/user authorization, curated ciphertext storage and relabeling.
- Complete: core operation benchmarks for setup, encrypt, KDer, decrypt, TokGen, and update in `schemes/aos/aos_benchmark_test.go`.
- Complete: `schemes/aos/README.md` documents parameters, core/update/protocol use, serialization, tests, benchmarks, and security limits.
- Complete: conservative ciphertext noise ledger (`Ciphertext.Updates`, `UpdateChecked`, and decrypt-time bound enforcement) with wire persistence and tests.
- Complete: `BenchmarkFullLifecycleNoise` executes setup, encrypt, update, KDer, decrypt and reports update/noise metrics.
- Complete: ordinary-BGV baseline (`VanillaBGVEquality`) and comparison test confirm identical equality output for the same input.
- Complete: versioned protobuf schema, generated Go bindings, protobuf adapters, and envelope/box/request round-trip tests.
- Complete: decryption scratch reuse and cached CRT reconstruction. `BenchmarkDecrypt` fell from 54.14 ms / 1.245M allocations to 20.98 ms / 32.8k allocations (three-iteration local run).
- Note: core AoS `Setup` pre-provisions owner slots; protocol registration assigns them dynamically but does not expand the system.
- Next: integration/documentation phase and public API review.
- Validation: portable Go 1.25.8 installed under `/tmp/go`; `go test ./schemes/aos/...` passes.
