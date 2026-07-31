## AoS

- Lattigo fit: custom `schemes/aos` over `ring` and `core/rlwe`; BGV supplies exact-modulus references, CKKS bootstrap is incompatible.
- Spec concern: Small (`n=4096`, `q=2^39`, `t=2^16`) violates §2.6 stated inequality by ~1.145e+08 for σ=3.2. Do not claim recommended sets valid until source formula or parameters are corrected.
- Use `bgv.ExampleParameters128BitLogN14LogQP438` for initial AoS work: `log2(lhs)≈64.77`, while `log2(Q/2)≈358` under the spec's bound.
- Core API currently accepts scalar plaintexts and uses shared label across a multi-client ciphertext vector, matching the AoS correctness condition.
- `TokGen` derives one update token per ciphertext public key; a vector update uses matching per-slot tokens before KDer under target label.
- Core test phase passes with portable Go 1.25.8: `GOCACHE=/tmp/aos-go-build GOMODCACHE=/tmp/aos-go-mod /tmp/go/bin/go test ./schemes/aos`.
- Protocol phase: `schemes/aos/protocol` authenticates curator requests with Ed25519 envelopes (timestamp+nonce+payload), keeps nonce replay state, encrypts labels and functional keys using X25519 plus XChaCha20-Poly1305, and relabels stored owner ciphertexts to slot 0 before deriving one vector key.
- Protocol limitation: owners are dynamically assigned to slots created by `Setup`; growing the owner population needs a future core lifecycle design.
- Noise tracking: ciphertexts persist an `Updates` count. `Parameters.NoiseBoundSatisfiedAfter` uses a deliberately conservative linear update charge; `UpdateChecked` and `Decrypt` enforce it. This is a guardrail, not a full tight noise analysis.
- Decrypt performance: `Engine` caches NTT polynomials and CRT factors. Equality zero-check reconstructs one coefficient at a time with reusable `big.Int` scratch; preserves centered modular semantics while avoiding `PolyToBigintCentered`'s per-call allocations. Engine remains intentionally non-concurrent.
