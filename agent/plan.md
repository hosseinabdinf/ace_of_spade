# AoS Optimization Plan

## [COMPLETE] Decrypt scratch reuse & zero-check optimization
**Status:** Done. `Decrypt2` + `isZeroModT2`: 12.4ms / 2B / 1 alloc (vs 27.8ms / 880KB / 32.8k).
**File:** `schemes/aos/aos.go`

## [COMPLETE] Encrypt optimization via scratch reuse
**Status:** Done. Encrypt2: 38ms / 3.2MB / 40 allocs (vs 45ms / 28.3MB / 248 allocs, 1.2x speed, 8.9x fewer allocs).
**File:** `schemes/aos/aos.go` — scratch: `encryptU`, `encryptE1`…`encryptE3`, `encryptLabelMult`, `encryptNoise1/2`, `encryptAddC1/C2`, `encryptMulUX/AKMult`, `encryptResultC1/C2`, `encryptScalar`, `encryptScratch`, `key*` fields (shared).

## [COMPLETE] KDer optimization via scratch reuse
**Status:** Done. KDer2: 31ms / 3.1MB / 35 allocs (vs 38ms / 23.6MB / 204 allocs, 1.2x speed, 7.5x fewer).
**File:** `schemes/aos/aos.go` — scratch: `keySkDelta`, `keyMulResult`, `keyNoiseScratch`, `keyKeyComp`, `keyE3`.

## [COMPLETE] TokGen optimization via scratch reuse
**Status:** Done. TokGen2: 27ms / 3.1MB / 34 allocs (vs 33ms / 20.5MB / 177 allocs, 1.2x speed, 6.4x fewer).
**File:** `schemes/aos/aos.go` — reuses `encryptE1/E2`, `encryptAddC1`, `encryptMulUX`, `encryptLabelMult`, `encryptNoise2`, `encryptResultC1/C2`.

## [COMPLETE] Update optimization via scratch reuse
**Status:** Done. Update2: same 26 allocs as Update (CopyNew unavoidable for result), 2× Add via scratch. Minimal latency gain.
**File:** `schemes/aos/aos.go` — reuses `encryptResultC1/C2`.

## [COMPLETE] Migrate Encrypt/KDer/TokGen/Update to scratch paths
**Status:** Done. All 4 `*2` functions complete. Benchmarks added to `aos_benchmark_test.go`. All 11 tests pass.

## [IN PROGRESS] Sample sampler caching
**Status:** In progress. `sampleInPlace()` exists (uses in-place NTT) but still allocates `ring.NewSampler(e.prng, ...)` per call.
**Remaining gap:** ~35-40 sampler allocations per Encrypt/KDer/TokGen call.
**Opportunity:** Cache sampler in Engine (`samplerXe`, `samplerTernary`) and reuse per distribution.
**Implementation:** Add cached sampler fields to Engine, initialize in NewEngine, modify sampleInPlace to use cached sampler when distribution matches.

## Notes
- All optimization keeps correctness identical — ring ops are deterministic, scratch is just in-memory buffer reuse.
- Tests run before any benchmark work.
- Portable Go 1.25.8 at `/tmp/go`.
