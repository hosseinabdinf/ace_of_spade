# AoS additions

- `schemes/aos/params.go`: AoS parameters backed by Lattigo BGV exact-integer parameters and noise-bound check.
- `schemes/aos/aos.go`: scalar AoS core, ciphertext updates, pair serialization, and reusable decrypt/CRT scratch.
- `schemes/aos/*_test.go`: core correctness, misuse, update, serialization, and randomized tests.
- `schemes/aos/aos_benchmark_test.go`: core-operation and full-lifecycle noise-tracking benchmarks.
- `schemes/aos/vanilla.go`: ordinary BGV decrypt-then-compare baseline (not selectively private).
- `schemes/aos/vanilla_test.go`: AoS versus vanilla BGV equality-output comparison.
- `proto/aos/v1/protocol.proto`: versioned protobuf wire schema for the AoS protocol.
- `schemes/aos/protocol/pb/protocol.pb.go`: generated official Go protobuf bindings.
- `schemes/aos/protocol/protobuf.go`: validated envelope/box protobuf adapters.
- `schemes/aos/README.md`: scheme and protocol use guide, transport details, and limitations.
- `schemes/aos/protocol/protocol.go`: signed envelope, protected key delivery, curator authorization, storage, and relabeling protocol.
- `schemes/aos/protocol/protocol_test.go`: end-to-end and message-attack coverage.
