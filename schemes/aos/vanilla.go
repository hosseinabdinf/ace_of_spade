package aos

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// VanillaBGVEquality is the non-AoS reference: ordinary BGV decrypts every
// value, then performs equality in the clear. It intentionally has no
// selective-decryption property and exists only as a comparison baseline.
func VanillaBGVEquality(params Parameters, values []uint64, target uint64) ([]bool, error) {
	if target >= params.PlaintextModulus() {
		return nil, fmt.Errorf("target %d exceeds plaintext modulus %d", target, params.PlaintextModulus())
	}
	if len(values) > params.MaxSlots() {
		return nil, fmt.Errorf("%d values exceed BGV slot count %d", len(values), params.MaxSlots())
	}
	for i, value := range values {
		if value >= params.PlaintextModulus() {
			return nil, fmt.Errorf("value %d at index %d exceeds plaintext modulus %d", value, i, params.PlaintextModulus())
		}
	}

	keyGenerator := rlwe.NewKeyGenerator(params.Parameters)
	secretKey, publicKey := keyGenerator.GenKeyPairNew()
	encoder := bgv.NewEncoder(params.Parameters)
	plaintext := bgv.NewPlaintext(params.Parameters, params.MaxLevel())
	if err := encoder.Encode(values, plaintext); err != nil {
		return nil, fmt.Errorf("encode vanilla BGV values: %w", err)
	}
	ciphertext, err := bgv.NewEncryptor(params.Parameters, publicKey).EncryptNew(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt vanilla BGV values: %w", err)
	}
	decoded := make([]uint64, len(values))
	if err := encoder.Decode(bgv.NewDecryptor(params.Parameters, secretKey).DecryptNew(ciphertext), decoded); err != nil {
		return nil, fmt.Errorf("decrypt vanilla BGV values: %w", err)
	}
	result := make([]bool, len(values))
	for i, value := range decoded {
		result[i] = value == target
	}
	return result, nil
}
