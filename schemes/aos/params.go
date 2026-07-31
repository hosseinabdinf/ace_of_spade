// Package aos implements Ace of SPADE selective partial decryption.
package aos

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Parameters wraps the exact-integer BGV parameter backend used by AoS.
// AoS uses its ring arithmetic directly; it does not use BGV encryption.
type Parameters struct {
	bgv.Parameters
}

// NewParameters validates that params provide the discrete Gaussian required by AoS.
func NewParameters(params bgv.Parameters) (Parameters, error) {
	if _, ok := params.Xe().(ring.DiscreteGaussian); !ok {
		return Parameters{}, fmt.Errorf("aos requires a discrete Gaussian error distribution, got %T", params.Xe())
	}
	return Parameters{Parameters: params}, nil
}

// NewParametersFromLiteral creates AoS parameters from a BGV parameter literal.
func NewParametersFromLiteral(literal bgv.ParametersLiteral) (Parameters, error) {
	params, err := bgv.NewParametersFromLiteral(literal)
	if err != nil {
		return Parameters{}, err
	}
	return NewParameters(params)
}

// LogNoiseBound returns log2 of the match-case variance bound specified in §2.6.
func (p Parameters) LogNoiseBound() float64 {
	xe := p.Xe().(ring.DiscreteGaussian)
	t := float64(p.PlaintextModulus())
	n := float64(p.N())
	return math.Log2(t * t * xe.Sigma * xe.Sigma * (4*n/3 + 2 + t*t/6))
}

// NoiseBoundSatisfied reports whether the AoS §2.6 bound is below q/2.
func (p Parameters) NoiseBoundSatisfied() bool {
	return p.NoiseBoundSatisfiedAfter(0)
}

// LogNoiseBoundAfter returns a conservative log2 noise bound after updates.
// Each update is charged linearly; this deliberately overestimates accumulated
// independent error and is a guardrail, not a tight cryptographic analysis.
func (p Parameters) LogNoiseBoundAfter(updates uint64) float64 {
	return p.LogNoiseBound() + math.Log2(float64(updates)+1)
}

// NoiseBoundSatisfiedAfter reports whether the conservative bound remains
// below Q/2 after updates ciphertext relabeling operations.
func (p Parameters) NoiseBoundSatisfiedAfter(updates uint64) bool {
	return p.LogNoiseBoundAfter(updates) < float64(p.RingQ().ModulusAtLevel[p.MaxLevel()].BitLen()-1)
}

// ExampleParameters128Bit uses Lattigo's documented 128-bit BGV example set.
func ExampleParameters128Bit() (Parameters, error) {
	return NewParametersFromLiteral(bgv.ExampleParameters128BitLogN14LogQP438)
}
