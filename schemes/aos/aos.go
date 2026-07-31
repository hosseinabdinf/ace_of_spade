package aos

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Engine owns sampling state for AoS operations. It is not safe for concurrent use.
type Engine struct {
	params Parameters
	prng   sampling.PRNG

	// Decrypt scratch is owned by the engine. Engine is intentionally not safe
	// for concurrent use, so this avoids allocating full ring polynomials and
	// big integers for every ciphertext decryption.
	decryptValue  ring.Poly
	decryptLeft   ring.Poly
	decryptRight  ring.Poly
	decryptCoeffs ring.Poly
	plaintextMod  big.Int
	decryptQ      big.Int
	decryptQHalf  big.Int
	decryptCRT    []*big.Int
	decryptAccum  big.Int
	decryptTmp    big.Int
}

// NewEngine creates an AoS engine using cryptographically secure randomness.
func NewEngine(params Parameters) (*Engine, error) {
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, fmt.Errorf("create AoS PRNG: %w", err)
	}
	ringQ := params.RingQ()
	decryptQ := new(big.Int).Set(ringQ.ModulusAtLevel[params.MaxLevel()])
	decryptCRT := make([]*big.Int, len(ringQ.SubRings))
	modulus := new(big.Int)
	for i, subring := range ringQ.SubRings {
		modulus.SetUint64(subring.Modulus)
		factor := new(big.Int).Quo(decryptQ, modulus)
		inverse := new(big.Int).ModInverse(factor, modulus)
		decryptCRT[i] = factor.Mul(factor, inverse)
	}
	decryptQHalf := new(big.Int).Rsh(new(big.Int).Set(decryptQ), 1)
	return &Engine{
		params:        params,
		prng:          prng,
		decryptValue:  ringQ.NewPoly(),
		decryptLeft:   ringQ.NewPoly(),
		decryptRight:  ringQ.NewPoly(),
		decryptCoeffs: ringQ.NewPoly(),
		plaintextMod:  *new(big.Int).SetUint64(params.PlaintextModulus()),
		decryptQ:      *decryptQ,
		decryptQHalf:  *decryptQHalf,
		decryptCRT:    decryptCRT,
	}, nil
}

// SecretKey is an AoS client secret key. Value is stored in NTT form.
type SecretKey struct{ Value ring.Poly }

// PublicKey is an AoS client public key. Its polynomials are stored in NTT form.
type PublicKey struct {
	A ring.Poly
	B ring.Poly
}

// Label is a private client identifier used to bind ciphertexts and functional keys.
type Label struct{ Value ring.Poly }

// MarshalBinary serializes a label for confidential transport.
func (label Label) MarshalBinary() ([]byte, error) {
	return label.Value.MarshalBinary()
}

// UnmarshalBinary restores a label serialized by MarshalBinary.
func (label *Label) UnmarshalBinary(data []byte, params Parameters) error {
	value, err := unmarshalPoly(data, params)
	if err != nil {
		return fmt.Errorf("decode label: %w", err)
	}
	label.Value = value
	return nil
}

// HelperKey is key-curator material bound to one Label.
type HelperKey struct{ Value ring.Poly }

// Ciphertext is an AoS ciphertext pair.
type Ciphertext struct {
	C1      ring.Poly
	C2      ring.Poly
	Updates uint64
}

// MarshalBinary serializes a ciphertext for transport or storage.
func (ct Ciphertext) MarshalBinary() ([]byte, error) {
	pair, err := marshalPair(ct.C1, ct.C2)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 12, 12+len(pair))
	copy(data[:4], "AOSC")
	binary.BigEndian.PutUint64(data[4:12], ct.Updates)
	return append(data, pair...), nil
}

// UnmarshalBinary restores a ciphertext serialized by MarshalBinary.
func (ct *Ciphertext) UnmarshalBinary(data []byte, params Parameters) error {
	updates := uint64(0)
	if len(data) >= 12 && string(data[:4]) == "AOSC" {
		updates = binary.BigEndian.Uint64(data[4:12])
		data = data[12:]
	}
	c1, c2, err := unmarshalPair(data, params)
	if err != nil {
		return err
	}
	ct.C1, ct.C2, ct.Updates = c1, c2, updates
	return nil
}

// UpdateToken relabels one ciphertext without exposing its plaintext.
type UpdateToken struct {
	C1 ring.Poly
	C2 ring.Poly
}

// MarshalBinary serializes an update token for transport or storage.
func (token UpdateToken) MarshalBinary() ([]byte, error) {
	return marshalPair(token.C1, token.C2)
}

// UnmarshalBinary restores an update token serialized by MarshalBinary.
func (token *UpdateToken) UnmarshalBinary(data []byte, params Parameters) error {
	c1, c2, err := unmarshalPair(data, params)
	if err != nil {
		return err
	}
	token.C1, token.C2 = c1, c2
	return nil
}

// FunctionalKey selectively decrypts only equality with Target.
type FunctionalKey struct {
	Target     uint64
	Components []ring.Poly
}

// MarshalBinary serializes a functional key for protected delivery to a user.
func (key FunctionalKey) MarshalBinary() ([]byte, error) {
	if len(key.Components) > int(^uint32(0)) {
		return nil, fmt.Errorf("too many functional key components: %d", len(key.Components))
	}
	polySize := 0
	encoded := make([][]byte, len(key.Components))
	for i, component := range key.Components {
		data, err := component.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode functional key component %d: %w", i, err)
		}
		if i == 0 {
			polySize = len(data)
		} else if len(data) != polySize {
			return nil, fmt.Errorf("functional key component %d has incompatible size", i)
		}
		encoded[i] = data
	}
	data := make([]byte, 12, 12+len(encoded)*polySize)
	binary.BigEndian.PutUint64(data[:8], key.Target)
	binary.BigEndian.PutUint32(data[8:12], uint32(len(encoded)))
	for _, component := range encoded {
		data = append(data, component...)
	}
	return data, nil
}

// UnmarshalBinary restores a functional key serialized by MarshalBinary.
func (key *FunctionalKey) UnmarshalBinary(data []byte, params Parameters) error {
	if len(data) < 12 {
		return fmt.Errorf("invalid serialized functional key length %d", len(data))
	}
	target := binary.BigEndian.Uint64(data[:8])
	if target == 0 || target >= params.PlaintextModulus() {
		return fmt.Errorf("functional key target must be in [1, %d)", params.PlaintextModulus())
	}
	count := int(binary.BigEndian.Uint32(data[8:12]))
	polySize := params.RingQ().NewPoly().BinarySize()
	if count > (len(data)-12)/polySize || len(data) != 12+count*polySize {
		return fmt.Errorf("invalid serialized functional key component length")
	}
	components := make([]ring.Poly, count)
	for i := range components {
		component, err := unmarshalPoly(data[12+i*polySize:12+(i+1)*polySize], params)
		if err != nil {
			return fmt.Errorf("decode functional key component %d: %w", i, err)
		}
		components[i] = component
	}
	key.Target, key.Components = target, components
	return nil
}

// System contains key-curator state created by Setup. Secret and Helpers stay at KC.
type System struct {
	Params  Parameters
	Secrets []SecretKey
	Public  []PublicKey
	Labels  []Label
	Helpers []HelperKey
}

// Setup creates one AoS key pair, label, and helper key for each client.
func (e *Engine) Setup(clients int) (*System, error) {
	if clients < 1 {
		return nil, fmt.Errorf("clients must be positive")
	}

	system := &System{
		Params:  e.params,
		Secrets: make([]SecretKey, clients),
		Public:  make([]PublicKey, clients),
		Labels:  make([]Label, clients),
		Helpers: make([]HelperKey, clients),
	}

	a, err := e.sample(ring.Uniform{})
	if err != nil {
		return nil, err
	}

	for i := 0; i < clients; i++ {
		sk, err := e.sample(ring.Ternary{P: 2.0 / 3.0})
		if err != nil {
			return nil, err
		}
		label, err := e.sample(ring.Ternary{P: 2.0 / 3.0})
		if err != nil {
			return nil, err
		}
		e0, err := e.sample(e.params.Xe())
		if err != nil {
			return nil, err
		}
		eLabel, err := e.sample(e.params.Xe())
		if err != nil {
			return nil, err
		}

		b := e.sub(e.scaleNoise(e0), e.mul(a, sk))
		helper := e.add(e.mul(a, label), e.scaleNoise(eLabel))

		system.Secrets[i] = SecretKey{Value: sk}
		system.Public[i] = PublicKey{A: *a.CopyNew(), B: b}
		system.Labels[i] = Label{Value: label}
		system.Helpers[i] = HelperKey{Value: helper}
	}
	return system, nil
}

// Encrypt encrypts one scalar value under public key and private label.
func (e *Engine) Encrypt(pk PublicKey, label Label, value uint64) (Ciphertext, error) {
	if value >= e.params.PlaintextModulus() {
		return Ciphertext{}, fmt.Errorf("value %d exceeds plaintext modulus %d", value, e.params.PlaintextModulus())
	}
	u, err := e.sample(ring.Ternary{P: 2.0 / 3.0})
	if err != nil {
		return Ciphertext{}, err
	}
	e1, err := e.sample(e.params.Xe())
	if err != nil {
		return Ciphertext{}, err
	}
	e2, err := e.sample(e.params.Xe())
	if err != nil {
		return Ciphertext{}, err
	}

	x := e.scalar(value)
	c1 := e.add(e.add(e.mul(pk.B, label.Value), e.scaleNoise(e1)), e.mul(u, x))
	c2 := e.sub(e.add(e.mul(pk.A, label.Value), e.scaleNoise(e2)), u)
	return Ciphertext{C1: c1, C2: c2}, nil
}

// KDer derives a functional key for target on behalf of one registered client.
func (e *Engine) KDer(system *System, requester int, target uint64) (FunctionalKey, error) {
	if requester < 0 || requester >= len(system.Helpers) {
		return FunctionalKey{}, fmt.Errorf("requester index %d out of range", requester)
	}
	if target == 0 || target >= e.params.PlaintextModulus() {
		return FunctionalKey{}, fmt.Errorf("target must be in [1, %d)", e.params.PlaintextModulus())
	}

	v := e.scalar(target)
	key := FunctionalKey{Target: target, Components: make([]ring.Poly, len(system.Secrets))}
	for i, sk := range system.Secrets {
		e3, err := e.sample(e.params.Xe())
		if err != nil {
			return FunctionalKey{}, err
		}
		key.Components[i] = e.add(e.mul(system.Helpers[requester].Value, e.sub(sk.Value, v)), e.scaleNoise(e3))
	}
	return key, nil
}

// Decrypt returns equality bits for ciphertext vector. Each ciphertext must use key's label.
func (e *Engine) Decrypt(key FunctionalKey, ciphertexts []Ciphertext) ([]bool, error) {
	if len(key.Components) != len(ciphertexts) {
		return nil, fmt.Errorf("functional key has %d components for %d ciphertexts", len(key.Components), len(ciphertexts))
	}
	e.scalarInto(key.Target, e.decryptValue)
	result := make([]bool, len(ciphertexts))
	for i, ct := range ciphertexts {
		if !e.params.NoiseBoundSatisfiedAfter(ct.Updates) {
			return nil, fmt.Errorf("ciphertext %d has %d updates and exceeds conservative noise bound", i, ct.Updates)
		}
		ringQ := e.params.RingQ()
		ringQ.Add(ct.C1, key.Components[i], e.decryptLeft)
		ringQ.MulCoeffsBarrett(e.decryptValue, ct.C2, e.decryptRight)
		ringQ.Add(e.decryptLeft, e.decryptRight, e.decryptLeft)
		result[i] = e.isZeroModT(e.decryptLeft)
	}
	return result, nil
}

// TokGen creates a token that changes a ciphertext label from source to target.
// It is intended for the trusted key curator, which controls public-key binding.
func (e *Engine) TokGen(pk PublicKey, source, target Label) (UpdateToken, error) {
	e1, err := e.sample(e.params.Xe())
	if err != nil {
		return UpdateToken{}, err
	}
	e2, err := e.sample(e.params.Xe())
	if err != nil {
		return UpdateToken{}, err
	}
	delta := e.sub(target.Value, source.Value)
	return UpdateToken{
		C1: e.add(e.mul(pk.B, delta), e.scaleNoise(e1)),
		C2: e.add(e.mul(pk.A, delta), e.scaleNoise(e2)),
	}, nil
}

// Update applies token to ciphertext. Source and target plaintext are identical.
func (e *Engine) Update(token UpdateToken, ciphertext Ciphertext) Ciphertext {
	return Ciphertext{
		C1:      e.add(ciphertext.C1, token.C1),
		C2:      e.add(ciphertext.C2, token.C2),
		Updates: ciphertext.Updates + 1,
	}
}

// UpdateChecked applies one label-update token only while the conservative
// tracked noise bound remains valid. Prefer it for service-facing code.
func (e *Engine) UpdateChecked(token UpdateToken, ciphertext Ciphertext) (Ciphertext, error) {
	if ciphertext.Updates == ^uint64(0) || !e.params.NoiseBoundSatisfiedAfter(ciphertext.Updates+1) {
		return Ciphertext{}, fmt.Errorf("ciphertext update would exceed conservative noise bound")
	}
	return e.Update(token, ciphertext), nil
}

func (e *Engine) sample(distribution ring.DistributionParameters) (ring.Poly, error) {
	sampler, err := ring.NewSampler(e.prng, e.params.RingQ(), distribution, false)
	if err != nil {
		return ring.Poly{}, err
	}
	coefficients := e.params.RingQ().NewPoly()
	sampler.Read(coefficients)
	result := e.params.RingQ().NewPoly()
	e.params.RingQ().NTT(coefficients, result)
	return result, nil
}

func (e *Engine) scalar(value uint64) ring.Poly {
	result := e.params.RingQ().NewPoly()
	e.scalarInto(value, result)
	return result
}

func (e *Engine) scalarInto(value uint64, result ring.Poly) {
	coefficients := e.decryptCoeffs
	coefficients.Zero()
	for i, subring := range e.params.RingQ().SubRings {
		coefficients.Coeffs[i][0] = value % subring.Modulus
	}
	e.params.RingQ().NTT(coefficients, result)
}

func (e *Engine) scaleNoise(noise ring.Poly) ring.Poly {
	coefficients := e.params.RingQ().NewPoly()
	e.params.RingQ().INTT(noise, coefficients)
	e.params.RingQ().MulScalar(coefficients, e.params.PlaintextModulus(), coefficients)
	result := e.params.RingQ().NewPoly()
	e.params.RingQ().NTT(coefficients, result)
	return result
}

func (e *Engine) add(left, right ring.Poly) ring.Poly {
	result := e.params.RingQ().NewPoly()
	e.params.RingQ().Add(left, right, result)
	return result
}

func (e *Engine) sub(left, right ring.Poly) ring.Poly {
	result := e.params.RingQ().NewPoly()
	e.params.RingQ().Sub(left, right, result)
	return result
}

func (e *Engine) mul(left, right ring.Poly) ring.Poly {
	result := e.params.RingQ().NewPoly()
	e.params.RingQ().MulCoeffsBarrett(left, right, result)
	return result
}

func (e *Engine) isZeroModT(value ring.Poly) bool {
	e.params.RingQ().INTT(value, e.decryptCoeffs)
	for j := 0; j < e.params.N(); j++ {
		e.decryptAccum.SetUint64(0)
		for k, crt := range e.decryptCRT {
			e.decryptTmp.SetUint64(e.decryptCoeffs.Coeffs[k][j])
			e.decryptTmp.Mul(&e.decryptTmp, crt)
			e.decryptAccum.Add(&e.decryptAccum, &e.decryptTmp)
		}
		e.decryptAccum.Mod(&e.decryptAccum, &e.decryptQ)
		if e.decryptAccum.Cmp(&e.decryptQHalf) >= 0 {
			e.decryptAccum.Sub(&e.decryptAccum, &e.decryptQ)
		}
		if e.decryptAccum.Mod(&e.decryptAccum, &e.plaintextMod).Sign() != 0 {
			return false
		}
	}
	return true
}

func marshalPair(left, right ring.Poly) ([]byte, error) {
	leftData, err := left.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rightData, err := right.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(leftData, rightData...), nil
}

func unmarshalPair(data []byte, params Parameters) (ring.Poly, ring.Poly, error) {
	left := params.RingQ().NewPoly()
	polySize := left.BinarySize()
	if len(data) != 2*polySize {
		return ring.Poly{}, ring.Poly{}, fmt.Errorf("invalid serialized AoS pair length %d, want %d", len(data), 2*polySize)
	}
	if err := left.UnmarshalBinary(data[:polySize]); err != nil {
		return ring.Poly{}, ring.Poly{}, fmt.Errorf("decode first polynomial: %w", err)
	}
	right := params.RingQ().NewPoly()
	if err := right.UnmarshalBinary(data[polySize:]); err != nil {
		return ring.Poly{}, ring.Poly{}, fmt.Errorf("decode second polynomial: %w", err)
	}
	return left, right, nil
}

func unmarshalPoly(data []byte, params Parameters) (ring.Poly, error) {
	poly := params.RingQ().NewPoly()
	if len(data) != poly.BinarySize() {
		return ring.Poly{}, fmt.Errorf("invalid serialized polynomial length %d, want %d", len(data), poly.BinarySize())
	}
	if err := poly.UnmarshalBinary(data); err != nil {
		return ring.Poly{}, err
	}
	return poly, nil
}
