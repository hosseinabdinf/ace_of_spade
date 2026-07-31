// Package protocol implements the authenticated delivery protocol around AoS.
package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/aos"
	"golang.org/x/crypto/chacha20poly1305"
)

const envelopeDomain = "lattigo-aos-envelope-v1"
const boxDomain = "lattigo-aos-key-delivery-v1"

// Identity owns independent signing and X25519 key-agreement keys.
type Identity struct {
	SignPrivate ed25519.PrivateKey
	SignPublic  ed25519.PublicKey
	BoxPrivate  *ecdh.PrivateKey
}

// NewIdentity creates an identity for a data owner or user.
func NewIdentity() (*Identity, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	boxPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	return &Identity{SignPrivate: private, SignPublic: public, BoxPrivate: boxPrivate}, nil
}

// Envelope authenticates an exact payload with a timestamp and random nonce.
type Envelope struct {
	Timestamp int64
	Nonce     [24]byte
	Payload   []byte
	Sender    ed25519.PublicKey
	Signature []byte
}

// SignEnvelope creates a replay-detectable signed message.
func SignEnvelope(identity *Identity, payload []byte, now time.Time) (Envelope, error) {
	if identity == nil || len(identity.SignPrivate) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("invalid signing identity")
	}
	envelope := Envelope{Timestamp: now.UnixNano(), Payload: append([]byte(nil), payload...), Sender: append(ed25519.PublicKey(nil), identity.SignPublic...)}
	if _, err := rand.Read(envelope.Nonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("generate envelope nonce: %w", err)
	}
	envelope.Signature = ed25519.Sign(identity.SignPrivate, envelope.signingBytes())
	return envelope, nil
}

func (envelope Envelope) signingBytes() []byte {
	data := make([]byte, 0, len(envelopeDomain)+8+len(envelope.Nonce)+4+len(envelope.Payload))
	data = append(data, envelopeDomain...)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(envelope.Timestamp))
	data = append(data, number[:]...)
	data = append(data, envelope.Nonce[:]...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(envelope.Payload)))
	data = append(data, length[:]...)
	data = append(data, envelope.Payload...)
	return data
}

// Verify checks identity, signature, and the permitted clock window.
func (envelope Envelope) Verify(expected ed25519.PublicKey, now time.Time, maxAge time.Duration) error {
	if len(expected) != ed25519.PublicKeySize || !bytes.Equal(envelope.Sender, expected) {
		return fmt.Errorf("unexpected envelope sender")
	}
	if !ed25519.Verify(expected, envelope.signingBytes(), envelope.Signature) {
		return fmt.Errorf("invalid envelope signature")
	}
	issued := time.Unix(0, envelope.Timestamp)
	if issued.Before(now.Add(-maxAge)) || issued.After(now.Add(maxAge)) {
		return fmt.Errorf("envelope timestamp outside permitted window")
	}
	return nil
}

// Box is a X25519/XChaCha20-Poly1305 protected delivery container.
type Box struct {
	EphemeralPublic []byte
	Nonce           [chacha20poly1305.NonceSizeX]byte
	Ciphertext      []byte
}

// Seal encrypts plaintext to recipient's X25519 public key.
func Seal(recipient *ecdh.PublicKey, plaintext []byte) (Box, error) {
	if recipient == nil {
		return Box{}, fmt.Errorf("missing recipient encryption key")
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Box{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return Box{}, fmt.Errorf("derive delivery secret: %w", err)
	}
	box := Box{EphemeralPublic: ephemeral.PublicKey().Bytes()}
	if _, err := rand.Read(box.Nonce[:]); err != nil {
		return Box{}, fmt.Errorf("generate delivery nonce: %w", err)
	}
	cipher, err := chacha20poly1305.NewX(boxKey(shared))
	if err != nil {
		return Box{}, err
	}
	box.Ciphertext = cipher.Seal(nil, box.Nonce[:], plaintext, []byte(boxDomain))
	return box, nil
}

// Open decrypts a protected delivery container.
func Open(identity *Identity, box Box) ([]byte, error) {
	if identity == nil || identity.BoxPrivate == nil {
		return nil, fmt.Errorf("missing recipient identity")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(box.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral key: %w", err)
	}
	shared, err := identity.BoxPrivate.ECDH(ephemeral)
	if err != nil {
		return nil, fmt.Errorf("derive delivery secret: %w", err)
	}
	cipher, err := chacha20poly1305.NewX(boxKey(shared))
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Open(nil, box.Nonce[:], box.Ciphertext, []byte(boxDomain))
	if err != nil {
		return nil, fmt.Errorf("open protected delivery: %w", err)
	}
	return plaintext, nil
}

func boxKey(shared []byte) []byte {
	digest := sha256.Sum256(append(append([]byte(nil), []byte(boxDomain)...), shared...))
	return digest[:]
}

// Curator is the trusted AoS key curator plus protocol authorization state.
// Setup fixes owner slots; RegisterOwner assigns those slots dynamically.
type Curator struct {
	engine     *aos.Engine
	system     *aos.System
	maxAge     time.Duration
	owners     map[string]owner
	users      map[string]ed25519.PublicKey
	replay     map[[32]byte]struct{}
	ciphertext []aos.Ciphertext
	hasCipher  []bool
}

type owner struct {
	index int
	sign  ed25519.PublicKey
}

// NewCurator creates a curator over a pre-provisioned AoS system.
func NewCurator(engine *aos.Engine, system *aos.System, maxAge time.Duration) (*Curator, error) {
	if engine == nil || system == nil || len(system.Public) == 0 || maxAge <= 0 {
		return nil, fmt.Errorf("invalid curator configuration")
	}
	return &Curator{engine: engine, system: system, maxAge: maxAge, owners: map[string]owner{}, users: map[string]ed25519.PublicKey{}, replay: map[[32]byte]struct{}{}, ciphertext: make([]aos.Ciphertext, len(system.Public)), hasCipher: make([]bool, len(system.Public))}, nil
}

// RegisterOwner verifies a signed registration and returns its private label encrypted to owner.
func (c *Curator) RegisterOwner(id string, identity *Identity, envelope Envelope, now time.Time) (aos.PublicKey, Box, error) {
	if id == "" || identity == nil {
		return aos.PublicKey{}, Box{}, fmt.Errorf("owner id and identity are required")
	}
	if err := c.accept(identity.SignPublic, envelope, now); err != nil {
		return aos.PublicKey{}, Box{}, err
	}
	if _, exists := c.owners[id]; exists {
		return aos.PublicKey{}, Box{}, fmt.Errorf("owner %q already registered", id)
	}
	index := len(c.owners)
	if index >= len(c.system.Public) {
		return aos.PublicKey{}, Box{}, fmt.Errorf("no unassigned AoS owner slots")
	}
	label, err := c.system.Labels[index].MarshalBinary()
	if err != nil {
		return aos.PublicKey{}, Box{}, err
	}
	grant, err := Seal(identity.BoxPrivate.PublicKey(), label)
	if err != nil {
		return aos.PublicKey{}, Box{}, err
	}
	c.owners[id] = owner{index: index, sign: append(ed25519.PublicKey(nil), identity.SignPublic...)}
	return c.system.Public[index], grant, nil
}

// RegisterUser verifies a signed request and authorizes future functional-key delivery.
func (c *Curator) RegisterUser(id string, identity *Identity, envelope Envelope, now time.Time) error {
	if id == "" || identity == nil {
		return fmt.Errorf("user id and identity are required")
	}
	if err := c.accept(identity.SignPublic, envelope, now); err != nil {
		return err
	}
	if _, exists := c.users[id]; exists {
		return fmt.Errorf("user %q already registered", id)
	}
	c.users[id] = append(ed25519.PublicKey(nil), identity.SignPublic...)
	return nil
}

// StoreCiphertext accepts one signed ciphertext from its registered owner.
func (c *Curator) StoreCiphertext(ownerID string, envelope Envelope, ciphertext aos.Ciphertext, now time.Time) error {
	registered, exists := c.owners[ownerID]
	if !exists {
		return fmt.Errorf("unknown owner %q", ownerID)
	}
	if err := c.accept(registered.sign, envelope, now); err != nil {
		return err
	}
	// Normalize every stored ciphertext to slot zero's label. This is the AoS
	// update step that makes one functional key valid for the full data vector.
	token, err := c.engine.TokGen(c.system.Public[registered.index], c.system.Labels[registered.index], c.system.Labels[0])
	if err != nil {
		return err
	}
	updated, err := c.engine.UpdateChecked(token, ciphertext)
	if err != nil {
		return err
	}
	c.ciphertext[registered.index], c.hasCipher[registered.index] = updated, true
	return nil
}

// DeliverFunctionalKey sends an authorized user a protected functional key and ciphertext vector.
func (c *Curator) DeliverFunctionalKey(userID string, identity *Identity, envelope Envelope, target uint64, now time.Time) (Box, []aos.Ciphertext, error) {
	sign, exists := c.users[userID]
	if !exists || identity == nil {
		return Box{}, nil, fmt.Errorf("unknown user %q", userID)
	}
	if err := c.accept(sign, envelope, now); err != nil {
		return Box{}, nil, err
	}
	if !bytes.Equal(sign, identity.SignPublic) {
		return Box{}, nil, fmt.Errorf("user identity does not match registration")
	}
	for i, stored := range c.hasCipher {
		if !stored {
			return Box{}, nil, fmt.Errorf("missing ciphertext for owner slot %d", i)
		}
	}
	key, err := c.engine.KDer(c.system, 0, target)
	if err != nil {
		return Box{}, nil, err
	}
	encoded, err := key.MarshalBinary()
	if err != nil {
		return Box{}, nil, err
	}
	box, err := Seal(identity.BoxPrivate.PublicKey(), encoded)
	if err != nil {
		return Box{}, nil, err
	}
	return box, append([]aos.Ciphertext(nil), c.ciphertext...), nil
}

func (c *Curator) accept(expected ed25519.PublicKey, envelope Envelope, now time.Time) error {
	if err := envelope.Verify(expected, now, c.maxAge); err != nil {
		return err
	}
	fingerprint := sha256.Sum256(append(append([]byte(nil), envelope.Sender...), envelope.Nonce[:]...))
	if _, replay := c.replay[fingerprint]; replay {
		return fmt.Errorf("replayed envelope")
	}
	c.replay[fingerprint] = struct{}{}
	return nil
}
