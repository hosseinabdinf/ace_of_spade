package protocol

import (
	"crypto/ed25519"
	"fmt"

	protocolpb "github.com/tuneinsight/lattigo/v6/schemes/aos/protocol/pb"
	"google.golang.org/protobuf/proto"
)

// EnvelopeProto converts an authenticated envelope to its protobuf message.
func EnvelopeProto(envelope Envelope) *protocolpb.Envelope {
	return &protocolpb.Envelope{
		TimestampUnixNano: envelope.Timestamp,
		Nonce:             append([]byte(nil), envelope.Nonce[:]...),
		Payload:           append([]byte(nil), envelope.Payload...),
		SenderEd25519:     append([]byte(nil), envelope.Sender...),
		Signature:         append([]byte(nil), envelope.Signature...),
	}
}

// EnvelopeFromProto validates and converts a protobuf envelope. Call Verify
// after conversion before acting on its payload.
func EnvelopeFromProto(message *protocolpb.Envelope) (Envelope, error) {
	if message == nil {
		return Envelope{}, fmt.Errorf("missing protobuf envelope")
	}
	if len(message.Nonce) != 24 {
		return Envelope{}, fmt.Errorf("protobuf envelope nonce has length %d, want 24", len(message.Nonce))
	}
	if len(message.SenderEd25519) != ed25519.PublicKeySize {
		return Envelope{}, fmt.Errorf("protobuf envelope sender has length %d, want %d", len(message.SenderEd25519), ed25519.PublicKeySize)
	}
	if len(message.Signature) != ed25519.SignatureSize {
		return Envelope{}, fmt.Errorf("protobuf envelope signature has length %d, want %d", len(message.Signature), ed25519.SignatureSize)
	}
	envelope := Envelope{
		Timestamp: message.TimestampUnixNano,
		Payload:   append([]byte(nil), message.Payload...),
		Sender:    append(ed25519.PublicKey(nil), message.SenderEd25519...),
		Signature: append([]byte(nil), message.Signature...),
	}
	copy(envelope.Nonce[:], message.Nonce)
	return envelope, nil
}

// BoxProto converts protected delivery material to its protobuf message.
func BoxProto(box Box) *protocolpb.Box {
	return &protocolpb.Box{
		EphemeralX25519Public: append([]byte(nil), box.EphemeralPublic...),
		Nonce:                 append([]byte(nil), box.Nonce[:]...),
		Ciphertext:            append([]byte(nil), box.Ciphertext...),
	}
}

// BoxFromProto validates and converts protected delivery material.
func BoxFromProto(message *protocolpb.Box) (Box, error) {
	if message == nil {
		return Box{}, fmt.Errorf("missing protobuf box")
	}
	if len(message.Nonce) != chachaNonceSize {
		return Box{}, fmt.Errorf("protobuf box nonce has length %d, want %d", len(message.Nonce), chachaNonceSize)
	}
	if len(message.EphemeralX25519Public) != 32 {
		return Box{}, fmt.Errorf("protobuf box ephemeral key has length %d, want 32", len(message.EphemeralX25519Public))
	}
	box := Box{EphemeralPublic: append([]byte(nil), message.EphemeralX25519Public...), Ciphertext: append([]byte(nil), message.Ciphertext...)}
	copy(box.Nonce[:], message.Nonce)
	return box, nil
}

// MarshalEnvelope emits canonical protobuf wire bytes for an envelope.
func MarshalEnvelope(envelope Envelope) ([]byte, error) {
	return proto.Marshal(EnvelopeProto(envelope))
}

// UnmarshalEnvelope decodes and structurally validates protobuf envelope bytes.
func UnmarshalEnvelope(data []byte) (Envelope, error) {
	message := new(protocolpb.Envelope)
	if err := proto.Unmarshal(data, message); err != nil {
		return Envelope{}, fmt.Errorf("decode protobuf envelope: %w", err)
	}
	return EnvelopeFromProto(message)
}

// MarshalBox emits protobuf wire bytes for protected delivery material.
func MarshalBox(box Box) ([]byte, error) {
	return proto.Marshal(BoxProto(box))
}

// UnmarshalBox decodes and structurally validates protobuf delivery bytes.
func UnmarshalBox(data []byte) (Box, error) {
	message := new(protocolpb.Box)
	if err := proto.Unmarshal(data, message); err != nil {
		return Box{}, fmt.Errorf("decode protobuf box: %w", err)
	}
	return BoxFromProto(message)
}

const chachaNonceSize = 24
