package protocol

import (
	"testing"
	"time"

	protocolpb "github.com/tuneinsight/lattigo/v6/schemes/aos/protocol/pb"
	"google.golang.org/protobuf/proto"
)

func TestProtobufEnvelopeAndBoxRoundTrip(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	envelope, err := SignEnvelope(identity, []byte("protobuf request"), now)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	restoredEnvelope, err := UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoredEnvelope.Verify(identity.SignPublic, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	restoredEnvelope.Payload[0] ^= 1
	if err := restoredEnvelope.Verify(identity.SignPublic, now, time.Minute); err == nil {
		t.Fatal("tampered protobuf envelope verified")
	}

	box, err := Seal(identity.BoxPrivate.PublicKey(), []byte("functional key bytes"))
	if err != nil {
		t.Fatal(err)
	}
	data, err = MarshalBox(box)
	if err != nil {
		t.Fatal(err)
	}
	restoredBox, err := UnmarshalBox(data)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Open(identity, restoredBox)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "functional key bytes" {
		t.Fatalf("got %q", plaintext)
	}
}

func TestProtobufRequestAndDeliveryMessagesRoundTrip(t *testing.T) {
	request := &protocolpb.FunctionalKeyRequest{
		UserId: "user-0",
		Envelope: &protocolpb.Envelope{
			TimestampUnixNano: 1,
			Nonce:             make([]byte, 24),
			SenderEd25519:     make([]byte, 32),
			Signature:         make([]byte, 64),
		},
		Target: 42,
	}
	data, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	restored := new(protocolpb.FunctionalKeyRequest)
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatal(err)
	}
	if restored.UserId != "user-0" || restored.Target != 42 {
		t.Fatalf("wrong protobuf request: %+v", restored)
	}
}
