package protocol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/schemes/aos"
)

func TestEndToEndProtocol(t *testing.T) {
	params, err := aos.ExampleParameters128Bit()
	require.NoError(t, err)
	engine, err := aos.NewEngine(params)
	require.NoError(t, err)
	system, err := engine.Setup(2)
	require.NoError(t, err)
	curator, err := NewCurator(engine, system, time.Minute)
	require.NoError(t, err)
	now := time.Now()

	owner0, err := NewIdentity()
	require.NoError(t, err)
	owner1, err := NewIdentity()
	require.NoError(t, err)
	user, err := NewIdentity()
	require.NoError(t, err)

	registration, err := SignEnvelope(owner0, []byte("register owner 0"), now)
	require.NoError(t, err)
	public0, labelBox0, err := curator.RegisterOwner("owner-0", owner0, registration, now)
	require.NoError(t, err)
	registration, err = SignEnvelope(owner1, []byte("register owner 1"), now)
	require.NoError(t, err)
	public1, labelBox1, err := curator.RegisterOwner("owner-1", owner1, registration, now)
	require.NoError(t, err)

	labelData, err := Open(owner0, labelBox0)
	require.NoError(t, err)
	var label0 aos.Label
	require.NoError(t, label0.UnmarshalBinary(labelData, params))
	labelData, err = Open(owner1, labelBox1)
	require.NoError(t, err)
	var label1 aos.Label
	require.NoError(t, label1.UnmarshalBinary(labelData, params))

	registration, err = SignEnvelope(user, []byte("register user"), now)
	require.NoError(t, err)
	require.NoError(t, curator.RegisterUser("user", user, registration, now))

	ciphertext0, err := engine.Encrypt(public0, label0, 42)
	require.NoError(t, err)
	ciphertext1, err := engine.Encrypt(public1, label1, 7)
	require.NoError(t, err)
	message, err := SignEnvelope(owner0, []byte("store owner 0"), now)
	require.NoError(t, err)
	require.NoError(t, curator.StoreCiphertext("owner-0", message, ciphertext0, now))
	message, err = SignEnvelope(owner1, []byte("store owner 1"), now)
	require.NoError(t, err)
	require.NoError(t, curator.StoreCiphertext("owner-1", message, ciphertext1, now))

	request, err := SignEnvelope(user, []byte("get key for 42"), now)
	require.NoError(t, err)
	keyBox, ciphertexts, err := curator.DeliverFunctionalKey("user", user, request, 42, now)
	require.NoError(t, err)
	keyData, err := Open(user, keyBox)
	require.NoError(t, err)
	var key aos.FunctionalKey
	require.NoError(t, key.UnmarshalBinary(keyData, params))
	match, err := engine.Decrypt(key, ciphertexts)
	require.NoError(t, err)
	require.Equal(t, []bool{true, false}, match)
}

func TestEnvelopeRejectsTamperReplayAndStaleTime(t *testing.T) {
	identity, err := NewIdentity()
	require.NoError(t, err)
	now := time.Now()
	envelope, err := SignEnvelope(identity, []byte("request"), now)
	require.NoError(t, err)
	require.NoError(t, envelope.Verify(identity.SignPublic, now, time.Minute))
	envelope.Payload[0] ^= 1
	require.Error(t, envelope.Verify(identity.SignPublic, now, time.Minute))

	params, err := aos.ExampleParameters128Bit()
	require.NoError(t, err)
	engine, err := aos.NewEngine(params)
	require.NoError(t, err)
	system, err := engine.Setup(1)
	require.NoError(t, err)
	curator, err := NewCurator(engine, system, time.Minute)
	require.NoError(t, err)
	registration, err := SignEnvelope(identity, []byte("register"), now)
	require.NoError(t, err)
	_, _, err = curator.RegisterOwner("owner", identity, registration, now)
	require.NoError(t, err)
	_, _, err = curator.RegisterOwner("owner-2", identity, registration, now)
	require.ErrorContains(t, err, "replayed")
	stale, err := SignEnvelope(identity, []byte("stale"), now.Add(-2*time.Minute))
	require.NoError(t, err)
	require.ErrorContains(t, stale.Verify(identity.SignPublic, now, time.Minute), "timestamp")
}
