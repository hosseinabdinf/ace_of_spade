package aos

import "testing"

func TestSelectiveDecryption(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		t.Fatal(err)
	}

	// Multi-client correctness requires one shared identifier across this vector.
	match, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := engine.Encrypt(system.Public[1], system.Labels[0], 7)
	if err != nil {
		t.Fatal(err)
	}
	key, err := engine.KDer(system, 0, 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(key, []Ciphertext{match, mismatch})
	if err != nil {
		t.Fatal(err)
	}
	if !got[0] || got[1] {
		t.Fatalf("unexpected equality bits: %v", got)
	}
}

func TestCiphertextUpdate(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		t.Fatal(err)
	}

	values := []uint64{42, 7}
	updated := make([]Ciphertext, len(values))
	for i, value := range values {
		ciphertext, err := engine.Encrypt(system.Public[i], system.Labels[0], value)
		if err != nil {
			t.Fatal(err)
		}
		token, err := engine.TokGen(system.Public[i], system.Labels[0], system.Labels[1])
		if err != nil {
			t.Fatal(err)
		}
		updated[i] = engine.Update(token, ciphertext)
	}

	key, err := engine.KDer(system, 1, 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(key, updated)
	if err != nil {
		t.Fatal(err)
	}
	if !got[0] || got[1] {
		t.Fatalf("unexpected equality bits after update: %v", got)
	}
}

func TestWrongLabelKeyDoesNotDecrypt(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		t.Fatal(err)
	}

	match, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := engine.Encrypt(system.Public[1], system.Labels[0], 7)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := engine.KDer(system, 1, 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(wrongKey, []Ciphertext{match, mismatch})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] || got[1] {
		t.Fatalf("wrong label key decrypted ciphertexts: %v", got)
	}
}

func TestRepeatedUpdatesPreserveSelectiveDecryption(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(1)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		forward, err := engine.TokGen(system.Public[0], system.Labels[0], system.Labels[0])
		if err != nil {
			t.Fatal(err)
		}
		ciphertext = engine.Update(forward, ciphertext)
	}

	key, err := engine.KDer(system, 0, 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(key, []Ciphertext{ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if !got[0] {
		t.Fatal("repeated updates lost equality result")
	}
}

func TestCiphertextSerialization(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ciphertext.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Ciphertext
	if err := decoded.UnmarshalBinary(encoded, params); err != nil {
		t.Fatal(err)
	}
	key, err := engine.KDer(system, 0, 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(key, []Ciphertext{decoded})
	if err != nil {
		t.Fatal(err)
	}
	if !got[0] {
		t.Fatal("serialized ciphertext lost equality result")
	}
}

func TestRandomizedSelectiveDecryption(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		t.Fatal(err)
	}
	key, err := engine.KDer(system, 0, 42)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 12; i++ {
		values := []uint64{uint64(7 + i), uint64(101 + i)}
		if i%2 == 0 {
			values[0] = 42
		}
		if i%3 == 0 {
			values[1] = 42
		}
		ciphertexts := make([]Ciphertext, len(values))
		for j, value := range values {
			ciphertexts[j], err = engine.Encrypt(system.Public[j], system.Labels[0], value)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := engine.Decrypt(key, ciphertexts)
		if err != nil {
			t.Fatal(err)
		}
		for j, value := range values {
			if got[j] != (value == 42) {
				t.Fatalf("iteration %d slot %d: value=%d got=%t", i, j, value, got[j])
			}
		}
	}
}

func TestWrongTargetDoesNotDecrypt(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		t.Fatal(err)
	}
	key, err := engine.KDer(system, 0, 41)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(key, []Ciphertext{ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] {
		t.Fatal("wrong target key decrypted ciphertext")
	}
}

func TestUpdateTokenSerialization(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		t.Fatal(err)
	}

	ciphertexts := make([]Ciphertext, 2)
	for i, value := range []uint64{42, 7} {
		ciphertexts[i], err = engine.Encrypt(system.Public[i], system.Labels[0], value)
		if err != nil {
			t.Fatal(err)
		}
		token, err := engine.TokGen(system.Public[i], system.Labels[0], system.Labels[1])
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := token.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var decoded UpdateToken
		if err := decoded.UnmarshalBinary(encoded, params); err != nil {
			t.Fatal(err)
		}
		ciphertexts[i] = engine.Update(decoded, ciphertexts[i])
	}
	key, err := engine.KDer(system, 1, 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Decrypt(key, ciphertexts)
	if err != nil {
		t.Fatal(err)
	}
	if !got[0] || got[1] {
		t.Fatalf("unexpected equality bits after serialized token update: %v", got)
	}
}

func TestUpdateTracksNoiseBudget(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		t.Fatal(err)
	}
	system, err := engine.Setup(1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		t.Fatal(err)
	}
	token, err := engine.TokGen(system.Public[0], system.Labels[0], system.Labels[0])
	if err != nil {
		t.Fatal(err)
	}
	updated, err := engine.UpdateChecked(token, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Updates != 1 {
		t.Fatalf("got update count %d, want 1", updated.Updates)
	}
	if params.LogNoiseBoundAfter(updated.Updates) <= params.LogNoiseBoundAfter(0) {
		t.Fatal("noise bound did not grow after update")
	}
	if !params.NoiseBoundSatisfiedAfter(updated.Updates) {
		t.Fatal("one update exceeds conservative noise bound")
	}

	data, err := updated.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var restored Ciphertext
	if err := restored.UnmarshalBinary(data, params); err != nil {
		t.Fatal(err)
	}
	if restored.Updates != updated.Updates {
		t.Fatalf("round-trip update count %d, want %d", restored.Updates, updated.Updates)
	}
	_, err = engine.UpdateChecked(token, Ciphertext{Updates: ^uint64(0)})
	if err == nil {
		t.Fatal("expected update count overflow to be rejected")
	}
}
