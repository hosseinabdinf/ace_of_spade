package aos

import "testing"

func benchmarkContext(b *testing.B) (*Engine, *System, []Ciphertext, FunctionalKey, UpdateToken) {
	b.Helper()
	params, err := ExampleParameters128Bit()
	if err != nil {
		b.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		b.Fatal(err)
	}
	system, err := engine.Setup(2)
	if err != nil {
		b.Fatal(err)
	}
	left, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
	if err != nil {
		b.Fatal(err)
	}
	right, err := engine.Encrypt(system.Public[1], system.Labels[0], 7)
	if err != nil {
		b.Fatal(err)
	}
	key, err := engine.KDer(system, 0, 42)
	if err != nil {
		b.Fatal(err)
	}
	token, err := engine.TokGen(system.Public[0], system.Labels[0], system.Labels[1])
	if err != nil {
		b.Fatal(err)
	}
	return engine, system, []Ciphertext{left, right}, key, token
}

func BenchmarkSetup(b *testing.B) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		b.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Setup(2); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	engine, system, _, _, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Encrypt(system.Public[0], system.Labels[0], 42); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt2(b *testing.B) {
	engine, system, _, _, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Encrypt2(system.Public[0], system.Labels[0], 42); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKDer(b *testing.B) {
	engine, system, _, _, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.KDer(system, 0, 42); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKDer2(b *testing.B) {
	engine, system, _, _, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.KDer2(system, 0, 42); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	engine, _, ciphertexts, key, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Decrypt(key, ciphertexts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt2(b *testing.B) {
	engine, _, ciphertexts, key, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Decrypt2(key, ciphertexts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokGen(b *testing.B) {
	engine, system, _, _, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.TokGen(system.Public[0], system.Labels[0], system.Labels[1]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokGen2(b *testing.B) {
	engine, system, _, _, _ := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.TokGen2(system.Public[0], system.Labels[0], system.Labels[1]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUpdate(b *testing.B) {
	engine, _, ciphertexts, _, token := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Update(token, ciphertexts[0])
	}
}

func BenchmarkUpdate2(b *testing.B) {
	engine, _, ciphertexts, _, token := benchmarkContext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Update2(token, ciphertexts[0])
	}
}

// BenchmarkFullLifecycleNoise measures setup through selective decryption.
// It reports the persisted update count and conservative final log2 noise bound.
func BenchmarkFullLifecycleNoise(b *testing.B) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		b.Fatal(err)
	}
	engine, err := NewEngine(params)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		system, err := engine.Setup(2)
		if err != nil {
			b.Fatal(err)
		}
		left, err := engine.Encrypt(system.Public[0], system.Labels[0], 42)
		if err != nil {
			b.Fatal(err)
		}
		right, err := engine.Encrypt(system.Public[1], system.Labels[1], 7)
		if err != nil {
			b.Fatal(err)
		}
		token, err := engine.TokGen(system.Public[1], system.Labels[1], system.Labels[0])
		if err != nil {
			b.Fatal(err)
		}
		right, err = engine.UpdateChecked(token, right)
		if err != nil {
			b.Fatal(err)
		}
		key, err := engine.KDer(system, 0, 42)
		if err != nil {
			b.Fatal(err)
		}
		matches, err := engine.Decrypt(key, []Ciphertext{left, right})
		if err != nil {
			b.Fatal(err)
		}
		if !matches[0] || matches[1] {
			b.Fatal("wrong selective-decryption result")
		}
		b.ReportMetric(float64(right.Updates), "updates/op")
		b.ReportMetric(params.LogNoiseBoundAfter(right.Updates), "noise-log2")
	}
}
