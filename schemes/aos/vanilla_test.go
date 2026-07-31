package aos

import (
	"reflect"
	"testing"
)

func TestAoSMatchesVanillaBGV(t *testing.T) {
	values := []uint64{42, 7}
	const target = uint64(42)
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
	first, err := engine.Encrypt(system.Public[0], system.Labels[0], values[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Encrypt(system.Public[1], system.Labels[0], values[1])
	if err != nil {
		t.Fatal(err)
	}
	key, err := engine.KDer(system, 0, target)
	if err != nil {
		t.Fatal(err)
	}
	aosOutput, err := engine.Decrypt(key, []Ciphertext{first, second})
	if err != nil {
		t.Fatal(err)
	}
	vanillaOutput, err := VanillaBGVEquality(params, values, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input=%v target=%d", values, target)
	t.Logf("AoS output=%v", aosOutput)
	t.Logf("vanilla BGV output=%v", vanillaOutput)
	if !reflect.DeepEqual(aosOutput, vanillaOutput) {
		t.Fatalf("AoS output %v differs from vanilla BGV %v", aosOutput, vanillaOutput)
	}
}
