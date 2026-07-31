package aos

import "testing"

func TestExampleParameters128BitNoiseBound(t *testing.T) {
	params, err := ExampleParameters128Bit()
	if err != nil {
		t.Fatal(err)
	}
	if !params.NoiseBoundSatisfied() {
		t.Fatalf("AoS noise bound fails: log2(lhs)=%.2f, log2(q/2)=%d", params.LogNoiseBound(), params.RingQ().ModulusAtLevel[params.MaxLevel()].BitLen()-1)
	}
}
