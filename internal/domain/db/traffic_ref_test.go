package db

import (
	"encoding/json"
	"testing"
)

func TestTrafficRefUnmarshalString(t *testing.T) {
	var refs []TrafficRef
	if err := json.Unmarshal([]byte(`["ev-1792294590438824976-0006",{"traffic_id":"ev-2","role":"baseline","note":"normal"}]`), &refs); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2", len(refs))
	}
	if refs[0].TrafficID != "ev-1792294590438824976-0006" || refs[0].Role != "proof" {
		t.Fatalf("string form = %+v", refs[0])
	}
	if refs[1].TrafficID != "ev-2" || refs[1].Role != "baseline" || refs[1].Note != "normal" {
		t.Fatalf("object form = %+v", refs[1])
	}
}
