package events

import (
	"reflect"
	"testing"
)

type testRequest struct {
	ID string `json:"id"`
}

const (
	eventWithResults = `{"file":{"name":"busybox"},"scan":{"save":{"elapsed":0.088491}},"iocs":[{"ioc":"example.com"}]}`
	eventNoResults   = `{"file":{"name":"data.json"}}`
)

func TestDecodeDoesNotCarryOverFields(t *testing.T) {
	req := testRequest{ID: "req-1"}

	first, err := Decode(eventWithResults, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Decode(eventNoResults, req)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"scan", "iocs"} {
		if _, ok := first[key]; !ok {
			t.Errorf("first event: expected %q to be present", key)
		}
		if _, ok := second[key]; ok {
			t.Errorf("second event: stale %q carried over from the first event", key)
		}
	}
}

func TestDecodeAttachesRequest(t *testing.T) {
	req := testRequest{ID: "req-1"}

	for _, raw := range []string{eventWithResults, eventNoResults} {
		ev, err := Decode(raw, req)
		if err != nil {
			t.Fatal(err)
		}
		if got := ev["request"]; !reflect.DeepEqual(got, req) {
			t.Errorf("request = %v, want %v", got, req)
		}
	}
}

func TestDecodeInvalidJSON(t *testing.T) {
	if _, err := Decode("not json", testRequest{}); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}
