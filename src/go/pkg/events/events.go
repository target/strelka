// Package events contains helpers for handling scan events in the frontend.
package events

import "encoding/json"

// Decode decodes a JSON event produced by the backend into a new map and
// attaches the request metadata under the "request" key.
//
// A new map is created on every call. Decoding successive events into one
// shared map keeps any key a later event omits, so results from an earlier
// event would leak into later ones.
func Decode(raw string, request interface{}) (map[string]interface{}, error) {
	ev := make(map[string]interface{})
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, err
	}
	ev["request"] = request

	return ev, nil
}
