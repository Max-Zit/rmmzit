package web

import (
	"bytes"
	"encoding/json"
	"strings"
)

// PostgreSQL stores no NUL character in text, and jsonb refuses the
// \u0000 escape: one NUL in an agent's data (registry values of installed
// programs often end with one) made the whole inventory fail to save, so
// the device showed no inventory at all. withoutNUL removes NUL characters
// from the strings of an agent message before it is decoded.
func withoutNUL(raw json.RawMessage) json.RawMessage {
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return raw
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber() // numbers stay exactly as sent
	var v any
	if d.Decode(&v) != nil {
		return raw // the typed decoding reports the error
	}
	b, err := json.Marshal(stripNUL(v))
	if err != nil {
		return raw
	}
	return b
}

func stripNUL(v any) any {
	switch x := v.(type) {
	case string:
		return strings.ReplaceAll(x, "\x00", "")
	case []any:
		for i := range x {
			x[i] = stripNUL(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[strings.ReplaceAll(k, "\x00", "")] = stripNUL(e)
		}
		return out
	}
	return v
}
