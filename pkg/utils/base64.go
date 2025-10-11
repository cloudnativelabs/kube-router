package utils

import (
	"encoding/base64"
	"fmt"

	"github.com/goccy/go-yaml"
)

// Base64String is a wrapper type that handles automatic b64 decoding of a
// string when unmarshalling
type Base64String string

func (b *Base64String) UnmarshalYAML(raw []byte) error {
	var tmp string
	if err := yaml.Unmarshal(raw, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal string into base64string type: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(tmp)
	if err != nil {
		return fmt.Errorf("failed to base64 decode field: %w", err)
	}
	*b = Base64String(string(decoded))
	return nil
}
